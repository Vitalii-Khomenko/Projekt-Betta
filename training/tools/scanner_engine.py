#!/usr/bin/env python3
# =============================================================================
# scanner_engine.py  -  SNN-driven scan orchestration and raw/connect fallback logic
# =============================================================================
# Usage:
#   python training/tools/scanner.py scan --target 10.10.10.5 [options]
#   python training/tools/scanner.py train --profile normal [options]
#
# Key options:
#   --connect-only   Force TCP connect probes instead of raw packet probes
#   --checkpoint-every N   Persist periodic scan checkpoints
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.3
# Created : 01.04.2026
# =============================================================================
from __future__ import annotations

import json
import random
import socket as _socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path
from typing import Callable, Optional

import numpy as np

from training.tools.scanner_probes import async_batch_connect_probe, batch_syn_probe, connect_probe, syn_probe
from training.tools.scanner_support import RAW_AVAILABLE, _print
from training.tools.scanner_types import ACTIONS, FLAG_INDEX, INPUT_DIM, OUTPUT_DIM, PROFILES, PortResult, derive_runtime_profile
from training.tools.scanner_utils import _normalize_result_text_fields, _recv_banner_chunks
from tools.artifact_schema import FAMILY_SCANNER, attach_artifact_metadata, normalize_artifact_payload, validate_artifact_payload

RAW_GUARD_VALIDATE_AFTER_PORTS = 1000
RAW_GUARD_SAMPLE_SIZE = 8
RAW_GUARD_CONFIRM_TIMEOUT = 1.0
RAW_GUARD_MIN_CONFIRMATIONS = 4
RAW_TCP_MAX_PARALLEL = 512
RAW_TCP_PARALLEL_MULTIPLIER = 8
RAW_TCP_MIN_TIMEOUT = 1.0


def _confirm_ports_with_connect(
    host: str,
    ports: list[int],
    timeout: float,
    source_port: Optional[int] = None,
    max_workers: int = 32,
) -> list[PortResult]:
    unique_ports = sorted(set(ports))
    if not unique_ports:
        return []

    worker_count = min(max_workers, len(unique_ports))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = {
            pool.submit(connect_probe, host, port, timeout, source_port): port
            for port in unique_ports
        }
        confirmed: list[PortResult] = []
        for future in as_completed(futures):
            confirmed.append(future.result())
    confirmed.sort(key=lambda result: result.port)
    return confirmed


class SpikeScanEngine:
    """Two-layer LIF network that drives Betta-Morpho scanning."""

    def __init__(
        self,
        profile: str = "normal",
        artifact: Optional[Path] = None,
        seed: Optional[int] = None,
        speed_level: Optional[int] = None,
    ) -> None:
        self.base_profile_name = profile
        self.speed_level = speed_level
        self.profile = derive_runtime_profile(PROFILES[profile], speed_level)
        self._rng = np.random.default_rng(seed)
        self.W1, self.W2 = self._init_weights()
        self.V_h = np.zeros(self.profile.hidden_dim)
        self.V_o = np.zeros(OUTPUT_DIM)
        if artifact and artifact.exists():
            self.load_artifact(artifact)

    def _init_weights(self) -> tuple[np.ndarray, np.ndarray]:
        hidden_dim = self.profile.hidden_dim
        weights_in = self._rng.standard_normal((INPUT_DIM, hidden_dim)) * np.sqrt(2.0 / INPUT_DIM)
        weights_out = self._rng.standard_normal((hidden_dim, OUTPUT_DIM)) * np.sqrt(2.0 / hidden_dim)
        if self.profile.beta >= 0.85:
            weights_out[:, ACTIONS.index("WAIT")] += 0.5
        elif self.profile.beta <= 0.40:
            weights_out[:, ACTIONS.index("PROBE_SYN")] += 0.8
        else:
            weights_out[:, ACTIONS.index("PROBE_SYN")] += 0.3
            weights_out[:, ACTIONS.index("WAIT")] += 0.1
        return weights_in, weights_out

    def reset(self) -> None:
        self.V_h[:] = 0.0
        self.V_o[:] = 0.0

    def _lif_step(self, context: np.ndarray) -> tuple[str, float, bool]:
        beta = self.profile.beta
        threshold = self.profile.threshold
        current_hidden = context @ self.W1
        self.V_h = beta * self.V_h + current_hidden
        spikes_hidden = (self.V_h >= threshold).astype(np.float32)
        self.V_h *= 1.0 - spikes_hidden

        current_output = spikes_hidden @ self.W2
        self.V_o = beta * self.V_o + current_output
        spikes_output = (self.V_o >= threshold).astype(np.float32)
        self.V_o *= 1.0 - spikes_output

        if not spikes_output.any():
            return "WAIT", 0.0, False

        action_index = int(np.argmax(spikes_output * 100 + self.V_o))
        return ACTIONS[action_index], float(spikes_output[action_index]), True

    @staticmethod
    def encode(port: int, last_flag: str, last_rtt_us: float, scan_progress: float, timeout_streak: int) -> np.ndarray:
        context = np.zeros(INPUT_DIM, dtype=np.float32)
        context[0] = port / 65535.0
        flag_index = FLAG_INDEX.get(last_flag, 2)
        context[1 + flag_index] = 1.0
        context[7] = min(last_rtt_us / 100_000.0, 1.0)
        context[8] = float(scan_progress)
        context[9] = min(timeout_streak / 10.0, 1.0)
        return context

    def scan(
        self,
        host: str,
        ports: list[int],
        decoys: Optional[list[str]] = None,
        max_integrate_steps: int = 8,
        spoof_ttl: Optional[int] = None,
        jitter_ms: int = 0,
        force_connect: bool = False,
        source_port: Optional[int] = None,
        checkpoint_interval: int = 1000,
        progress_callback: Optional[Callable[[int, int, list[PortResult]], None]] = None,
        _raw_guard_enabled: bool = True,
    ) -> list[PortResult]:
        probe_mode = "connect" if force_connect else ("raw" if RAW_AVAILABLE else "connect")
        raw_profile = replace(self.profile, probe_timeout=max(self.profile.probe_timeout, RAW_TCP_MIN_TIMEOUT))
        if probe_mode == "connect":
            _print("[yellow]No raw socket access (Npcap not installed or no admin).[/] Using TCP connect fallback; SNN logic unchanged.")
        else:
            _print("[bold green][Betta-Morpho] Raw SYN mode active.[/] Using raw socket probes.")

        self.reset()
        results: list[PortResult] = []
        last_flag = "TIMEOUT"
        last_rtt = 0.0
        streak = 0
        port_index = 0
        forced_probes = 0
        wait_cycles = 0
        batch_size = max(1, self.profile.max_parallel * 8)
        if probe_mode == "raw":
            batch_size = min(
                RAW_TCP_MAX_PARALLEL,
                max(1, self.profile.max_parallel * RAW_TCP_PARALLEL_MULTIPLIER),
            )
        checkpoint_step = checkpoint_interval if checkpoint_interval > 0 else 0
        next_checkpoint = checkpoint_step if checkpoint_step and len(ports) > checkpoint_step else 0
        if probe_mode == "connect" and source_port is not None:
            batch_size = 1
        deterministic_coverage = probe_mode == "connect"
        raw_guard_checked = False
        raw_guard_validate_after = min(len(ports), RAW_GUARD_VALIDATE_AFTER_PORTS)

        def _dispatch(port: int, action: str) -> PortResult:
            if action in {"PROBE_SYN", "PROBE_FIN", "PROBE_NULL", "PROBE_UDP"}:
                if probe_mode == "raw":
                    return syn_probe(host, port, raw_profile, decoys, spoof_ttl=spoof_ttl)
                return connect_probe(host, port, self.profile.probe_timeout, source_port=source_port)
            return connect_probe(host, port, self.profile.probe_timeout, source_port=source_port)

        def _probe_protocol_for_action(action: str) -> str:
            return "udp" if action == "PROBE_UDP" else "tcp"

        def _dispatch_safe(port: int, action: str) -> PortResult:
            try:
                return _dispatch(port, action)
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                return PortResult(
                    host,
                    port,
                    "filtered",
                    _probe_protocol_for_action(action),
                    "TIMEOUT",
                    0.0,
                    0,
                    int(time.time() * 1_000_000),
                    technology=f"probe-error={exc.__class__.__name__}",
                )

        pool: ThreadPoolExecutor | None = None
        try:
            while port_index < len(ports):
                port = ports[port_index]
                progress = port_index / max(len(ports), 1)
                context = self.encode(port, last_flag, last_rtt, progress, streak)

                action = "WAIT"
                for _ in range(max_integrate_steps):
                    action, _confidence, fired = self._lif_step(context)
                    if fired:
                        break

                if action == "WAIT":
                    wait_cycles += 1
                    if deterministic_coverage and wait_cycles >= max_integrate_steps:
                        action = "PROBE_SYN"
                        forced_probes += 1
                    else:
                        time.sleep(self.profile.wait_ms / 1000.0)
                        continue

                if action == "SKIP":
                    if deterministic_coverage:
                        action = "PROBE_SYN"
                        forced_probes += 1
                    else:
                        port_index += 1
                        continue

                if action == "DONE":
                    if deterministic_coverage:
                        action = "PROBE_SYN"
                        forced_probes += 1
                    else:
                        break

                wait_cycles = 0
                if action == "WAIT":
                    time.sleep(self.profile.wait_ms / 1000.0)
                    continue

                batch_ports: list[int] = []
                batch_actions: list[str] = []
                while port_index < len(ports) and len(batch_ports) < batch_size:
                    batch_ports.append(ports[port_index])
                    batch_actions.append(action)
                    port_index += 1
                    if port_index < len(ports) and len(batch_ports) < batch_size:
                        context_next = self.encode(ports[port_index], last_flag, last_rtt, port_index / max(len(ports), 1), streak)
                        next_action, _, _ = self._lif_step(context_next)
                        if next_action in {"SKIP", "WAIT", "DONE"}:
                            break
                        action = next_action

                if probe_mode == "raw":
                    try:
                        batch_results = batch_syn_probe(host, batch_ports, raw_profile, decoys=decoys, spoof_ttl=spoof_ttl)
                    except (OSError, RuntimeError, ValueError):
                        if pool is None:
                            pool = ThreadPoolExecutor(max_workers=batch_size)
                        futures = {pool.submit(_dispatch_safe, port, action_name): (port, action_name) for port, action_name in zip(batch_ports, batch_actions)}
                        batch_results = []
                        for future in as_completed(futures):
                            batch_results.append(future.result())
                else:
                    if source_port is not None:
                        # Fallback to ThreadPool if source_port is strictly required (asyncio open_connection doesn't support source_port binding natively without custom transports)
                        if pool is None:
                            pool = ThreadPoolExecutor(max_workers=batch_size)
                        futures = {pool.submit(_dispatch_safe, port, action_name): (port, action_name) for port, action_name in zip(batch_ports, batch_actions)}
                        batch_results = []
                        for future in as_completed(futures):
                            batch_results.append(future.result())
                    else:
                        batch_results = async_batch_connect_probe(host, batch_ports, timeout=self.profile.probe_timeout)
                        
                batch_results.sort(key=lambda result: result.port)
                results.extend(batch_results)
                if batch_results:
                    last = batch_results[-1]
                    last_flag = last.protocol_flag
                    last_rtt = last.rtt_us
                    for result in batch_results:
                        if result.protocol_flag == "TIMEOUT":
                            streak += 1
                        else:
                            streak = 0
                    


                if probe_mode == "raw" and _raw_guard_enabled and not raw_guard_checked and port_index >= raw_guard_validate_after:
                    raw_guard_checked = True
                    raw_open_ports = [
                        result.port
                        for result in results
                        if result.protocol == "tcp" and result.protocol_flag == "SYN_ACK"
                    ]
                    sample_ports = raw_open_ports[:RAW_GUARD_SAMPLE_SIZE]
                    if len(sample_ports) == RAW_GUARD_SAMPLE_SIZE:
                        confirmed_sample = _confirm_ports_with_connect(
                            host,
                            sample_ports,
                            timeout=max(RAW_GUARD_CONFIRM_TIMEOUT, min(raw_profile.probe_timeout, 1.5)),
                            source_port=source_port,
                            max_workers=min(8, RAW_GUARD_SAMPLE_SIZE),
                        )
                        confirmed_count = sum(1 for result in confirmed_sample if result.protocol_flag == "SYN_ACK")
                        if confirmed_count < RAW_GUARD_MIN_CONFIRMATIONS:
                            _print(
                                "[yellow][Betta-Morpho] Raw SYN validation failed:[/] "
                                + f"{confirmed_count}/{len(sample_ports)} sample ports confirmed. "
                                + "Switching this host to TCP connect fallback."
                            )
                            results = _confirm_ports_with_connect(
                                host,
                                ports[:port_index],
                                timeout=self.profile.probe_timeout,
                                source_port=source_port,
                                max_workers=min(32, batch_size),
                            )
                            probe_mode = "connect"
                            deterministic_coverage = True
                            if results:
                                last = results[-1]
                                last_flag = last.protocol_flag
                                last_rtt = last.rtt_us
                                streak = 1 if last.protocol_flag == "TIMEOUT" else 0
                            else:
                                last_flag = "TIMEOUT"
                                last_rtt = 0.0
                                streak = 0

                if jitter_ms:
                    time.sleep(random.uniform(0, jitter_ms / 1000.0))

                while next_checkpoint and port_index >= next_checkpoint:
                    if progress_callback is not None:
                        progress_callback(next_checkpoint, len(ports), list(results[:next_checkpoint]))
                    next_checkpoint += checkpoint_step

                if progress_callback is None and port_index % 1000 == 0 and port_index > 0:
                    open_so_far = sum(1 for result in results if result.protocol_flag == "SYN_ACK")
                    _print(f"[dim]  {port_index}/{len(ports)} ports scanned, {open_so_far} open[/]")
        finally:
            if pool is not None:
                pool.shutdown(wait=True)

        if forced_probes:
            _print(f"[dim]Coverage guard forced {forced_probes} probe decisions in connect mode.[/]")

        open_results = [result for result in results if result.protocol_flag == "SYN_ACK" and not result.banner]
        if open_results and probe_mode == "raw":

            def _grab(result: PortResult) -> tuple[int, str]:
                try:
                    with _socket.create_connection((result.host, result.port), timeout=1.0) as connection:
                        banner, _payload_size = _recv_banner_chunks(connection, initial_wait=0.05, read_timeout=0.4, max_total_wait=1.5)
                        return result.port, banner
                except (OSError, TimeoutError):
                    return result.port, ""

            with ThreadPoolExecutor(max_workers=min(32, len(open_results))) as pool:
                for port, banner in pool.map(_grab, open_results):
                    for result in results:
                        if result.port == port and result.protocol_flag == "SYN_ACK":
                            result.banner = banner
                            if banner:
                                result.payload_size = len(banner)
                            _normalize_result_text_fields(result)

        return results

    def load_artifact(self, path: Path) -> None:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        validate_artifact_payload(data, expected_family=FAMILY_SCANNER)
        data = normalize_artifact_payload(
            data,
            expected_family=FAMILY_SCANNER,
            default_model_type="scan-strategy-snn",
            producer="training.tools.scanner",
        )
        self.W1 = np.array(data["W1"], dtype=np.float32)
        self.W2 = np.array(data["W2"], dtype=np.float32)
        hidden_dim = self.W1.shape[1]
        if self.V_h.shape[0] != hidden_dim:
            self.V_h = np.zeros(hidden_dim, dtype=np.float32)
        _print(f"[dim]Loaded scanner artifact: {path}[/]")

    def save_artifact(self, path: Path, meta: Optional[dict] = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict = {
            "scanner_version": 1,
            "profile": self.base_profile_name,
            "runtime_profile": self.profile.name,
            "speed_level": self.speed_level,
            "beta": self.profile.beta,
            "threshold": self.profile.threshold,
            "input_dim": INPUT_DIM,
            "hidden_dim": self.profile.hidden_dim,
            "output_dim": OUTPUT_DIM,
            "actions": ACTIONS,
            "W1": self.W1.tolist(),
            "W2": self.W2.tolist(),
        }
        if meta:
            payload.update(meta)
        payload = attach_artifact_metadata(
            payload,
            FAMILY_SCANNER,
            model_type="scan-strategy-snn",
            producer="training.tools.scanner",
            extra_metadata={"profile_name": self.base_profile_name},
        )
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        _print(f"[bold green]Saved[/] scanner artifact: {path}")


def _oracle_action(last_flag: str, streak: int, progress: float, profile_name: str) -> str:
    if progress >= 0.97:
        return "DONE"
    aggressive = profile_name in {"aggressive", "x5", "x10", "x15"}
    stealthy = profile_name in {"paranoid", "sneaky"}
    if last_flag == "ICMP_UNREACHABLE":
        return "SKIP"
    if last_flag in {"SYN_ACK", "UDP_RESPONSE", "ICMP_REPLY", "RST"}:
        return "PROBE_SYN"
    if streak == 0:
        return random.choice(["PROBE_SYN", "WAIT"]) if stealthy else "PROBE_SYN"
    if streak <= 2:
        if aggressive:
            return "PROBE_SYN"
        if stealthy:
            return "WAIT"
        return random.choice(["PROBE_SYN", "WAIT"])
    if streak <= 4:
        if aggressive:
            return "PROBE_SYN"
        return random.choice(["PROBE_FIN", "PROBE_NULL", "WAIT"])
    return "SKIP"


def generate_scanner_scenarios(
    n_scenarios: int = 600,
    ports_per_scenario: int = 30,
    profile_name: str = "normal",
    seed: int = 42,
) -> list[tuple[np.ndarray, int]]:
    rng = random.Random(seed)
    samples: list[tuple[np.ndarray, int]] = []
    all_flags = list(FLAG_INDEX.keys())
    for _ in range(n_scenarios):
        streak = 0
        last_flag = "TIMEOUT"
        last_rtt = rng.uniform(500, 5000)
        for port_index in range(ports_per_scenario):
            port = rng.randint(1, 65535)
            progress = port_index / ports_per_scenario
            context = SpikeScanEngine.encode(port, last_flag, last_rtt, progress, streak)
            action = _oracle_action(last_flag, streak, progress, profile_name)
            samples.append((context, ACTIONS.index(action)))
            if action in {"PROBE_SYN", "PROBE_FIN", "PROBE_NULL"}:
                roll = rng.random()
                if roll < 0.30:
                    last_flag = "SYN_ACK"
                    last_rtt = rng.uniform(200, 3000)
                    streak = 0
                elif roll < 0.70:
                    last_flag = "RST"
                    last_rtt = rng.uniform(100, 1000)
                    streak = 0
                else:
                    last_flag = "TIMEOUT"
                    last_rtt = 2_000_000.0
                    streak += 1
            elif action == "PROBE_UDP":
                roll = rng.random()
                last_flag = "UDP_RESPONSE" if roll < 0.25 else "ICMP_UNREACHABLE" if roll < 0.70 else "TIMEOUT"
                last_rtt = rng.uniform(500, 5000)
                streak = streak + 1 if last_flag == "TIMEOUT" else 0
            else:
                last_flag = rng.choice(all_flags)
                last_rtt = rng.uniform(500, 5000)
    return samples


def train_scanner_snn(
    engine: SpikeScanEngine,
    scenarios: int = 600,
    epochs: int = 30,
    lr: float = 0.01,
    seed: int = 42,
) -> float:
    data = generate_scanner_scenarios(n_scenarios=scenarios, profile_name=engine.profile.name, seed=seed)
    xs = np.stack([item[0] for item in data])
    ys = np.array([item[1] for item in data], dtype=np.int32)
    sample_count = len(xs)
    rng = np.random.default_rng(seed)
    best_accuracy = 0.0

    for epoch in range(1, epochs + 1):
        order = rng.permutation(sample_count)
        correct = 0
        for index in order:
            features = xs[index]
            target = ys[index]
            engine.V_h[:] = 0.0
            engine.V_o[:] = 0.0

            current_hidden = features @ engine.W1
            hidden_voltage = engine.profile.beta * engine.V_h + current_hidden
            hidden_spikes = (hidden_voltage >= engine.profile.threshold).astype(np.float32)
            hidden_voltage *= 1.0 - hidden_spikes

            current_output = hidden_spikes @ engine.W2
            output_voltage = engine.profile.beta * engine.V_o + current_output
            shifted = output_voltage - output_voltage.max()
            exp_values = np.exp(shifted)
            probabilities = exp_values / exp_values.sum()

            prediction = int(np.argmax(probabilities))
            correct += int(prediction == target)

            d_output = probabilities.copy()
            d_output[target] -= 1.0
            surrogate_hidden = 4.0 * (1.0 / (1.0 + np.exp(-4.0 * (hidden_voltage - engine.profile.threshold)))) * (
                1.0 - 1.0 / (1.0 + np.exp(-4.0 * (hidden_voltage - engine.profile.threshold)))
            )
            grad_w2 = np.outer(hidden_spikes, d_output)
            grad_hidden_spikes = d_output @ engine.W2.T
            grad_hidden = grad_hidden_spikes * surrogate_hidden
            grad_w1 = np.outer(features, grad_hidden)

            engine.W1 -= lr * grad_w1
            engine.W2 -= lr * grad_w2

        accuracy = correct / sample_count
        best_accuracy = max(best_accuracy, accuracy)
        if epoch % max(1, epochs // 5) == 0 or epoch == epochs:
            _print(f"  epoch {epoch:3d}/{epochs}  acc={accuracy:.3f}  best={best_accuracy:.3f}")

    return best_accuracy

