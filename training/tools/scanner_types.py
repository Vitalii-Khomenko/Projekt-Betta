from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class SNNProfile:
    """Hyperparameters that control Betta-Morpho scanner behaviour."""

    name: str
    beta: float
    threshold: float
    hidden_dim: int
    wait_ms: float
    probe_timeout: float
    ttl: int
    max_parallel: int


PROFILES: dict[str, SNNProfile] = {
    "paranoid": SNNProfile("paranoid", 0.95, 0.80, 24, 5000.0, 5.0, 64, 1),
    "sneaky": SNNProfile("sneaky", 0.88, 0.70, 20, 1000.0, 3.0, 64, 1),
    "polite": SNNProfile("polite", 0.75, 0.90, 16, 300.0, 2.0, 64, 1),
    "normal": SNNProfile("normal", 0.60, 1.00, 16, 50.0, 2.0, 64, 1),
    "aggressive": SNNProfile("aggressive", 0.30, 0.50, 12, 10.0, 1.0, 64, 4),
    "x5": SNNProfile("x5", 0.24, 0.45, 12, 5.0, 0.75, 64, 8),
    "x10": SNNProfile("x10", 0.18, 0.40, 12, 2.0, 0.50, 64, 16),
    "x15": SNNProfile("x15", 0.12, 0.35, 12, 1.0, 0.35, 64, 24),
}

MIN_MANUAL_SPEED_LEVEL = 1
MAX_MANUAL_SPEED_LEVEL = 100


def clamp_speed_level(level: int) -> int:
    return max(MIN_MANUAL_SPEED_LEVEL, min(MAX_MANUAL_SPEED_LEVEL, int(level)))


def derive_runtime_profile(base_profile: SNNProfile, speed_level: int | None = None) -> SNNProfile:
    """Return the runtime profile, optionally overriding pacing with a manual speed level.

    The manual speed level preserves the base profile's neural character while replacing
    transport pacing parameters with a smooth 1-100 throughput scale:
    - lower levels -> longer waits, higher timeouts, low parallelism
    - higher levels -> shorter waits, shorter timeouts, high parallelism
    """

    if speed_level is None:
        return base_profile

    level = clamp_speed_level(speed_level)
    norm = (level - MIN_MANUAL_SPEED_LEVEL) / (MAX_MANUAL_SPEED_LEVEL - MIN_MANUAL_SPEED_LEVEL)

    min_wait_ms = 0.25
    max_wait_ms = 5000.0
    min_timeout = 0.20
    max_timeout = 5.0
    min_parallel = 1
    max_parallel = 64

    wait_ms = math.exp(math.log(max_wait_ms) + (math.log(min_wait_ms) - math.log(max_wait_ms)) * norm)
    probe_timeout = math.exp(math.log(max_timeout) + (math.log(min_timeout) - math.log(max_timeout)) * norm)
    parallel = int(round(min_parallel + (max_parallel - min_parallel) * norm))

    return SNNProfile(
        name=f"{base_profile.name}@manual-{level}",
        beta=base_profile.beta,
        threshold=base_profile.threshold,
        hidden_dim=base_profile.hidden_dim,
        wait_ms=wait_ms,
        probe_timeout=probe_timeout,
        ttl=base_profile.ttl,
        max_parallel=max(min_parallel, min(max_parallel, parallel)),
    )

INPUT_DIM = 10
OUTPUT_DIM = 7
ACTIONS = ["PROBE_SYN", "PROBE_UDP", "PROBE_FIN", "PROBE_NULL", "WAIT", "SKIP", "DONE"]
FLAG_INDEX = {
    "SYN_ACK": 0,
    "RST": 1,
    "TIMEOUT": 2,
    "UDP_RESPONSE": 3,
    "ICMP_UNREACHABLE": 4,
    "ICMP_REPLY": 5,
}


@dataclass
class PortResult:
    host: str
    port: int
    state: str
    protocol: str
    protocol_flag: str
    rtt_us: float
    payload_size: int
    timestamp_us: int
    banner: str = ""
    os_hint: str = ""
    service: str = ""
    service_version: str = ""
    technology: str = ""
    cpe: str = ""
    cve_hint: str = ""
    service_prediction: str = ""
    service_confidence: float = 0.0
    response_entropy: float = 0.0
    tcp_window: int = 0
    scan_note: str = ""


TOP100_PORTS = sorted(
    {
        20, 21, 22, 23, 25, 53, 69, 79, 80, 88, 102, 110, 111, 113, 119, 135,
        137, 138, 139, 143, 161, 179, 194, 389, 443, 445, 636, 873, 902, 990,
        993, 995, 1024, 1080, 1194, 1352, 1433, 1521, 1610, 1723, 1883, 2049,
        2121, 2222, 27017, 27018, 28017, 3000, 3306, 3389, 3899, 4444, 47001,
        4848, 5000, 5432, 5555, 5601, 5800, 5900, 5985, 5986, 6379, 6443, 7001,
        7080, 7443, 8000, 8008, 8069, 8080, 8161, 8180, 8443, 8500, 8834, 8888,
        8983, 9000, 9042, 9090, 9092, 9200, 9300, 9418, 10000, 11211, 14330,
        50000, 50070,
    }
)
TOP20_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 9090]
