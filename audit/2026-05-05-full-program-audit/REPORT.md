# Betta-Morpho Full Program Audit

Date: 2026-05-05

## Scope

- Static audit of the launcher, scanner CLI, probe layer, Fast Start flow, and Nmap verification flow.
- Post-fix validation against the current workspace code.
- Dynamic validation of the previously reported failure modes.
- Baseline regression checks around launcher wiring, probe safety, scan telemetry, and Nmap verification.

## Current Summary

The original high/medium findings in this audit are now addressed in the current workspace:

- Out-of-range TCP/UDP ports are rejected before scan execution and before direct probe calls reach the socket layer.
- Missing or unreadable `@port-file` inputs fail explicitly instead of becoming successful zero-port scans.
- Empty resolved port lists are rejected before the scanner starts.
- CIDR/range target expansion has a default safety limit and a CLI override.
- Nmap verification has an operator-configurable subprocess timeout.
- Fast Start now shows live scan statistics and prints open ports immediately when discovered.
- A `--dry-run` mode validates and previews targets/ports without sending probes.

No new high-severity issue was found in the audited surfaces during this follow-up pass.

## Validation Run

Commands executed:

```bash
.venv/bin/python -m unittest tools.test_launcher_smoke tools.test_raw_probe_safety tools.test_scanner_telemetry tools.test_verify_scan
.venv/bin/python -m py_compile launcher.py training/tools/scanner.py training/tools/scanner_engine.py training/tools/scanner_probes.py tools/verify_scan.py
.venv/bin/python training/tools/scanner.py scan --target 127.0.0.1 --ports 22,80 --dry-run
.venv/bin/python launcher.py scan --target 127.0.0.1 --ports 22,80 --dry-run
```

Result:

- Unit tests: `OK` (`25` tests).
- Python compile check: `OK`.
- Dry-run validation: `OK`.

Dynamic validation snippets:

```text
parse_ports_zero: ValueError: invalid tcp port 0: expected 1-65535
parse_ports_high: ValueError: invalid tcp port 70000: expected 1-65535
parse_ports_range_high: ValueError: invalid tcp port 70000: expected 1-65535
missing_port_file: FileNotFoundError: [Errno 2] No such file or directory: '/definitely/missing/ports.txt'
large_cidr: ValueError: CIDR '10.0.0.0/8' is too large: limit is 4096 hosts
direct_connect_high: ValueError: invalid tcp port 70000: expected 1-65535
```

CLI validation:

```bash
.venv/bin/python training/tools/scanner.py scan --target 127.0.0.1 --ports 70000 --minimal-output --fast-start-stats --connect-only
```

Result:

```text
ERROR: invalid scan input: invalid tcp port 70000: expected 1-65535
exit=2
```

Dry-run validation:

```text
Dry run: no probes sent.
targets=1 preview=127.0.0.1
tcp_ports=2 preview=22, 80
profile=normal
max_targets=4096
```

## Finding Status

### 1. Resolved: Out-of-range TCP ports are accepted and can probe the wrong OS-level port

Original severity: High

Original issue:

- `parse_ports()` accepted arbitrary integers outside the valid TCP/UDP range.
- Direct calls such as `connect_probe("127.0.0.1", 70000, ...)` could reach the socket layer.
- On this platform, that could connect to a wrapped OS-level port while reporting the logical target as `70000`.

Current fix:

- Added `MIN_PORT = 1` and `MAX_PORT = 65535` in `training/tools/scanner_probes.py`.
- Added `_validate_port()` and wired it into:
  - `parse_ports()`
  - `connect_probe()`
  - `_async_connect_probe()`
  - `syn_probe()`
  - `batch_syn_probe()`
  - `udp_probe()`
  - `udp_connect_probe()`
- Scanner CLI now catches invalid scan input and returns exit code `2`.

Regression coverage:

- `tools.test_raw_probe_safety.test_parse_ports_rejects_out_of_range_values`
- `tools.test_raw_probe_safety.test_connect_probe_rejects_out_of_range_port_before_socket_layer`

Status: Resolved.

### 2. Resolved: Missing or unreadable `@port-file` inputs degrade into successful zero-port scans

Original severity: Medium

Original issue:

- `_parse_ports_from_file()` caught all exceptions and returned `[]`.
- The scanner could then run with no ports and exit successfully.

Current fix:

- `_parse_ports_from_file()` now lets file read errors surface.
- Main scan input parsing rejects empty resolved TCP and UDP port lists.
- Scanner CLI returns exit code `2` for invalid scan input.

Regression coverage:

- `tools.test_raw_probe_safety.test_parse_ports_missing_file_raises`
- CLI validation with `@/definitely/missing/ports.txt`.

Status: Resolved.

### 3. Resolved: CIDR targets are expanded eagerly with no upper bound

Original severity: Medium

Original issue:

- `parse_targets()` materialized every host in a CIDR before scan execution.
- Inputs such as `/8` could cause large memory pressure or an apparent hang.

Current fix:

- Added `MAX_TARGETS = 4096` default guard in `training/tools/scanner_probes.py`.
- `parse_targets(spec, max_targets=...)` rejects large CIDR/range inputs before full expansion.
- Added scanner CLI flag:
  - `--max-targets N`
  - `0` disables the limit for operators who explicitly need it.
- Launcher now forwards `--max-targets` and exposes it in advanced guided scan options.

Regression coverage:

- `tools.test_raw_probe_safety.test_parse_targets_rejects_large_cidr_before_expansion`
- Launcher parser coverage for `--max-targets`.

Status: Resolved.

### 4. Resolved: Nmap verification has no subprocess timeout and runs inline in the scan pipeline

Original severity: Medium

Original issue:

- `run_nmap()` used `subprocess.run(command, check=True)` without a timeout.
- Inline post-scan verification could block reporting indefinitely.

Current fix:

- Added `NMAP_DEFAULT_TIMEOUT_SECONDS = 900`.
- Added `--nmap-timeout` to `tools/verify_scan.py`.
- Added `--nmap-timeout` to scanner CLI and launcher scan forwarding.
- `run_nmap()` now calls `subprocess.run(..., timeout=timeout_seconds)`.
- `subprocess.TimeoutExpired` is caught in scanner verification handling.

Regression coverage:

- `tools.test_verify_scan.test_run_nmap_preserves_dotted_session_prefix_for_xml` now verifies timeout forwarding.
- Launcher parser coverage for `--nmap-timeout`.

Status: Resolved.

## Fast Start Follow-Up Audit

Fast Start behavior was also reviewed after the user-requested changes.

Current behavior:

- Main launcher menu now uses ordered items:
  - `1` Fast Start
  - `2` Project learning
  - `3` Model training
  - `4` Scanner launch
- Scanner Launch submenu also has Fast Start as item `1`.
- Fast Start asks only for target IP.
- Fast Start command shape:

```bash
scan --target <IP> --ports 1-65535 --profile aggressive --speed-level 300 --checkpoint-every 0 --max-targets 4096 --no-discovery --minimal-output --fast-start-stats
```

Live statistics include:

- progress bar
- percent complete
- scanned/total ports
- elapsed scan time
- approximate sent KB
- approximate received KB
- requests per second

Open ports are printed immediately when first observed, while the scan continues.

Example output shape:

```text
[########################] 100.0%  ports=3/3  time=00:00:02  tx=0.2KB  rx=0.1KB  req/s=1.5
OPEN host=127.0.0.1 port=8765 proto=tcp
[########################] 100.0%  ports=3/3  time=00:00:02  tx=0.2KB  rx=0.1KB  req/s=1.5
```

Note:

- `tx` and `rx` are scanner-side estimates based on probe/result metadata, not kernel packet counters.
- This is suitable for operator progress feedback, but not for exact network accounting.

## Remaining Notes

No high-severity blocker remains from this audit. Suggested future hardening:

1. Add an exact packet accounting mode if precise TX/RX byte counts become important.
2. Consider streaming target iteration for very large authorized scans instead of requiring `--max-targets 0`.

## Additional Hardening Completed

### Dry-run mode

Status: Implemented.

Added scanner and launcher support for:

```bash
--dry-run
```

Behavior:

- resolves target input with the same `--max-targets` guard as a real scan
- resolves TCP and optional UDP port specifications
- rejects invalid ports and missing `@port-file` inputs
- prints concise previews
- exits before creating the scan engine or sending probes

Regression coverage:

- `tools.test_scanner_telemetry.test_scan_dry_run_resolves_inputs_without_probe_engine`
- launcher parser coverage for `--dry-run`

### Nmap timeout partial-status reporting

Status: Implemented.

When inline Nmap verification times out during the scanner pipeline:

- scanner keeps the main scan results
- scanner creates an in-memory verification summary with `verification_status=timeout`
- generated HTML reports can show the timeout status and error text
- Betta-Morpho-open ports are retained as `betta_morpho_only_ports` in that partial summary

Regression coverage:

- `tools.test_verify_scan.test_export_html_renders_verification_timeout_status`

## Files Reviewed

- `launcher.py`
- `training/tools/scanner.py`
- `training/tools/scanner_engine.py`
- `training/tools/scanner_probes.py`
- `tools/verify_scan.py`
- `tools/test_launcher_smoke.py`
- `tools/test_raw_probe_safety.py`
- `tools/test_scanner_telemetry.py`
- `tools/test_verify_scan.py`
