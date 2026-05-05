# Betta-Morpho Full Program Audit

Date: 2026-05-05

## Scope

- Static audit of the launcher, scanner CLI, probe layer, and Nmap verification flow.
- Dynamic validation with short Python snippets against the current workspace code.
- Baseline regression check with the nearest existing smoke and verification tests.

## Validation Run

- Python snippet: `parse_ports("@/definitely/missing/ports.txt")` returned `[]`; `scanner.main()` then printed `No open ports found.` and returned `0`.
- Python snippet: a local TCP listener on port `4464` accepted `connect_probe("127.0.0.1", 70000, ...)`, and Betta-Morpho reported the result as open on port `70000` with banner `wrapped-port-test`.
- Unit tests: `python -m unittest tools.test_launcher_smoke tools.test_verify_scan tools.test_raw_probe_safety`.
- Unit test result: `OK` (`12` tests).

## Findings

### 1. High: Out-of-range TCP ports are accepted and can probe the wrong OS-level port

- Files:
  - `training/tools/scanner_probes.py:64`
  - `training/tools/scanner_probes.py:679`
  - `training/tools/scanner_probes.py:697`
  - `training/tools/scanner_probes.py:702`
- Detail:
  - `parse_ports()` accepts arbitrary integers without enforcing the valid TCP/UDP range `1-65535`.
  - `connect_probe()` then forwards that unchecked value to the socket layer.
  - In this environment, `connect_probe("127.0.0.1", 70000, ...)` successfully connected to a listener on port `4464` while the returned `PortResult` still claimed the target port was `70000`.
- Impact:
  - False positives and false attribution in scan results.
  - Verification and reporting can describe a service on a port that was never actually probed.
- Recommendation:
  - Reject `0` and all values above `65535` in `parse_ports()` before scan execution.
  - Add regression tests for single values and ranges that cross the valid boundary.

### 2. Medium: Missing or unreadable `@port-file` inputs degrade into successful zero-port scans

- Files:
  - `training/tools/scanner_probes.py:655`
  - `training/tools/scanner_probes.py:676`
  - `training/tools/scanner.py:1017`
  - `training/tools/scanner.py:1273`
- Detail:
  - `_parse_ports_from_file()` catches all exceptions and returns an empty list.
  - The main scan flow consumes that empty list without validation and still exits with status `0`.
  - The validated runtime behavior was: `No open ports found.` followed by `main_return= 0` for a missing file path.
- Impact:
  - Operators can believe a scan completed successfully when no probes were sent.
  - Automation can record empty artifacts as successful runs.
- Recommendation:
  - Fail fast on unreadable port files.
  - Reject empty resolved port lists before scan start unless an explicit dry-run mode is requested.

### 3. Medium: CIDR targets are expanded eagerly with no upper bound

- Files:
  - `training/tools/scanner_probes.py:636`
  - `training/tools/scanner_probes.py:643`
  - `training/tools/scanner.py:1016`
- Detail:
  - `parse_targets()` materializes every host from `ipaddress.ip_network(...).hosts()` into a Python list.
  - There is no cap, streaming behavior, or confirmation gate for very large networks.
- Impact:
  - Large inputs such as `/8` scale to millions of hosts before the scanner can start work.
  - This can cause avoidable memory pressure or make the CLI appear hung.
- Recommendation:
  - Add an explicit maximum target count, or require an override flag for large expansions.
  - Prefer iterative target generation over eager full-list materialization.

### 4. Medium: Nmap verification has no subprocess timeout and runs inline in the scan pipeline

- Files:
  - `tools/verify_scan.py:157`
  - `tools/verify_scan.py:182`
  - `training/tools/scanner.py:1149`
  - `training/tools/scanner.py:1160`
- Detail:
  - `run_nmap()` invokes `subprocess.run(command, check=True)` without a timeout.
  - The scan CLI calls verification inline after the main scan when `--verify-with-nmap` is enabled.
- Impact:
  - A stalled or very slow Nmap run can block the entire post-scan reporting path indefinitely.
  - This is especially risky with heavier presets such as `deep`, `aggressive`, or script-based verification.
- Recommendation:
  - Add an operator-configurable timeout for verification.
  - Surface a clear partial-result state when verification is aborted or times out.

## Coverage Notes

- Existing tests cover launcher wiring, Nmap verification artifact naming, HTML verification rendering, and raw-scan fallback behavior.
- I did not find regression coverage for:
  - invalid port values outside `1-65535`
  - missing `@port-file` inputs
  - oversized CIDR target expansion

## Suggested Fix Order

1. Validate ports strictly at parse time and add tests for invalid single values and invalid ranges.
2. Turn unreadable `@port-file` inputs and empty port lists into explicit CLI errors.
3. Guard large CIDR expansion before materializing full target lists.
4. Add a timeout and cancellation boundary to Nmap verification.