# Betta-Morpho Scan Speed Theory

## Purpose

This note explains what scan speed really means in Betta-Morpho, how it relates to target-side load, how it compares to Nmap, and how to reason about raising speed for training or practical testing.

## Core Variables

The practical scan rate is driven mostly by four variables:

- `probes_per_second`
- `concurrency`
- `average_probe_time`
- `work_per_probe`

A useful first-order approximation is:

```text
scan_rate approx. concurrency / average_probe_time
```

Example:

```text
concurrency = 400
average_probe_time = 0.10 s
scan_rate approx. 4000 probes/s
```

This is only a throughput estimate. It does not automatically mean the target is processing 4000 full application sessions per second.

## What Loads the Target

Target-side load depends more on probe type than on raw bandwidth.

### Raw-style TCP probing

Typical raw SYN behavior:

- send `SYN`
- receive `SYN-ACK` for open ports
- receive `RST` for closed ports

This usually loads the target less because the application service often does not need to accept a full connection.

### Connect-only probing

Typical connect behavior:

- full TCP handshake
- socket allocation on the target side
- optional banner or application-layer reads

This usually loads the target more than SYN-only probing, especially on open ports and banner-rich services.

### Application enrichment

Load rises further when the scanner does more than just detect openness:

- banner reads
- protocol greetings
- HTTP requests
- retry logic
- service fingerprinting

## Useful Practical Equations

### Ports in flight

```text
connections_in_flight approx. probes_per_second x average_RTT
```

If the average round-trip time is `0.08 s` and the scanner emits `5000 probes/s`:

```text
connections_in_flight approx. 5000 x 0.08 = 400
```

### Packet-rate estimate

For a TCP connect scan, packet count is not one packet per probe. A single successful connect often implies:

- `SYN`
- `SYN-ACK`
- `ACK`
- close sequence

So target packet processing grows faster than the simple count of open ports.

### Timeout pressure

When many ports are filtered or silent:

```text
resource_pressure approx. concurrency x timeout
```

High timeout plus high concurrency can create more scanner-side and target-side stress than fast negative responses.

## How Betta-Morpho Profiles Affect Speed

Betta-Morpho speed depends mainly on:

- `wait_ms`
- `probe_timeout`
- `max_parallel`

Higher speed means:

- shorter waits
- shorter timeouts
- more parallel work

That improves throughput, but only until the result quality starts degrading.

## Manual Speed Level 1-100

Betta-Morpho also supports a manual speed override:

- `1` = minimum pressure
- `50` = balanced manual pacing
- `100` = maximum manual throughput

This manual level keeps the chosen profile's neural behavior, but overrides runtime pacing:

- wait time
- timeout
- parallelism

So the selected profile still controls the style of the scanner, while the manual speed level controls how hard the runtime pushes the network.

## Comparison With Nmap

Nmap is often slower because it is usually more conservative and more diagnostic:

- adaptive timing
- retries
- careful state differentiation
- optional service detection
- optional version probing
- optional OS hints

Rough intuition:

- `nmap -sS` is closer to raw SYN discovery
- `nmap -sT` is closer to connect scanning
- `nmap -sV` is much heavier because it asks the service more questions

Betta-Morpho is usually best used as:

- fast discovery engine
- fast report generator
- training-data generator

Nmap is best used as:

- targeted verifier
- richer secondary control pass

## How to Know If More Speed Is Still Safe

You can usually raise speed further while these remain stable:

- open-port count
- repeatability across repeated runs
- filtered/timeout ratio
- RTT distribution
- agreement with a control scan

Warning signs that speed is too high:

- open ports disappear intermittently
- filtered ports rise sharply
- repeated runs disagree often
- timeout-heavy behavior grows
- control scans consistently find ports that Betta-Morpho misses

## Practical Recommendations

### Good places for high speed

- localhost
- controlled lab ranges
- LAN testing
- internal validation
- synthetic-data generation

### Be more careful on

- HTB / VPN links
- unstable WAN targets
- filtered networks
- rate-limited services
- fragile production systems

## Recommended Operating Model

For real testing, a strong workflow is:

1. Betta-Morpho fast scan for discovery
2. optional service-model enrichment
3. targeted Nmap verification only on Betta-Morpho-open ports

This gives high throughput without paying Nmap's full cost across the entire port space.
