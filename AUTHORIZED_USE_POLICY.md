# Authorized Use Policy

Betta-Morpho may be used only in environments where you have clear authorization.

Allowed examples:

- your own lab, localhost, or development systems
- systems owned by your employer or client where you have explicit written approval
- training platforms, CTFs, or HTB-style labs that permit this kind of activity
- internal defensive testing, validation, and telemetry research

Not allowed examples:

- third-party systems without permission
- internet-wide opportunistic scanning without authorization
- scanning that violates platform rules, bug bounty scope, customer contracts, or internal policy
- attempts to hide unauthorized activity behind decoys, spoofing, or evasion features

Operator responsibilities:

- verify scope before each test
- use the least aggressive profile and speed consistent with the task
- avoid unnecessary load on production systems
- review whether verification, banner capture, live capture, replay, or enrichment may collect sensitive data
- store generated artifacts, captures, logs, and reports securely
- stop immediately if the activity exceeds the approved scope or creates unexpected impact

Project-specific note:

Stealth, decoy, source-port, TTL, jitter, and raw-mode features exist for
research and controlled testing. They are not permission substitutes and must
not be used to obscure unauthorized activity.

If you are unsure whether a target or workflow is authorized, do not run the scan.
