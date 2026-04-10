# GitHub Copilot Instructions - Betta-Morpho

These rules apply to the entire repository.

---

## 1. File Headers

Every source file should begin with a short header block that includes:

- what the file does
- main usage or CLI entry
- author line
- license line
- current version

### Python

```python
# =============================================================================
# module_name.py  - one-line description
# =============================================================================
# Usage:
#   python module_name.py [options]
#   python module_name.py --help
#
# Key options:
#   --option VALUE   Description
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 0.1.0
# =============================================================================
```

### Rust

```rust
//! # module_name
//!
//! One-line description of what this module does.
//!
//! ## Usage
//! ```bash
//! cargo run -- [options]
//! ```
//!
//! Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
//! License : Apache-2.0 - see LICENSE
//! Version : 0.1.0
```

### YAML / TOML / JSON

```yaml
# =============================================================================
# filename.yml  - one-line description
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 0.1.0
# =============================================================================
```

### Bash / Shell

```bash
#!/usr/bin/env bash
# =============================================================================
# script.sh  - one-line description
# Usage   : ./script.sh [options]
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 0.1.0
# =============================================================================
```

---

## 2. Versioning

- meaningful code changes should update the modified file header version
- package version updates belong in `pyproject.toml` or Rust metadata when the distributed package meaningfully changes
- follow Semantic Versioning where practical

Do not invent version badges or changelog sections that do not exist.

---

## 3. Documentation Rules

- documentation must stay aligned with actual behavior
- docstrings and user-facing docs must be in English
- public Python functions and classes should have docstrings when they are part of the operator-facing or developer-facing surface

The repository now uses split documentation:

- `README.md` is the short entry point
- detailed usage belongs in `docs/`
- legal and usage boundaries live in:
  - `LICENSE`
  - `NOTICE`
  - `DISCLAIMER.md`
  - `AUTHORIZED_USE_POLICY.md`
  - `TRADEMARKS.md`
  - `CONTRIBUTING.md`
  - `DCO`

When behavior changes:

- update the relevant guide in `docs/`
- update `README.md` only if the quickstart, top-level command examples, or document map changed

---

## 4. License, Attribution, and Contributor Protection

- every new file should preserve author attribution in the header
- every new file should use the Apache-2.0 license line in its header
- do not remove or weaken `LICENSE`, `NOTICE`, `DISCLAIMER.md`, `AUTHORIZED_USE_POLICY.md`, `TRADEMARKS.md`, `CONTRIBUTING.md`, or `DCO`
- if code is adapted from an external source, add an `Adapted from:` note with the source URL when appropriate

Important repository facts:

- the project license is Apache License 2.0
- the project also ships a `NOTICE` file
- the Betta-Morpho name and branding are not granted for unrestricted reuse; see `TRADEMARKS.md`
- contributor sign-off uses the Developer Certificate of Origin in `DCO`

---

## 5. General Quality Rules

- no dead code after refactors
- no unexplained `TODO` comments
- no hardcoded secrets or credentials
- new Python functions should use type annotations
- CLI tools must support `--help`
- new operator-facing behavior should include either a smoke test or a usage example in docs

Static analysis and tests are first-class:

- keep `pyright` clean
- keep launcher and scanner flows testable from CLI
- prefer fixing stale documentation and stale policy text in the same change that updates behavior

---

## 6. Scope and Authorization

Betta-Morpho is for authorized security work only:

- approved penetration testing
- HTB or CTF environments
- isolated labs
- local validation
- defensive telemetry research

Do not generate changes that normalize or encourage:

- unauthorized targeting
- destructive actions against real infrastructure
- misuse of stealth or evasion features as a substitute for permission

When in doubt, align any new guidance with:

- `DISCLAIMER.md`
- `AUTHORIZED_USE_POLICY.md`
