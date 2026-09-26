# Changelog

All notable changes to `copyfail-audit` are documented here.

## [1.1.0] — 2026-09-26

### Changed — verdicts (review before relying on exit codes)
- A `modprobe.d` rule no longer counts as MITIGATED while `algif_aead` is still loaded; the verdict is VULNERABLE with an "rmmod required" note.
- A bare `blacklist algif_aead` is no longer a mitigation. The kernel requests the module by name (`algif-aead`), and `blacklist` only disables aliases, so it never stopped the autoload. Only `install algif_aead /bin/false` (or `/bin/true`) counts.
- A patched RHEL 8/9/10 vendor kernel is now SAFE; before, it was reported "PATCHED" but the verdict stayed VULNERABLE.
- `CONFIG_CRYPTO_USER_API_AEAD` not set (per the running kernel's config) → SAFE.
- Module not installed, or `kernel.modules_disabled=1` while not loaded → MITIGATED.

### Fixed
- RHEL 9/10 thresholds compared only the first build field (611.1.1 passed as ≥ 611.49.2); full builds are now compared.

### Security
- `PATH` is pinned, and the shebang is `#!/bin/bash` instead of `/usr/bin/env bash`.
- `/etc/os-release` is parsed as text instead of sourced, so embedded shell code is never executed.

### Added
- Regression tests (`tests/run_tests.sh`) with mock commands and fixture trees.
- CI: syntax check, tests and ShellCheck.

## [1.0.0] — 2026-05-01

Initial release, same-day as public disclosure (2026-04-29).

### Checks implemented
- Kernel version range validation (4.14 – 6.18.21 / 6.19.x < 6.19.12)
- Distribution-specific patched version comparison (RHEL 8/9/10, AlmaLinux, Ubuntu, Debian, SUSE, Arch)
- `algif_aead` module state detection: loaded, built-in (`CONFIG_CRYPTO_USER_API_AEAD=y`), or absent
- Kernel config parsing (`/proc/config.gz`, `/boot/config-$(uname -r)`)
- `modprobe.d` blacklist detection with built-in module false-security warning
- `initcall_blacklist=algif_aead_init` cmdline mitigation check
- GRUB persistence verification
- Active AF_ALG processes via `lsof`
- Kernel hardening sysctls
- Kernel lockdown status
- SELinux / AppArmor status
- Container / Kubernetes context detection

### Exit codes
- `0` — Safe
- `1` — Vulnerable
- `2` — Mitigated (workaround active, update still required)
- `3` — Unknown
