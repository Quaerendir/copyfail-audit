# Changelog

All notable changes to `copyfail-audit` are documented here.

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
