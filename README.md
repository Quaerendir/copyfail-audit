# copyfail-audit

![CVE](https://img.shields.io/badge/CVE-2026--31431-red?style=flat-square)
![CVSS](https://img.shields.io/badge/CVSS-7.8%20HIGH-orange?style=flat-square)
![Shell](https://img.shields.io/badge/shell-bash-4EAA25?style=flat-square&logo=gnu-bash)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Disclosed](https://img.shields.io/badge/disclosed-2026--04--29-yellow?style=flat-square)

Audit script for **CVE-2026-31431 "Copy Fail"** — a Linux kernel local privilege escalation vulnerability affecting virtually every major Linux distribution released since 2017.

---

## What is Copy Fail?

**Copy Fail** is a logic bug in the Linux kernel's cryptographic subsystem introduced in 2017 via commit `72548b093ee3`, which optimized `algif_aead` to operate in-place.

The attack chain:

```
AF_ALG SEQPACKET socket
  └── algif_aead (AEAD userspace crypto interface)
        └── authencesn(hmac(sha256),cbc(aes))
              └── splice() from a readable file (e.g. /usr/bin/su)
                    └── 4-byte scratch write → lands in PAGE CACHE
                          └── kernel executes modified in-memory binary
                                └── root
```

Key properties that make it dangerous:

- ✗ **No race condition** — unlike Dirty Cow / Dirty Pipe, it works every time
- ✗ **No disk modification** — file on disk untouched, forensics miss it
- ✗ **No special capabilities** — any local user with a shell
- ✗ **Broadly applicable** — single 732-byte Python PoC works across distros
- ✗ **Container escape potential** — page cache is shared across the host kernel

> **Fix:** mainline commit `a664bf3d603d` — reverts the 2017 in-place optimization.

---

## Affected Kernels

| Range | Status |
|---|---|
| < 4.14 | ✅ Not affected (optimization didn't exist) |
| **4.14 – 6.18.21** | ❌ **Vulnerable** |
| **6.19.x < 6.19.12** | ❌ **Vulnerable** |
| ≥ 6.18.22 | ✅ Patched |
| ≥ 6.19.12 | ✅ Patched |
| ≥ 7.0 | ✅ Patched |

### Distribution Patch Status

| Distribution | Patched Version |
|---|---|
| AlmaLinux / RHEL 8 | `kernel-4.18.0-553.121.1.el8_10` |
| AlmaLinux / RHEL 9 | `kernel-5.14.0-611.49.2.el9_7` |
| AlmaLinux / RHEL 10 | `kernel-6.12.0-124.52.2.el10_1` |
| Ubuntu ≥ 26.04 | Not affected (ships unaffected kernel) |
| Ubuntu < 26.04 | Patch available via `apt-get dist-upgrade` |
| Debian | Patch available via `apt-get dist-upgrade` |
| SUSE | Patch available via `zypper update kernel-default` |
| Arch | Patch available via `pacman -Syu linux` |

---

## Usage

```bash
# Clone
git clone https://github.com/Quaerendir/copyfail-audit
cd copyfail-audit

# Run (no root required for audit)
chmod +x audit_copyfail.sh
./audit_copyfail.sh
```

**Remote one-liner** (verify the script before running in prod):

```bash
curl -fsSL https://raw.githubusercontent.com/Quaerendir/copyfail-audit/main/audit_copyfail.sh | bash
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Safe — kernel not in vulnerable range |
| `1` | Vulnerable — no mitigation active |
| `2` | Mitigated — workaround active, but update still required |
| `3` | Unknown — could not determine state |

Useful for automation:

```bash
./audit_copyfail.sh
case $? in
  0) echo "All good" ;;
  1) echo "PATCH IMMEDIATELY" ;;
  2) echo "Workaround active — schedule update" ;;
  3) echo "Manual check required" ;;
esac
```

---

## What the Script Checks

| Check | Details |
|---|---|
| Kernel version | Numeric comparison against all known patched upstream versions |
| Distro patch level | RPM/DEB package version vs patched release per distro |
| `algif_aead` module state | Loaded, built-in (`CONFIG_CRYPTO_USER_API_AEAD=y`), or absent |
| Kernel config | Reads `/proc/config.gz` or `/boot/config-$(uname -r)` |
| `modprobe.d` blacklist | Detects rule presence AND warns if built-in (rule is useless) |
| `initcall_blacklist=` cmdline | The only effective mitigation for built-in modules |
| GRUB persistence | Verifies the mitigation will survive reboot |
| Active AF_ALG users | `lsof` for processes currently using the interface |
| Kernel hardening | `dmesg_restrict`, `kptr_restrict`, `perf_event_paranoid` |
| Kernel lockdown | `/sys/kernel/security/lockdown` |
| SELinux / AppArmor | Containment layer status |
| Container context | Docker/Podman/LXC detection + Kubernetes node warning |

> ⚠️ **Important:** On many distributions `algif_aead` is compiled into the kernel (`CONFIG_CRYPTO_USER_API_AEAD=y`). In this case, `modprobe.d` blacklisting runs without errors but **has no effect**. The script detects and flags this false-security scenario. Only `initcall_blacklist=algif_aead_init` on the kernel cmdline works for built-in modules.

---

## Mitigation

### Option A — Update the kernel (definitive fix)

```bash
# RHEL / AlmaLinux 8
yum update kernel    # target: ≥ 4.18.0-553.121.1.el8_10

# RHEL / AlmaLinux 9
dnf update kernel    # target: ≥ 5.14.0-611.49.2.el9_7

# Ubuntu / Debian
apt-get update && apt-get dist-upgrade

# SUSE
zypper update kernel-default

# Arch
pacman -Syu linux
```

### Option B — Blacklist module (loadable `.ko` only)

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

### Option C — initcall_blacklist (required for built-in modules)

```bash
grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
# or manually in /etc/default/grub → GRUB_CMDLINE_LINUX, then:
grub2-mkconfig -o /boot/grub2/grub.cfg
# REBOOT required
```

Verify after reboot:

```bash
grep initcall_blacklist /proc/cmdline
```

### Option D — Live patch (no reboot, KernelCare)

```bash
kcarectl --update
kcarectl --info | grep CVE-2026-31431
```

### What is NOT affected by the workaround

Disabling `algif_aead` does not affect:
`dm-crypt` / `LUKS` · `kTLS` · `IPsec/XFRM` · `OpenSSL` · `GnuTLS` · `NSS` · `SSH`

Only applications explicitly using `AF_ALG` for AEAD (rare outside hardware crypto offload or OpenSSL `afalg` engine) are impacted.

---

## Comparison to Dirty Cow / Dirty Pipe

| Property | Dirty Cow (2016) | Dirty Pipe (2022) | **Copy Fail (2026)** |
|---|---|---|---|
| Kernel range | 2.6.22 – 4.8 | 5.8 – 5.16 | **4.14 – 6.18.21** |
| Race condition needed | ✅ Yes | ❌ No | ❌ **No** |
| Works every run | ❌ Timing-dependent | ✅ Yes | ✅ **Yes** |
| Modifies disk | ✅ Yes | ❌ No | ❌ **No** |
| Forensic trace | ✅ Yes | ❌ No | ❌ **No** |
| PoC size | Large | Medium | **732 bytes Python** |

---

## References

- [copy.fail](https://copy.fail) — Theori / Xint Code researcher writeup
- [theori-io/copy-fail-CVE-2026-31431](https://github.com/theori-io/copy-fail-CVE-2026-31431) — public PoC
- [CERT-EU Advisory 2026-005](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [Tenable FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions)
- [Help Net Security writeup](https://www.helpnetsecurity.com/2026/04/30/copyfail-linux-lpe-vulnerability-cve-2026-31431/)
- [The Register](https://www.theregister.com/2026/04/30/linux_cryptographic_code_flaw/)
- [Sysdig analysis + Falco rule](https://sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds)
- [AlmaLinux announcement](https://almalinux.org/blog/2026-05-01-cve-2026-31431-copy-fail/)
- [OVHcloud MKS mitigation](https://blog.ovhcloud.com/copy-fail-cve-2026-31431-how-to-rapidly-protect-ovhcloud-mks-clusters-from-the-linux-kernel-zero-day/)

---

## License

MIT — see [LICENSE](LICENSE)

---

*Quaerendir / Kostur IT SERVICES*
