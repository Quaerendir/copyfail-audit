#!/usr/bin/env bash
# =============================================================================
#  audit_copyfail.sh — CVE-2026-31431 "Copy Fail" Audit Script
#  Author  : Quaerendir
#  Version : 1.0.0
#  Date    : 2026-05-01
#  License : MIT
#  Repo    : https://github.com/Quaerendir/copyfail-audit
#
#  CVE-2026-31431 "Copy Fail" — Linux Kernel Local Privilege Escalation
#  -----------------------------------------------------------------------
#  CVSS  : 7.8 HIGH
#  CWE   : CWE-787 (Out-of-bounds Write)
#  Intro : 2017 (commit 72548b093ee3 — algif_aead in-place optimization)
#  Fix   : mainline commit a664bf3d603d (revert of the 2017 optimization)
#  Scope : Linux kernel 4.14 – 6.18.21 / 6.19.x < 6.19.12
#
#  Root cause:
#    authencesn (IPsec AEAD template) + AF_ALG SEQPACKET socket + splice()
#    An unprivileged local user can write 4 controlled bytes into the page
#    cache of any readable file, including SUID binaries, to gain root.
#    The disk file is NOT modified — no forensic trace left.
#
#  References:
#    https://copy.fail                               — researcher writeup
#    https://github.com/theori-io/copy-fail-CVE-2026-31431  — public PoC
#    https://cert.europa.eu/publications/security-advisories/2026-005/
#    https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions
# =============================================================================

set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ─── State ────────────────────────────────────────────────────────────────────
VULN_STATE="UNKNOWN"   # SAFE | MITIGATED | VULNERABLE | UNKNOWN
ISSUES=()
MITIGATIONS=()

# ─── Helpers ──────────────────────────────────────────────────────────────────
header() { printf "\n${BOLD}${CYAN}══╡ %s ╞${RESET}\n\n" "$1"; }
ok()     { printf "  ${GREEN}[OK]${RESET}   %s\n" "$1"; }
warn()   { printf "  ${YELLOW}[!!]${RESET}   %s\n" "$1"; }
fail()   { printf "  ${RED}[VULN]${RESET} %s\n" "$1"; }
info()   { printf "  ${CYAN}[i]${RESET}    %s\n" "$1"; }
sep()    { printf "  ${DIM}────────────────────────────────────────────${RESET}\n"; }

add_issue()      { ISSUES+=("$1"); }
add_mitigation() { MITIGATIONS+=("$1"); }

# ─── Banner ───────────────────────────────────────────────────────────────────
clear_screen() { [[ -t 1 ]] && printf '\033[2J\033[H' || true; }
clear_screen

printf "${BOLD}${RED}"
cat <<'BANNER'
  ██████╗ ██████╗ ██████╗ ██╗   ██╗    ███████╗ █████╗ ██╗██╗
 ██╔════╝██╔═══██╗██╔══██╗╚██╗ ██╔╝    ██╔════╝██╔══██╗██║██║
 ██║     ██║   ██║██████╔╝ ╚████╔╝     █████╗  ███████║██║██║
 ██║     ██║   ██║██╔═══╝   ╚██╔╝      ██╔══╝  ██╔══██║██║██║
 ╚██████╗╚██████╔╝██║        ██║       ██║     ██║  ██║██║███████╗
  ╚═════╝ ╚═════╝ ╚═╝        ╚═╝       ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝
BANNER
printf "${RESET}"
printf "  ${BOLD}CVE-2026-31431 \"Copy Fail\" — Linux Kernel LPE Audit v1.0.0${RESET}\n"
printf "  ${DIM}Disclosed 2026-04-29 | CVSS 7.8 HIGH | algif_aead + authencesn + splice()${RESET}\n\n"

# ─────────────────────────────────────────────────────────────────────────────
#  §1  SYSTEM INFORMATION
# ─────────────────────────────────────────────────────────────────────────────
header "1 · System Information"

KERNEL=$(uname -r)
ARCH=$(uname -m)
HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)
KVER_MAJOR=$(cut -d. -f1 <<< "$KERNEL")
KVER_MINOR=$(cut -d. -f2 <<< "$KERNEL")
KVER_PATCH=$(cut -d. -f3 <<< "$KERNEL" | grep -oP '^\d+' || echo 0)

DISTRO_NAME="unknown"; DISTRO_ID="unknown"; DISTRO_VERSION="0"
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO_NAME="${NAME:-unknown} ${VERSION_ID:-}"
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION="${VERSION_ID:-0}"
fi

info "Hostname   : $HOSTNAME_FQDN"
info "Distro     : $DISTRO_NAME"
info "Kernel     : $KERNEL"
info "Arch       : $ARCH"
info "Date       : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ─────────────────────────────────────────────────────────────────────────────
#  §2  KERNEL VERSION CHECK
# ─────────────────────────────────────────────────────────────────────────────
header "2 · Kernel Version"

info "Parsed: ${KVER_MAJOR}.${KVER_MINOR}.${KVER_PATCH}"

if (( KVER_MAJOR < 4 )) || ( (( KVER_MAJOR == 4 )) && (( KVER_MINOR < 14 )) ); then
    ok "Kernel < 4.14 — vulnerability NOT present (in-place opt. was not introduced yet)"
    VULN_STATE="SAFE"

elif (( KVER_MAJOR >= 7 )); then
    ok "Kernel ≥ 7.0 — vulnerability NOT present (upstream fix included)"
    VULN_STATE="SAFE"

elif (( KVER_MAJOR == 6 )) && (( KVER_MINOR == 18 )) && (( KVER_PATCH >= 22 )); then
    ok "Kernel 6.18.${KVER_PATCH} ≥ 6.18.22 — patched (upstream fix)"
    VULN_STATE="SAFE"

elif (( KVER_MAJOR == 6 )) && (( KVER_MINOR == 19 )) && (( KVER_PATCH >= 12 )); then
    ok "Kernel 6.19.${KVER_PATCH} ≥ 6.19.12 — patched (upstream fix)"
    VULN_STATE="SAFE"

else
    fail "Kernel ${KERNEL} is in vulnerable range (4.14 – 6.18.21 / 6.19.11)"
    add_issue "Kernel $KERNEL lacks upstream fix"
    VULN_STATE="VULNERABLE"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §3  DISTRIBUTION-SPECIFIC PATCHED VERSIONS
# ─────────────────────────────────────────────────────────────────────────────
header "3 · Distribution Patch Status"

_rhel_check() {
    command -v rpm &>/dev/null || return
    local kpkg ver_major patched=false
    kpkg=$(rpm -q kernel 2>/dev/null | grep "$(uname -r)" | head -1 || true)
    [[ -n "$kpkg" ]] && info "Installed kernel RPM: $kpkg"
    ver_major="${DISTRO_VERSION%%.*}"

    case "$ver_major" in
        8)
            local n
            n=$(uname -r | grep -oP '4\.18\.0-\K\d+' || echo 0)
            if (( n > 553 )); then patched=true
            elif (( n == 553 )); then
                local s; s=$(uname -r | grep -oP '553\.\K\d+' || echo 0)
                (( s >= 121 )) && patched=true
            fi
            "$patched" && ok  "RHEL/AlmaLinux 8: kernel ≥ 4.18.0-553.121.1.el8_10 — PATCHED" || \
                         fail "RHEL/AlmaLinux 8: needs kernel ≥ 4.18.0-553.121.1.el8_10"; $patched || add_issue "RHEL8 kernel unpatched"
            ;;
        9)
            local n; n=$(uname -r | grep -oP '5\.14\.0-\K\d+' || echo 0)
            (( n >= 611 )) && patched=true
            "$patched" && ok  "RHEL/AlmaLinux 9: kernel ≥ 5.14.0-611.49.2.el9_7 — PATCHED" || \
                         fail "RHEL/AlmaLinux 9: needs kernel ≥ 5.14.0-611.49.2.el9_7"; $patched || add_issue "RHEL9 kernel unpatched"
            ;;
        10)
            local n; n=$(uname -r | grep -oP '6\.12\.0-\K\d+' || echo 0)
            (( n >= 124 )) && patched=true
            "$patched" && ok  "RHEL/AlmaLinux 10: kernel ≥ 6.12.0-124.52.2.el10_1 — PATCHED" || \
                         fail "RHEL/AlmaLinux 10: needs kernel ≥ 6.12.0-124.52.2.el10_1"; $patched || add_issue "RHEL10 kernel unpatched"
            ;;
        *)  info "RHEL family v$ver_major — no specific patched version on record yet" ;;
    esac
}

_deb_check() {
    command -v dpkg &>/dev/null || return
    local kpkg
    kpkg=$(dpkg -l "linux-image-$(uname -r)" 2>/dev/null | grep '^ii' | awk '{print $2" "$3}' || true)
    [[ -n "$kpkg" ]] && info "Installed kernel DEB: $kpkg"
    case "$DISTRO_ID" in
        ubuntu)
            local maj="${DISTRO_VERSION%%.*}"
            if (( maj >= 26 )); then
                ok "Ubuntu ≥ 26.04 — NOT affected (builtin fix in shipped kernel)"
                VULN_STATE="SAFE"
            else
                warn "Ubuntu $DISTRO_VERSION — check: apt-get update && apt-cache show linux-image-\$(uname -r)"
            fi ;;
        debian) warn "Debian — check security.debian.org for kernel $KERNEL update" ;;
        *)      info "Debian-family ($DISTRO_ID) — manual check recommended" ;;
    esac
}

case "$DISTRO_ID" in
    almalinux|rocky|centos|rhel|fedora) _rhel_check ;;
    ubuntu|debian|linuxmint|pop)        _deb_check  ;;
    opensuse*|sles)   warn "SUSE — run: zypper update kernel-default" ;;
    arch|manjaro)     warn "Arch — run: pacman -Syu linux" ;;
    *)                info "Distribution $DISTRO_ID — manual patch verification required" ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
#  §4  algif_aead MODULE STATUS
# ─────────────────────────────────────────────────────────────────────────────
header "4 · algif_aead Module"

BUILTIN=false; LOADED=false

# ── Built-in check via modules.builtin ──
if [[ -f /lib/modules/"$(uname -r)"/modules.builtin ]]; then
    if grep -q 'algif_aead' /lib/modules/"$(uname -r)"/modules.builtin 2>/dev/null; then
        BUILTIN=true
    fi
fi

# ── Built-in check via kernel config ──
CONFIG_FILE=""
for f in /proc/config.gz "/boot/config-$(uname -r)" /boot/config; do
    [[ -f "$f" ]] && { CONFIG_FILE="$f"; break; }
done

if [[ -n "$CONFIG_FILE" ]]; then
    info "Kernel config: $CONFIG_FILE"
    if [[ "$CONFIG_FILE" == *.gz ]]; then
        AEAD_CFG=$(zcat "$CONFIG_FILE" 2>/dev/null | grep -m1 CONFIG_CRYPTO_USER_API_AEAD || echo "NOT_FOUND")
    else
        AEAD_CFG=$(grep -m1 CONFIG_CRYPTO_USER_API_AEAD "$CONFIG_FILE" 2>/dev/null || echo "NOT_FOUND")
    fi
    info "Config entry: $AEAD_CFG"
    if   echo "$AEAD_CFG" | grep -q '=y'; then BUILTIN=true
    elif echo "$AEAD_CFG" | grep -q '=m'; then info "algif_aead is a loadable module (.ko)"
    elif echo "$AEAD_CFG" | grep -q 'NOT_FOUND'; then warn "CONFIG_CRYPTO_USER_API_AEAD not found in config"
    else ok "CONFIG_CRYPTO_USER_API_AEAD not set — attack surface absent"
    fi
else
    warn "Kernel config not accessible (/proc/config.gz, /boot/config-*)"
fi

sep

if [[ "$BUILTIN" == "true" ]]; then
    fail "algif_aead is BUILT INTO the kernel (CONFIG_CRYPTO_USER_API_AEAD=y)"
    fail "modprobe.d blacklist will NOT work — initcall_blacklist= is required!"
    add_issue "algif_aead built-in: modprobe.d mitigation is ineffective"
    LOADED=true
else
    info "algif_aead is a loadable kernel module"
fi

# ── lsmod ──
if lsmod 2>/dev/null | grep -q '^algif_aead'; then
    LOADED=true
    fail "algif_aead is currently LOADED"
    add_issue "algif_aead module is active — exploit possible right now"
elif [[ "$BUILTIN" == "false" ]]; then
    ok "algif_aead module is NOT loaded"
fi

# ── AF_ALG active processes ──
if command -v lsof &>/dev/null; then
    AFALG_PROCS=$(lsof -n 2>/dev/null | grep -iE 'AF_ALG|algif' | head -10 || true)
    if [[ -n "$AFALG_PROCS" ]]; then
        warn "Processes actively using AF_ALG:"
        while IFS= read -r line; do warn "  ↳ $line"; done <<< "$AFALG_PROCS"
    else
        ok "No active processes using AF_ALG (via lsof)"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §5  MITIGATION VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────
header "5 · Mitigation Status"

BLACKLISTED_MODPROBE=false; BLACKLISTED_CMDLINE=false

# ── 5a: modprobe.d ──
printf "\n  ${BOLD}[a] modprobe.d blacklist${RESET}\n\n"
for modconf in /etc/modprobe.d/*.conf; do
    [[ -f "$modconf" ]] || continue
    if grep -qP '^(blacklist|install)\s+algif_aead' "$modconf" 2>/dev/null; then
        BLACKLISTED_MODPROBE=true
        rule=$(grep -P '^(blacklist|install)\s+algif_aead' "$modconf" | head -1)
        ok "Rule found in $modconf: ${rule}"
        [[ "$BUILTIN" == "true" ]] && { \
            fail "  BUT: module is built-in — this rule has NO EFFECT!"; \
            add_issue "False mitigation: modprobe.d rule on built-in module"; }
    fi
done
[[ "$BLACKLISTED_MODPROBE" == "false" ]] && {
    [[ "$BUILTIN" == "true" ]] && info "modprobe.d not applicable (built-in module)" || \
        warn "No blacklist/install rule found in /etc/modprobe.d/ for algif_aead"
}

# ── 5b: kernel cmdline ──
printf "\n  ${BOLD}[b] Kernel cmdline (initcall_blacklist)${RESET}\n\n"
CMDLINE=$(cat /proc/cmdline 2>/dev/null || true)
info "Active cmdline: $CMDLINE"

if grep -q 'initcall_blacklist=.*algif_aead_init' <<< "$CMDLINE"; then
    BLACKLISTED_CMDLINE=true
    ok "initcall_blacklist=algif_aead_init is ACTIVE — module blocked at boot"
    add_mitigation "initcall_blacklist=algif_aead_init in kernel cmdline"
else
    [[ "$BUILTIN" == "true" ]] && \
        { fail "Built-in module, but initcall_blacklist=algif_aead_init NOT in cmdline!"; \
          add_issue "Missing initcall_blacklist for built-in algif_aead"; } || \
        warn "initcall_blacklist=algif_aead_init not found in cmdline"
fi

# ── 5c: GRUB persistence ──
printf "\n  ${BOLD}[c] Mitigation persistence (GRUB)${RESET}\n\n"
GRUB_FOUND=false
for grubcfg in /etc/default/grub /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
    [[ -f "$grubcfg" ]] || continue
    if grep -q 'initcall_blacklist=.*algif_aead' "$grubcfg" 2>/dev/null; then
        ok "initcall_blacklist found in $grubcfg — survives reboot"
        GRUB_FOUND=true
    fi
done
[[ "$GRUB_FOUND" == "false" ]] && [[ "$BLACKLISTED_CMDLINE" == "true" ]] && \
    warn "initcall_blacklist active NOW but may not survive reboot (not found in /etc/default/grub)"
[[ "$GRUB_FOUND" == "false" ]] && [[ "$BLACKLISTED_CMDLINE" == "false" ]] && \
    info "initcall_blacklist not configured in GRUB"

# ─────────────────────────────────────────────────────────────────────────────
#  §6  KERNEL HARDENING CONTEXT
# ─────────────────────────────────────────────────────────────────────────────
header "6 · Kernel Hardening (Context)"

_sysctl_check() {
    local key="$1" desc="$2"
    local val; val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if   [[ "$val" == "N/A" ]]; then info "$key = N/A"
    elif (( val >= 1 )) 2>/dev/null; then ok  "$key = $val ($desc)"
    else                                 warn "$key = $val ($desc)"
    fi
}

_sysctl_check "kernel.dmesg_restrict"            "restrict /dev/kmsg access"
_sysctl_check "kernel.perf_event_paranoid"       "perf events paranoia"
_sysctl_check "kernel.kptr_restrict"             "kernel pointer hiding"
_sysctl_check "kernel.unprivileged_userns_clone" "unprivileged user namespaces"

info "Note: CopyFail does NOT require user namespaces — only a local shell"

sep
LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "N/A")
if [[ "$LOCKDOWN" == "N/A" ]]; then warn "Kernel lockdown: not available"
else info "Kernel lockdown: $LOCKDOWN"; fi

# ─────────────────────────────────────────────────────────────────────────────
#  §7  MAC (SELinux / AppArmor)
# ─────────────────────────────────────────────────────────────────────────────
header "7 · Mandatory Access Control"

if command -v getenforce &>/dev/null; then
    SE_STATUS=$(getenforce 2>/dev/null || echo "N/A")
    [[ "$SE_STATUS" == "Enforcing" ]] && \
        { ok "SELinux: Enforcing (additional containment layer)"; add_mitigation "SELinux Enforcing"; } || \
        warn "SELinux: $SE_STATUS"
elif [[ -f /sys/module/apparmor/parameters/enabled ]]; then
    AA=$(cat /sys/module/apparmor/parameters/enabled)
    [[ "$AA" == "Y" ]] && \
        { ok "AppArmor: active"; add_mitigation "AppArmor active"; } || \
        warn "AppArmor: inactive"
else
    warn "No MAC framework detected (SELinux/AppArmor)"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §8  CONTAINER / KUBERNETES CONTEXT
# ─────────────────────────────────────────────────────────────────────────────
header "8 · Container / Kubernetes Context"

IN_CONTAINER=false
[[ -f /.dockerenv ]] && { IN_CONTAINER=true; warn "Running INSIDE a Docker container"; }
grep -q 'container=podman\|container=lxc' /proc/1/environ 2>/dev/null && \
    { IN_CONTAINER=true; warn "Running inside a container (podman/lxc)"; }

if "$IN_CONTAINER"; then
    fail "CopyFail page cache is HOST-WIDE — container isolation does NOT protect the host kernel"
    add_issue "Container context: page cache shared with host — potential container escape"
else
    ok "Not running inside a detected container"
fi

if command -v kubectl &>/dev/null || [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
    warn "Kubernetes environment detected — prioritize patching all nodes!"
    add_issue "Kubernetes node detected — shared page cache risk across pods"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §9  FINAL VERDICT
# ─────────────────────────────────────────────────────────────────────────────
header "VERDICT — CVE-2026-31431 \"Copy Fail\""

printf "  Host:   %s\n" "$HOSTNAME_FQDN"
printf "  Distro: %s\n" "$DISTRO_NAME"
printf "  Kernel: %s\n\n" "$KERNEL"

# Refine state based on mitigation
if [[ "$VULN_STATE" != "SAFE" ]]; then
    if "$BLACKLISTED_CMDLINE" || ( "$BLACKLISTED_MODPROBE" && ! "$BUILTIN" ); then
        VULN_STATE="MITIGATED"
    fi
fi

case "$VULN_STATE" in
    SAFE)
    printf "  ${GREEN}${BOLD}╔══════════════════════════════════╗\n"
    printf "  ║  ✔  SAFE — not vulnerable         ║\n"
    printf "  ╚══════════════════════════════════╝${RESET}\n"
    ;;
    MITIGATED)
    printf "  ${YELLOW}${BOLD}╔══════════════════════════════════╗\n"
    printf "  ║  ⚡  MITIGATED — patch ASAP!       ║\n"
    printf "  ╚══════════════════════════════════╝${RESET}\n"
    printf "\n  ${YELLOW}Workaround is active but NOT a permanent fix.${RESET}\n"
    printf "  ${YELLOW}Update the kernel and remove the workaround.${RESET}\n"
    ;;
    VULNERABLE)
    printf "  ${RED}${BOLD}╔══════════════════════════════════╗\n"
    printf "  ║  ✘  VULNERABLE — patch NOW!        ║\n"
    printf "  ╚══════════════════════════════════╝${RESET}\n"
    ;;
    *)
    printf "  ${CYAN}${BOLD}╔══════════════════════════════════╗\n"
    printf "  ║  ?  UNKNOWN — manual check needed  ║\n"
    printf "  ╚══════════════════════════════════╝${RESET}\n"
    ;;
esac

# ── Issues ──
if [[ ${#ISSUES[@]} -gt 0 ]]; then
    printf "\n  ${RED}${BOLD}Issues found:${RESET}\n"
    for i in "${ISSUES[@]}"; do printf "  ${RED}→${RESET} %s\n" "$i"; done
fi

# ── Active mitigations ──
if [[ ${#MITIGATIONS[@]} -gt 0 ]]; then
    printf "\n  ${GREEN}${BOLD}Active mitigations:${RESET}\n"
    for m in "${MITIGATIONS[@]}"; do printf "  ${GREEN}✓${RESET} %s\n" "$m"; done
fi

# ─────────────────────────────────────────────────────────────────────────────
#  §10  REMEDIATION GUIDE
# ─────────────────────────────────────────────────────────────────────────────
header "Remediation"

cat <<REMED
  ┌─ [1] UPDATE THE KERNEL (definitive fix) ─────────────────────────────────┐
  │  RHEL / AlmaLinux 8:  yum update kernel   # target: ≥ 4.18.0-553.121.1   │
  │  RHEL / AlmaLinux 9:  dnf update kernel   # target: ≥ 5.14.0-611.49.2    │
  │  RHEL / AlmaLinux 10: dnf update kernel   # target: ≥ 6.12.0-124.52.2    │
  │  Ubuntu / Debian:     apt-get update && apt-get dist-upgrade              │
  │  SUSE:                zypper update kernel-default                         │
  │  Arch:                pacman -Syu linux                                    │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [2] WORKAROUND — loadable module only (NOT built-in) ───────────────────┐
  │  echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf│
  │  rmmod algif_aead 2>/dev/null                                              │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [3] WORKAROUND — built-in module (CONFIG_CRYPTO_USER_API_AEAD=y) ───────┐
  │  grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"   │
  │  # or manually edit /etc/default/grub then run grub2-mkconfig             │
  │  # REBOOT required!                                                        │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [4] LIVE PATCH (no reboot) ─────────────────────────────────────────────┐
  │  kcarectl --update                                                         │
  │  kcarectl --info | grep CVE-2026-31431                                     │
  └───────────────────────────────────────────────────────────────────────────┘

  ┌─ [5] VERIFY MITIGATION AFTER REBOOT ─────────────────────────────────────┐
  │  grep initcall_blacklist /proc/cmdline                                     │
  │  cat /sys/module/algif_aead/parameters/ 2>/dev/null || echo "not loaded"  │
  └───────────────────────────────────────────────────────────────────────────┘

  References:
    https://copy.fail
    https://github.com/theori-io/copy-fail-CVE-2026-31431
    https://cert.europa.eu/publications/security-advisories/2026-005/

REMED

printf "  ${DIM}audit_copyfail.sh v1.0.0 — github.com/Quaerendir/copyfail-audit${RESET}\n\n"

# ── Exit code ──
case "$VULN_STATE" in
    SAFE)      exit 0 ;;
    MITIGATED) exit 2 ;;
    VULNERABLE)exit 1 ;;
    *)         exit 3 ;;
esac
