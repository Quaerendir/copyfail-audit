#!/bin/bash
# Regression tests for audit_copyfail.sh.
#
# Each case builds a fixture filesystem tree (os-release, modules.builtin,
# kernel config, modprobe.d, /proc/cmdline) and runs the script against it
# with the mock commands in tests/mock_bin, then asserts the exit code and
# the verdict banner. Exit codes: 0 SAFE, 1 VULNERABLE, 2 MITIGATED.

set -u

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SCRIPT="${HERE}/../audit_copyfail.sh"
MOCK_BIN="${HERE}/mock_bin"

# The script ignores its test hooks for root, so a root run would audit the
# real host instead of the fixtures.
if [[ $EUID -eq 0 ]]; then
    echo "ERROR: run the tests as a non-root user" >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
LAST_OUT=""

# new_root <kernel-release> <os-id> <version-id>: create a fixture tree for
# a typical host: algif_aead shipped as a loadable module (zstd, like
# current Ubuntu), nothing built in, loaded or blacklisted. Print its path.
# Runs in a $( ) subshell, so it cannot keep a counter: mktemp gives every
# case its own tree.
new_root() {
    local r
    r=$(mktemp -d "${TMP}/root.XXXXXX")
    mkdir -p "$r/etc/modprobe.d" "$r/lib/modules/$1" "$r/proc/1" "$r/boot"
    : > "$r/lib/modules/$1/modules.builtin"
    : > "$r/lib/modules/$1/modules.dep"
    mkdir -p "$r/lib/modules/$1/kernel/crypto"
    : > "$r/lib/modules/$1/kernel/crypto/algif_aead.ko.zst"
    : > "$r/proc/cmdline"
    : > "$r/proc/1/environ"
    printf 'NAME="%s"\nID=%s\nVERSION_ID="%s"\n' "$2" "$2" "$3" > "$r/etc/os-release"
    echo "$1" > "$r/.krel"
    echo "$r"
}

# check <name> <root> <exit-code> <verdict> [VAR=value ...]
check() {
    local name=$1 root=$2 want_rc=$3 want_verdict=$4
    shift 4
    local krel out rc verdict ok=1
    krel=$(cat "$root/.krel")
    out=$(env -i HOME="$TMP" PATH=/usr/bin:/bin \
        COPYFAIL_TEST_PATH="$MOCK_BIN" COPYFAIL_TEST_ROOT="$root" \
        MOCK_UNAME_R="$krel" "$@" bash "$SCRIPT" 2>&1)
    rc=$?
    out=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$out")
    LAST_OUT=$out
    verdict=$(grep -oE '(SAFE|MITIGATED|VULNERABLE|UNKNOWN) — ' <<< "$out" | head -1 | cut -d' ' -f1)

    # Guard: a script that bypasses the mocks would report the real kernel.
    if ! grep -q "Kernel     : ${krel}\$" <<< "$out"; then
        echo "  FAIL: $name — mock kernel ${krel} not used"
        ok=0
    fi
    if grep -qE 'syntax error|unbound variable|command not found' <<< "$out"; then
        echo "  FAIL: $name — shell error in output:"
        grep -E 'syntax error|unbound variable|command not found' <<< "$out" | sed 's/^/        /'
        ok=0
    fi
    if [[ "$rc" != "$want_rc" || "$verdict" != "$want_verdict" ]]; then
        echo "  FAIL: $name — expected ${want_verdict}/${want_rc}, got ${verdict:-none}/${rc}"
        ok=0
    fi
    if (( ok )); then
        echo "  PASS: $name"
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
}

# refute <name> <pattern>: the previous check's output must not match.
refute() {
    if grep -qE "$2" <<< "$LAST_OUT"; then
        echo "  FAIL: $1 — output matches '$2'"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: $1"
        PASS=$((PASS + 1))
    fi
}

echo "Kernel version ranges"
r=$(new_root 4.9.0-13-amd64 debian 9);            check "4.9 predates the bug"       "$r" 0 SAFE
r=$(new_root 7.0.0-10-generic ubuntu 24.04);      check "7.0 has the upstream fix"   "$r" 0 SAFE
r=$(new_root 6.18.22 arch rolling);               check "6.18.22 is patched"         "$r" 0 SAFE
r=$(new_root 6.18.21 arch rolling);               check "6.18.21 is vulnerable"      "$r" 1 VULNERABLE
r=$(new_root 6.19.12 arch rolling);               check "6.19.12 is patched"         "$r" 0 SAFE
r=$(new_root 6.19.11 arch rolling);               check "6.19.11 is vulnerable"      "$r" 1 VULNERABLE
r=$(new_root 6.8.0-40-generic ubuntu 24.04);      check "Ubuntu 24.04 on 6.8"        "$r" 1 VULNERABLE
r=$(new_root 6.8.0-40-generic ubuntu 26.04);      check "Ubuntu 26.04 ships the fix" "$r" 0 SAFE

echo "Mitigations"
r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "install algif_aead /bin/false" > "$r/etc/modprobe.d/disable-algif.conf"
check "modprobe.d rule on a loadable module" "$r" 2 MITIGATED

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "kernel/crypto/algif_aead.ko" > "$r/lib/modules/6.8.0-40-generic/modules.builtin"
echo "install algif_aead /bin/false" > "$r/etc/modprobe.d/disable-algif.conf"
check "modprobe.d rule on a built-in module is no mitigation" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "blacklist algif_aead" > "$r/etc/modprobe.d/blacklist-algif.conf"
check "blacklist alone does not stop the by-name autoload" "$r" 1 VULNERABLE
refute "blacklist alone is not listed as a mitigation" 'No blacklist/install rule found'

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
printf 'blacklist algif_aead\ninstall algif_aead /bin/true\n' > "$r/etc/modprobe.d/disable-algif.conf"
check "blacklist plus install /bin/true" "$r" 2 MITIGATED

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "CONFIG_CRYPTO_USER_API_AEAD=y" > "$r/boot/config-6.8.0-40-generic"
echo "install algif_aead /bin/false" > "$r/etc/modprobe.d/disable-algif.conf"
check "built-in detected from kernel config" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "kernel/crypto/algif_aead.ko" > "$r/lib/modules/6.8.0-40-generic/modules.builtin"
echo "BOOT_IMAGE=/vmlinuz ro initcall_blacklist=algif_aead_init" > "$r/proc/cmdline"
check "initcall_blacklist on a built-in module" "$r" 2 MITIGATED

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "install algif_aead /bin/false" > "$r/etc/modprobe.d/disable-algif.conf"
check "modprobe.d rule but module still loaded" "$r" 1 VULNERABLE MOCK_LSMOD=algif_aead

echo "Module availability"
r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "# CONFIG_CRYPTO_USER_API_AEAD is not set" > "$r/boot/config-6.8.0-40-generic"
check "AEAD user API compiled out" "$r" 0 SAFE
refute "compiled-out AEAD drops the upstream-range issue" 'lacks upstream fix'

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
echo "# CONFIG_CRYPTO_USER_API_AEAD is not set" > "$r/boot/config"
check "compiled out per a generic /boot/config is not trusted" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
rm "$r/lib/modules/6.8.0-40-generic/kernel/crypto/algif_aead.ko.zst"
check "algif_aead.ko not installed" "$r" 2 MITIGATED

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
rm -r "$r/lib/modules/6.8.0-40-generic"
check "no module tree (e.g. container) proves nothing" "$r" 1 VULNERABLE

r=$(new_root 6.8.0-40-generic ubuntu 24.04)
check "kernel.modules_disabled=1, not loaded" "$r" 2 MITIGATED \
    MOCK_SYSCTL_kernel_modules_disabled=1
r=$(new_root 6.8.0-40-generic ubuntu 24.04)
check "kernel.modules_disabled=1 but already loaded" "$r" 1 VULNERABLE \
    MOCK_SYSCTL_kernel_modules_disabled=1 MOCK_LSMOD=algif_aead

echo "RHEL vendor kernels"
r=$(new_root 4.18.0-553.121.1.el8_10.x86_64 almalinux 8.10)
check "RHEL 8 at the fixed build" "$r" 0 SAFE
refute "RHEL 8 fixed build drops the upstream-range issue" 'lacks upstream fix'
r=$(new_root 4.18.0-553.120.9.el8_10.x86_64 almalinux 8.10)
check "RHEL 8 one build short" "$r" 1 VULNERABLE
r=$(new_root 5.14.0-611.1.1.el9_7.x86_64 almalinux 9.7)
check "RHEL 9 611.1.1 is below 611.49.2" "$r" 1 VULNERABLE
r=$(new_root 5.14.0-611.49.2.el9_7.x86_64 rocky 9.7)
check "RHEL 9 at the fixed build" "$r" 0 SAFE
r=$(new_root 6.12.0-124.60.1.el10_1.x86_64 almalinux 10.1)
check "RHEL 10 above the fixed build" "$r" 0 SAFE

echo "Hardening"
r=$(new_root 6.8.0-40-generic ubuntu 24.04)
printf 'NAME="Evil$(touch %s/pwned)"\nID=ubuntu\nVERSION_ID="24.04"\n`touch %s/pwned2`\n' \
    "$TMP" "$TMP" > "$r/etc/os-release"
check "os-release is parsed, not executed" "$r" 1 VULNERABLE
if compgen -G "${TMP}/pwned*" > /dev/null; then
    echo "  FAIL: code embedded in os-release was executed"
    FAIL=$((FAIL + 1))
fi

echo
echo "${PASS} passed, ${FAIL} failed."
[[ $FAIL -eq 0 ]]
