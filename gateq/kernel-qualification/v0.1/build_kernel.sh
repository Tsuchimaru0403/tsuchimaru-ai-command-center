#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:?source directory required}"
OUT_DIR="${2:?output directory required}"
JOBS="${JOBS:-2}"

cd "$SRC_DIR"
test -f Microsoft/config-wsl
test -x scripts/config

if command -v ccache >/dev/null 2>&1; then
  echo "ccache must be absent from the qualified toolchain" >&2
  exit 64
fi
test "${CCACHE_DISABLE:-}" = "1"

cp Microsoft/config-wsl .config

# Preserve the Microsoft WSL feature surface while making the final image
# module-free: promote every existing tristate module selection to built-in
# before CONFIG_MODULES is disabled. olddefconfig remains authoritative.
sed -i -E 's/^(CONFIG_[A-Za-z0-9_]+)=m$/\1=y/' .config

scripts/config --disable SECURITY
scripts/config --disable MODULES
scripts/config --disable BPF_SYSCALL
scripts/config --disable KPROBES
scripts/config --disable LIVEPATCH
scripts/config --disable KEXEC
scripts/config --disable KEXEC_FILE
scripts/config --enable EXT4_FS
scripts/config --enable EXT4_FS_POSIX_ACL
scripts/config --enable IKCONFIG
scripts/config --enable IKCONFIG_PROC
scripts/config --enable PROC_FS
scripts/config --enable SYSFS
scripts/config --disable LOCALVERSION_AUTO
scripts/config --enable RANDSTRUCT_NONE
scripts/config --disable RANDSTRUCT_FULL
scripts/config --disable RANDSTRUCT_PERFORMANCE
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str SYSTEM_REVOCATION_KEYS ""
scripts/config --set-str BUILD_SALT ""

make olddefconfig

mkdir -p "$OUT_DIR"
: > "$OUT_DIR/KCONFIG_EFFECTIVE_N_ABSENT.txt"

assert_y() {
  grep -qx "$1=y" .config || {
    echo "required y assertion failed: $1" >&2
    exit 64
  }
}
assert_n() {
  # In a resolved Kconfig, a disabled visible symbol is normally emitted as
  # "# CONFIG_FOO is not set". If its dependencies make it invisible, the
  # symbol may be absent entirely; that is also an effective n. Any concrete
  # assignment is therefore a fail-closed violation.
  if grep -q "^$1=" .config; then
    echo "required n assertion failed: $1 has a concrete assignment" >&2
    grep "^$1=" .config >&2 || true
    exit 64
  fi
  if grep -qx "# $1 is not set" .config; then
    return 0
  fi
  if grep -q "^# $1 is not set$" .config; then
    return 0
  fi
  printf '%s\n' "$1=ABSENT_EFFECTIVE_N" >> "$OUT_DIR/KCONFIG_EFFECTIVE_N_ABSENT.txt"
}
assert_empty_string_or_absent() {
  if grep -q "^$1=" .config; then
    grep -qx "$1=\"\"" .config || {
      echo "required empty deterministic string failed: $1" >&2
      exit 64
    }
  fi
}

assert_n CONFIG_SECURITY
assert_n CONFIG_MODULES
assert_n CONFIG_BPF_SYSCALL
assert_n CONFIG_KPROBES
assert_n CONFIG_LIVEPATCH
assert_n CONFIG_KEXEC
assert_n CONFIG_KEXEC_FILE
assert_y CONFIG_EXT4_FS
assert_y CONFIG_EXT4_FS_POSIX_ACL
assert_y CONFIG_IKCONFIG
assert_y CONFIG_IKCONFIG_PROC
assert_y CONFIG_PROC_FS
assert_y CONFIG_SYSFS
assert_n CONFIG_LOCALVERSION_AUTO
assert_y CONFIG_RANDSTRUCT_NONE
assert_n CONFIG_RANDSTRUCT_FULL
assert_n CONFIG_RANDSTRUCT_PERFORMANCE
assert_empty_string_or_absent CONFIG_SYSTEM_TRUSTED_KEYS
assert_empty_string_or_absent CONFIG_SYSTEM_REVOCATION_KEYS
assert_empty_string_or_absent CONFIG_BUILD_SALT

if grep -Eq '^CONFIG_[A-Za-z0-9_]+=m$' .config; then
  echo "module selection remains in final config" >&2
  grep -E '^CONFIG_[A-Za-z0-9_]+=m$' .config >&2 || true
  exit 64
fi

cp .config "$OUT_DIR/final.config"

{
  printf 'SOURCE_DATE_EPOCH=%s\n' "${SOURCE_DATE_EPOCH:-}"
  printf 'KBUILD_BUILD_TIMESTAMP=%s\n' "${KBUILD_BUILD_TIMESTAMP:-}"
  printf 'KBUILD_BUILD_USER=%s\n' "${KBUILD_BUILD_USER:-}"
  printf 'KBUILD_BUILD_HOST=%s\n' "${KBUILD_BUILD_HOST:-}"
  printf 'KBUILD_BUILD_VERSION=%s\n' "${KBUILD_BUILD_VERSION:-}"
  printf 'KBUILD_ABS_SRCTREE=%s\n' "${KBUILD_ABS_SRCTREE:-}"
  printf 'CCACHE_DISABLE=%s\n' "${CCACHE_DISABLE:-}"
  printf 'KCFLAGS=%s\n' "${KCFLAGS:-}"
  printf 'KCPPFLAGS=%s\n' "${KCPPFLAGS:-}"
  printf 'HOSTCFLAGS=%s\n' "${HOSTCFLAGS:-}"
  printf 'HOSTCXXFLAGS=%s\n' "${HOSTCXXFLAGS:-}"
  printf 'LANG=%s\n' "${LANG:-}"
  printf 'LC_ALL=%s\n' "${LC_ALL:-}"
  printf 'TZ=%s\n' "${TZ:-}"
} > "$OUT_DIR/BUILD_ENV_EFFECTIVE.txt"

{
  gcc --version | head -1
  ld --version | head -1
  as --version | head -1
  objcopy --version | head -1
  make --version | head -1
  pahole --version | head -1
  bc --version | head -1
  bison --version | head -1
  flex --version | head -1
} > "$OUT_DIR/TOOL_VERSIONS_KERNEL_BUILD.txt"

make -j"$JOBS" bzImage vmlinux

test -s arch/x86/boot/bzImage
test -s vmlinux
test -s System.map

cp arch/x86/boot/bzImage "$OUT_DIR/bzImage"
cp vmlinux "$OUT_DIR/vmlinux"
cp System.map "$OUT_DIR/System.map"
cp .config "$OUT_DIR/final.config"

build_id="$(readelf -n vmlinux | awk '/Build ID:/ {print $3; exit}')"
test -n "$build_id"
printf '%s\n' "$build_id" > "$OUT_DIR/GNU_BUILD_ID.txt"
make -s kernelrelease > "$OUT_DIR/KERNEL_RELEASE.txt"

if test -f include/generated/compile.h; then
  grep '^#define UTS_VERSION ' include/generated/compile.h > "$OUT_DIR/UTS_VERSION.txt" || true
  grep '^#define LINUX_COMPILE_BY ' include/generated/compile.h > "$OUT_DIR/LINUX_COMPILE_BY.txt" || true
  grep '^#define LINUX_COMPILE_HOST ' include/generated/compile.h > "$OUT_DIR/LINUX_COMPILE_HOST.txt" || true
fi
if test -f include/generated/utsrelease.h; then
  cp include/generated/utsrelease.h "$OUT_DIR/UTSRELEASE.h"
fi

(
  cd "$OUT_DIR"
  sha256sum bzImage vmlinux System.map final.config GNU_BUILD_ID.txt KERNEL_RELEASE.txt     BUILD_ENV_EFFECTIVE.txt TOOL_VERSIONS_KERNEL_BUILD.txt > OUTPUTS.sha256
)
