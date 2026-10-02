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
  if grep -q "^$1=" .config; then
    echo "required n assertion failed: $1 has a concrete assignment" >&2
    grep "^$1=" .config >&2 || true
    exit 64
  fi
  if grep -qx "# $1 is not set" .config; then
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
  strings --version | head -1
  make --version | head -1
  pahole --version | head -1
  bc --version | head -1
  bison --version | head -1
  flex --version | head -1
  python3 --version
} > "$OUT_DIR/TOOL_VERSIONS_KERNEL_BUILD.txt"

make -j"$JOBS" bzImage vmlinux

test -s arch/x86/boot/bzImage
test -s vmlinux
test -s System.map
test -s include/generated/compile.h
test -s include/generated/utsrelease.h
test -s include/generated/utsversion.h

cp arch/x86/boot/bzImage "$OUT_DIR/bzImage"
cp vmlinux "$OUT_DIR/vmlinux"
cp System.map "$OUT_DIR/System.map"
cp .config "$OUT_DIR/final.config"
cp include/generated/compile.h "$OUT_DIR/compile.h"
cp include/generated/utsrelease.h "$OUT_DIR/utsrelease.h"
cp include/generated/utsversion.h "$OUT_DIR/utsversion.h"

build_id="$(readelf -n vmlinux | awk '/Build ID:/ {print $3; exit}')"
test -n "$build_id"
printf '%s\n' "$build_id" > "$OUT_DIR/GNU_BUILD_ID.txt"

make -s kernelrelease > "$OUT_DIR/KERNEL_RELEASE.txt"
test -s "$OUT_DIR/KERNEL_RELEASE.txt"

python3 - "$OUT_DIR" <<'PY'
import ast
import hashlib
import json
import pathlib
import re
import sys

src = pathlib.Path.cwd()
out = pathlib.Path(sys.argv[1])

def c_string(path: pathlib.Path, name: str) -> str:
    text = path.read_text()
    pattern = rf'^\s*#define\s+{re.escape(name)}\s+("(?:\\.|[^"\\])*")\s*$'
    m = re.search(pattern, text, re.MULTILINE)
    if not m:
        raise SystemExit(f'missing string macro {name} in {path}')
    value = ast.literal_eval(m.group(1))
    if not isinstance(value, str) or not value:
        raise SystemExit(f'empty/invalid string macro {name} in {path}')
    return value

release = (out / 'KERNEL_RELEASE.txt').read_text().strip()
if not release:
    raise SystemExit('empty kernel release')

uts_release = c_string(src / 'include/generated/utsrelease.h', 'UTS_RELEASE')
uts_version = c_string(src / 'include/generated/utsversion.h', 'UTS_VERSION')
uts_machine = c_string(src / 'include/generated/compile.h', 'UTS_MACHINE')
compile_by = c_string(src / 'include/generated/compile.h', 'LINUX_COMPILE_BY')
compile_host = c_string(src / 'include/generated/compile.h', 'LINUX_COMPILE_HOST')
compiler = c_string(src / 'include/generated/compile.h', 'LINUX_COMPILER')
uts_sysname = c_string(src / 'include/linux/uts.h', 'UTS_SYSNAME')

if release != uts_release:
    raise SystemExit(f'kernelrelease/UTS_RELEASE mismatch: {release!r} != {uts_release!r}')
if uts_sysname != 'Linux':
    raise SystemExit(f'unexpected UTS_SYSNAME: {uts_sysname!r}')

expected_proc_version = (
    f'{uts_sysname} version {release} '
    f'({compile_by}@{compile_host}) ({compiler}) {uts_version}\n'
)

(out / 'UTS_VERSION.txt').write_text(uts_version + '\n')
(out / 'EXPECTED_UNAME_R.txt').write_text(release + '\n')
(out / 'EXPECTED_UNAME_V.txt').write_text(uts_version + '\n')
(out / 'EXPECTED_UNAME_M.txt').write_text(uts_machine + '\n')
(out / 'EXPECTED_PROC_VERSION.txt').write_text(expected_proc_version)
(out / 'LINUX_COMPILE_BY.txt').write_text(compile_by + '\n')
(out / 'LINUX_COMPILE_HOST.txt').write_text(compile_host + '\n')
(out / 'LINUX_COMPILER.txt').write_text(compiler + '\n')

corroboration = {
    'schema': 'KERNEL_VERSION_CORROBORATION_V1',
    'expected_uname_r': release,
    'expected_uname_v': uts_version,
    'expected_uname_m': uts_machine,
    'expected_proc_version': expected_proc_version,
    'expected_proc_version_sha256': hashlib.sha256(expected_proc_version.encode()).hexdigest(),
    'linux_compile_by': compile_by,
    'linux_compile_host': compile_host,
    'linux_compiler': compiler,
    'uts_sysname': uts_sysname,
    'sources': {
        'uname_r': 'make -s kernelrelease + include/generated/utsrelease.h',
        'uname_v': 'include/generated/utsversion.h',
        'uname_m_compile_identity': 'include/generated/compile.h',
        'proc_version_format': 'init/version.c::linux_proc_banner + fs/proc/version.c',
        'binary_banner_format': 'init/version-timestamp.c::linux_banner'
    }
}
(out / 'VERSION_CORROBORATION_V1.json').write_text(
    json.dumps(corroboration, indent=2, sort_keys=True) + '\n'
)
PY

expected_proc_line="$(python3 - "$OUT_DIR/EXPECTED_PROC_VERSION.txt" <<'PY'
import pathlib, sys
s=pathlib.Path(sys.argv[1]).read_text()
if not s.endswith('\n') or '\n' in s[:-1]:
    raise SystemExit('EXPECTED_PROC_VERSION.txt must be exactly one line plus newline')
print(s[:-1], end='')
PY
)"
test -n "$expected_proc_line"

match_count="$(strings -a vmlinux | grep -Fxc -- "$expected_proc_line" || true)"
if test "$match_count" -lt 1; then
  echo "expected Linux version banner not found in vmlinux" >&2
  exit 64
fi
printf '%s\n' "$expected_proc_line" > "$OUT_DIR/VMLINUX_PROC_VERSION_STRING.txt"

(
  cd "$OUT_DIR"
  sha256sum     bzImage vmlinux System.map final.config     GNU_BUILD_ID.txt KERNEL_RELEASE.txt     UTS_VERSION.txt EXPECTED_UNAME_R.txt EXPECTED_UNAME_V.txt EXPECTED_UNAME_M.txt     EXPECTED_PROC_VERSION.txt VMLINUX_PROC_VERSION_STRING.txt VERSION_CORROBORATION_V1.json     compile.h utsrelease.h utsversion.h     LINUX_COMPILE_BY.txt LINUX_COMPILE_HOST.txt LINUX_COMPILER.txt     BUILD_ENV_EFFECTIVE.txt TOOL_VERSIONS_KERNEL_BUILD.txt     KCONFIG_EFFECTIVE_N_ABSENT.txt > OUTPUTS.sha256
)
