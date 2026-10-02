#!/usr/bin/env bash
set -euo pipefail
TASK_ROOT="$(cd "$(dirname "$0")" && pwd)"
ZIP_IN="$TASK_ROOT/input/gateq-windows-path-qualifier-v0.4.zip"
EXPECTED=ee28c59ef131b994841f5884dac6cdcdc55625b95998893b50db547f34e2a092
test "$(sha256sum "$ZIP_IN" | awk '{print $1}')" = "$EXPECTED"
ROOT="${RUNNER_TEMP}/gateq-v05"
rm -rf "$ROOT"
mkdir -p "$ROOT/unpack"
python3 - "$ZIP_IN" "$ROOT/unpack" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    if z.testzip() is not None or len(z.infolist()) != 44: raise SystemExit('canonical ZIP integrity/entry check failed')
    z.extractall(sys.argv[2])
PY
BUNDLE="$ROOT/unpack/gateq_windows_path_qualifier_v04"
python3 - "$BUNDLE" <<'PY'
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]); src=r/'src/windows_path_chain_qualifier.c'
source_v04=src.read_text()
s=source_v04
ev=r/'evidence'; ev.mkdir(exist_ok=True)
(ev/'RUNTIME_SOURCE_V04.c').write_text(source_v04)

old='static void revalidate(path_chain*c){u32 i;chain_node now;for(i=0;i<c->count;i++){inspect(c->nodes[i].h,c->nodes[i].is_dir,&now,c->nodes[i].component);if(!same_id(&now.id,&c->nodes[i].id))stop("FILE_ID_DRIFT",50);volume_check(c->nodes[i].h,c,&now.id);}}'
new='static void revalidate(path_chain*c){u32 i;chain_node now;for(i=0;i<c->count;i++){inspect(c->nodes[i].h,c->nodes[i].is_dir,&now,c->nodes[i].component);if(!same_id(&now.id,&c->nodes[i].id))stop("FILE_ID_DRIFT",50);if(now.tag.FileAttributes!=c->nodes[i].tag.FileAttributes)stop("FILE_ATTRIBUTES_DRIFT",51);if(now.tag.ReparseTag!=c->nodes[i].tag.ReparseTag)stop("REPARSE_TAG_DRIFT",52);volume_check(c->nodes[i].h,c,&now.id);}}'
if s.count(old)!=1: raise SystemExit('F-09 source anchor mismatch; fail closed')
src.write_text(s.replace(old,new))
import difflib
source_v05=src.read_text()
diff=''.join(difflib.unified_diff(source_v04.splitlines(True),source_v05.splitlines(True),fromfile='v0.4/src/windows_path_chain_qualifier.c',tofile='v0.5/src/windows_path_chain_qualifier.c'))
(ev/'RUNTIME_SOURCE_V04_TO_V05.diff').write_text(diff)
if source_v05.replace(new,old) != source_v04: raise SystemExit('runtime source differs beyond F-09 replacement')

binding=r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json'; b=json.loads(binding.read_text())
b['revision']='v0.5'; b['status']='QUALIFIED_REMEDIATED_CANDIDATE_PENDING_FRESH_REAUDIT'
b['prior_bundle_sha256']='ee28c59ef131b994841f5884dac6cdcdc55625b95998893b50db547f34e2a092'
b['clang_path']='/usr/bin/clang'; b['lld_link_path']='/usr/bin/lld-link'
if not isinstance(b.get('toolchain'),dict): raise SystemExit('binding nested toolchain object missing')
b['toolchain']['clang_path']='/usr/bin/clang'
b['toolchain']['lld_link_path']='/usr/bin/lld-link'

b['clang_version']='clang version 17.0.0 (https://github.com/swiftlang/llvm-project.git 10999b6d034fe318f3d56c83bddb6572593a8bb0)'
b['lld_link_version']='LLD 17.0.0 (https://github.com/swiftlang/llvm-project.git 10999b6d034fe318f3d56c83bddb6572593a8bb0)'
b['toolchain_provenance']={'image':'swift:6.2.1-jammy@sha256:6e33c70a59180c9b518f67728538312975cb3891177d20215cd2e31bdfe70791','platform':'linux/amd64','discovery':'Existing /usr/bin/clang and /usr/bin/lld-link discovered in the pinned official Swift image; no swiftlang/llvm-project source build was performed.'}
b['source_sha256']=hashlib.sha256(src.read_bytes()).hexdigest()
b['revalidation_policy']={'file_attributes':'exact equality: saved node.tag.FileAttributes == current inspect tag.FileAttributes; mismatch stops FILE_ATTRIBUTES_DRIFT','reparse_tag':'exact equality: saved node.tag.ReparseTag == current inspect tag.ReparseTag; mismatch stops REPARSE_TAG_DRIFT','fail_closed':True}
b['prior_audit']={'revision':'v0.4','result':'FAIL','critical':0,'major':1,'minor':0,'note':1,'finding_ids':['F-09']}
binding.write_text(json.dumps(b,indent=2,ensure_ascii=False)+'\n')
matrix=r/'evidence/REMEDIATION_MATRIX.md'; m=matrix.read_text(encoding='utf-8')
m=m.replace('F-09','F-10').replace('v0.4 — v0.3 Fresh Audit Remediation Matrix','v0.5 — F-10 evidence-only remediation matrix')
m += '\n| F-09 MAJOR — attribute/tag drift | `revalidate()` compares saved and current `FileAttributes` and `ReparseTag` individually using exact equality; mismatches stop as `FILE_ATTRIBUTES_DRIFT` / `REPARSE_TAG_DRIFT`. | REMEDIATED CANDIDATE / pending Fresh Re-Audit |\n\nF-01–F-08 remain as recorded in v0.4. No Windows host execution, Host Activation, Gate A, or Runtime was performed.\n'
m=m.replace('F-09','F-10').replace('F-08 remain','F-08 remain')
m=m.replace('v0.4 — v0.3 Fresh Audit Remediation Matrix','v0.5 — F-10 evidence-only remediation matrix')
m=m.replace('Prior Fresh Static Audit result for v0.3: FAIL — CRITICAL 0 / MAJOR 4 / MINOR 2 / NOTE 2.','Prior Fresh Static Audit result for v0.4: FAIL — CRITICAL 0 / MAJOR 1 / MINOR 0 / NOTE 1 (F-10 only).')
matrix.write_text(m,encoding='utf-8')
compat_note="## Evidence-only build compatibility adjustments\n\nThe v0.5 remediation build carries two build/evidence compatibility adjustments from v0.4: `FILE_TOOL` changes from `/usr/bin/file` to `/usr/bin/objdump` (invoked with `-f` solely to record PE file-format evidence), and the import-evidence parser accepts the decimal address-column form emitted by the pinned image's objdump. These changes affect evidence collection/parsing only; they do not change F-01–F-09 implementation source, compiler inputs/options, linker inputs/options, or runtime behavior. The A/B artifacts are freshly rebuilt from identical source and their normalized COFF, PE, and import libraries are compared byte-for-byte. Independent audit should verify this scope from the bundled build scripts and logs."
def append_once(path, marker, text):
    data=path.read_text(encoding='utf-8')
    if marker not in data:
        path.write_text(data.rstrip()+'\n\n'+text+'\n',encoding='utf-8')
append_once(matrix, 'Evidence-only build compatibility adjustments', compat_note)
f10='## F-10 evidence-only remediation\n\nAll binding toolchain paths, including nested `toolchain.clang_path` and `toolchain.lld_link_path`, identify the actual tools: `/usr/bin/clang` and `/usr/bin/lld-link`. Current facts are the pinned image `swift:6.2.1-jammy@sha256:6e33c70a59180c9b518f67728538312975cb3891177d20215cd2e31bdfe70791`, platform `linux/amd64`, exact Clang/LLD 17.0.0 strings, and Python 3.13.5. F-10 changes evidence only; v0.5 runtime source is unchanged. Fresh independent re-audit remains pending.\n'
append_once(matrix, 'F-10 evidence-only remediation', f10)

append_once(r/'README_JA.md', 'Evidence-only build compatibility adjustments', compat_note)
append_once(r/'README_JA.md', 'F-10 evidence-only remediation', f10)

(r/'evidence/BUILD_COMPATIBILITY_NOTE.md').write_text(compat_note+'\n',encoding='utf-8')
readme=r/'README_JA.md'; d=readme.read_text(encoding='utf-8').replace('Gate Q Windows Path Qualifier v0.4','Gate Q Windows Path Qualifier v0.5').replace('**Fresh Re-Audit待ちのread-only candidateです。Windowsホストではまだ実行しないでください。**','**QUALIFIED/REMEDIATED CANDIDATE PENDING FRESH RE-AUDIT。Windowsホストではまだ実行しないでください。**')
d+='\n## v0.5 F-09 remediation\n\n`revalidate()` compares saved `FileAttributes` and `ReparseTag` independently by exact equality. Drift fails closed with `FILE_ATTRIBUTES_DRIFT` or `REPARSE_TAG_DRIFT`. F-01–F-08 remain unchanged. Fresh independent audit is required; this bundle does not authorize Windows execution, Host Activation, Gate A, or Runtime.\n'
d=d.replace('v0.5 F-09 remediation','v0.5 F-10 evidence-only remediation')
readme.write_text(d,encoding='utf-8')
PY
export PATH="/usr/bin:$PATH"
mkdir -p /opt/pyvenv
/opt/hostedtoolcache/Python/3.13.5/x64/bin/python3 -m venv /opt/pyvenv
ln -sf /opt/pyvenv/bin/python3 /opt/pyvenv/python3
export PYTHON=/opt/pyvenv/python3
test "$(/usr/bin/clang --version | head -1)" = 'clang version 17.0.0 (https://github.com/swiftlang/llvm-project.git 10999b6d034fe318f3d56c83bddb6572593a8bb0)'
test "$(/usr/bin/lld-link --version | head -1)" = 'LLD 17.0.0 (https://github.com/swiftlang/llvm-project.git 10999b6d034fe318f3d56c83bddb6572593a8bb0)'
test "$(/opt/pyvenv/python3 --version 2>&1)" = 'Python 3.13.5'
export GITHUB_HEAD_SHA="${GITHUB_SHA:?}" GITHUB_RUN_ID="${GITHUB_RUN_ID:?}" GITHUB_JOB="${GITHUB_JOB:?}" GITHUB_JOB_ID="${GITHUB_JOB_ID:?}"
cp "$GITHUB_WORKSPACE/.github/workflows/gateq-windows-path-qualifier-v05.yml" "$BUNDLE/evidence/WORKFLOW_SNAPSHOT_gateq-windows-path-qualifier-v05.yml"
python3 - "$BUNDLE/evidence/GITHUB_RUN_JOB_ARTIFACT_METADATA_V1.json" <<'PYMETA'
import json,pathlib,sys
data={"snapshot_kind":"previous_run_metadata_reference","run":{"id":37003180168,"head_sha":"73f909368fe1636287ba57484a6afb20e92a9c35","status":"completed","conclusion":"success","workflow_path":".github/workflows/gateq-windows-path-qualifier-v05.yml"},"job":{"id":110825476969,"run_id":37003180168,"head_sha":"73f909368fe1636287ba57484a6afb20e92a9c35","status":"completed","conclusion":"success"},"artifact":{"id":11224309094,"name":"gateq-windows-path-qualifier-v0.5","size_in_bytes":48327,"digest":"sha256:e5e4f87a68b17a126a69fdb6036e78f0fdce53dafccad1becc9b043e56d46a13"},"note":"This is prior-run metadata; current-run metadata is recorded in the post-upload workflow summary."}
pathlib.Path(sys.argv[1]).write_text(json.dumps(data,indent=2)+"\\n")
PYMETA

python3 - "$BUNDLE/build/build_windows_path_qualifier.sh" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text()
for old,new in (('/usr/local/swift/usr/bin/clang','/usr/bin/clang'),('/usr/local/swift/usr/bin/lld-link','/usr/bin/lld-link'),('/usr/bin/file','/usr/bin/objdump')):
    if s.count(old)!=1: raise SystemExit(f'expected exactly one tool path anchor: {old}')
    s=s.replace(old,new)
s=s.replace('"$FILE_TOOL" windows_path_chain_qualifier.exe > PE_FILE.txt','"$FILE_TOOL" -f windows_path_chain_qualifier.exe > PE_FILE.txt')
old = r'<none>\s+[0-9a-f]+\s+'
new = r'(?:<none>\s+[0-9a-f]+\s+|[0-9]+\s+)'
if s.count(old)!=1: raise SystemExit('PE import parser anchor mismatch')
s=s.replace(old,new)
p.write_text(s)
PY
printf "=== bundled build scripts (patched verified paths) ===\n" >&2
cat "$BUNDLE/build/rebuild_ab.sh" >&2
cat "$BUNDLE/build/build_windows_path_qualifier.sh" >&2
if ! bash -x "$BUNDLE/build/rebuild_ab.sh"; then
  cat "$BUNDLE/evidence/BUILD_A.log" "$BUNDLE/evidence/BUILD_B.log" 2>/dev/null || true
  cat "$BUNDLE/bin/A/PE_IMPORTS.txt" 2>/dev/null || true
  exit 1
fi
{
  printf 'container_image=%s\n' 'swift:6.2.1-jammy@sha256:6e33c70a59180c9b518f67728538312975cb3891177d20215cd2e31bdfe70791'
  printf 'platform=%s\n' 'linux/amd64'
  printf 'toolchain_discovery=%s\n' 'Existing tools discovered and used in the pinned official Swift image; no swiftlang/llvm-project source build was performed.'
  printf 'clang_path=%s\n' '/usr/bin/clang'
  printf 'clang_version=%s\n' "$(/usr/bin/clang --version | head -1)"
  printf 'lld_link_path=%s\n' '/usr/bin/lld-link'
  printf 'lld_link_version=%s\n' "$(/usr/bin/lld-link --version | head -1)"
  printf 'python_version=%s\n' "$(/opt/pyvenv/python3 --version 2>&1)"
  printf 'upstream_version_commit=%s\n' "${LLVM_SOURCE_COMMIT:?}"
  printf 'version_provenance=%s\n' 'Upstream revision embedded in exact Clang/LLD version strings; not a source-build input.'
  printf 'verification=%s\n' 'Complete Clang and LLD version strings matched the v0.4 expected values before build; mismatch fails closed.'
} > "$BUNDLE/evidence/TOOLCHAIN_INSTALLATION.txt"
python3 - "$BUNDLE" <<'PY'
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]); sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json').read_text()); e=json.loads((r/'evidence/A_B_BUILD_EXECUTION_V1.json').read_text())
b.update(binary_a_sha256=sha(r/'bin/A/windows_path_chain_qualifier.exe'),binary_b_sha256=sha(r/'bin/B/windows_path_chain_qualifier.exe'),normalized_object_a_sha256=sha(r/'bin/A/qualifier.obj'),normalized_object_b_sha256=sha(r/'bin/B/qualifier.obj'),import_kernel32_lib_sha256=sha(r/'bin/A/kernel32.lib'),import_ntdll_lib_sha256=sha(r/'bin/A/ntdll.lib'),object_ab_byte_identical=True,binary_ab_byte_identical=True,build_script_sha256=sha(r/'build/build_windows_path_qualifier.sh'),rebuild_ab_script_sha256=sha(r/'build/rebuild_ab.sh'))
(r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json').write_text(json.dumps(b,indent=2,ensure_ascii=False)+'\n')
e.update(head_commit=__import__('os').environ['GITHUB_HEAD_SHA'],run_id=int(__import__('os').environ['GITHUB_RUN_ID']),job_id=int(__import__('os').environ['GITHUB_JOB_ID']),job_name=__import__('os').environ['GITHUB_JOB'],prior_bundle_sha256='ee28c59ef131b994841f5884dac6cdcdc55625b95998893b50db547f34e2a092',result='REMEDIATED CANDIDATE PENDING FRESH RE-AUDIT',fresh_reaudit='PENDING',normalized_coff_a_sha256=sha(r/'bin/A/qualifier.obj'),normalized_coff_b_sha256=sha(r/'bin/B/qualifier.obj'),pe_a_sha256=sha(r/'bin/A/windows_path_chain_qualifier.exe'),pe_b_sha256=sha(r/'bin/B/windows_path_chain_qualifier.exe'),kernel32_lib_a_sha256=sha(r/'bin/A/kernel32.lib'),kernel32_lib_b_sha256=sha(r/'bin/B/kernel32.lib'),ntdll_lib_a_sha256=sha(r/'bin/A/ntdll.lib'),ntdll_lib_b_sha256=sha(r/'bin/B/ntdll.lib'),normalized_coff_ab_byte_identical=(r/'bin/A/qualifier.obj').read_bytes()==(r/'bin/B/qualifier.obj').read_bytes(),pe_ab_byte_identical=(r/'bin/A/windows_path_chain_qualifier.exe').read_bytes()==(r/'bin/B/windows_path_chain_qualifier.exe').read_bytes(),import_libs_ab_byte_identical=all((r/f'bin/A/{name}').read_bytes()==(r/f'bin/B/{name}').read_bytes() for name in ('kernel32.lib','ntdll.lib')))
(r/'evidence/A_B_BUILD_EXECUTION_V1.json').write_text(json.dumps(e,indent=2,sort_keys=True)+'\n')
for name in ('PE_FILE.txt','PE_IMPORTS.txt','TOOLCHAIN.txt'):
 (r/'evidence'/name).write_bytes((r/'bin/A'/name).read_bytes())
keys={
 'source':sha(r/'src/windows_path_chain_qualifier.c'),
 'build_script':sha(r/'build/build_windows_path_qualifier.sh'),
 'rebuild_ab_script':sha(r/'build/rebuild_ab.sh'),
 'binding':sha(r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json'),
 'PE_A':sha(r/'bin/A/windows_path_chain_qualifier.exe'),
 'PE_B':sha(r/'bin/B/windows_path_chain_qualifier.exe'),
 'normalized_COFF_A':sha(r/'bin/A/qualifier.obj'),
 'normalized_COFF_B':sha(r/'bin/B/qualifier.obj'),
 'kernel32_lib':sha(r/'bin/A/kernel32.lib'),
 'kernel32_lib_B':sha(r/'bin/B/kernel32.lib'),
 'ntdll_lib':sha(r/'bin/A/ntdll.lib'),
 'ntdll_lib_B':sha(r/'bin/B/ntdll.lib'),
}
(r/'evidence/KEY_SHA256.txt').write_text(''.join(f'{k}={v}\n' for k,v in keys.items()))
prompt='''# FRESH INDEPENDENT STATIC RE-AUDIT — GATE Q WINDOWS PATH QUALIFIER v0.5\n\nAudit the attached canonical v0.5 ZIP bytes independently. Recompute the ZIP SHA-256, verify ZIP integrity, entry set, and every payload in FILES.sha256. Do not trust author claims.\n\nBlocking prior finding: F-10 only (MAJOR), caused by inconsistent nested toolchain paths in the previous binding. Verify all current paths agree with actual build facts. Inspect `revalidate()` and verify exact, separate equality comparisons of saved `node.tag.FileAttributes` against current `current.tag.FileAttributes` and saved `node.tag.ReparseTag` against current `current.tag.ReparseTag`; verify mismatch causes fail-closed `FILE_ATTRIBUTES_DRIFT` and `REPARSE_TAG_DRIFT`.\n\nConfirm F-01–F-08 behavior and read-only boundaries remain unchanged from v0.4. Independently inspect source, scripts, build logs, A/B evidence, normalized COFF objects, PE images/imports/headers, binding, toolchain evidence, and all hashes. A/B must be separate fresh outputs and invocations; each lane must independently generate import libraries, compile, normalize only COFF header bytes 4..7 after asserting Machine 0x8664, link with /Brepro, inspect PE, and hash. Compare actual A/B normalized objects and PE bytes. Exact toolchain mismatches must fail closed.\n\nDo not execute the PE on Windows. Do not perform WSL, .wslconfig, Host Activation, Gate A, or Runtime actions. Do not infer Windows Host Qualification or Fresh Re-Audit PASS from build success. Explicitly assess whether the following build/evidence compatibility-only edits alter product behavior: FILE_TOOL changed from /usr/bin/file to /usr/bin/objdump -f for PE metadata, and the import-evidence regex accepts the decimal address-column format from objdump. Verify these are limited to evidence generation/parsing and that implementation source/compiler/linker behavior is unchanged.\n\nInspect the workflow snapshot and run/job/artifact metadata snapshot; distinguish prior-run metadata from current-run metadata. Verify the v0.4-to-v0.5 runtime diff contains only F-09 and that this F-10 cleanup leaves runtime source unchanged. Return an independent finding-by-finding result.\n'''
(r/'FRESH_RE_AUDIT_PROMPT_JA.md').write_text(prompt,encoding='utf-8')
# Verify normalized bytes and hashes before packaging.
assert (r/'bin/A/qualifier.obj').read_bytes()==(r/'bin/B/qualifier.obj').read_bytes()
assert (r/'bin/A/windows_path_chain_qualifier.exe').read_bytes()==(r/'bin/B/windows_path_chain_qualifier.exe').read_bytes()
files=[]
for p in sorted(x for x in r.rglob('*') if x.is_file() and x.name!='FILES.sha256'):
 rel=p.relative_to(r).as_posix(); files.append(f'{sha(p)}  {rel}')
(r/'FILES.sha256').write_text('\n'.join(files)+'\n')
PY
AUDIT="$ROOT/FRESH_RE_AUDIT_PROMPT_JA.md"
cp "$BUNDLE/FRESH_RE_AUDIT_PROMPT_JA.md" "$AUDIT"
python3 - "$BUNDLE" "$ROOT/gateq-windows-path-qualifier-v0.5.zip" <<'PY'
import pathlib,sys,zipfile
r=pathlib.Path(sys.argv[1]); dest=pathlib.Path(sys.argv[2])
with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in sorted(x for x in r.rglob('*') if x.is_file()):
  rel=pathlib.Path('gateq_windows_path_qualifier_v05')/p.relative_to(r)
  i=zipfile.ZipInfo(rel.as_posix(),(2026,1,1,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;i.create_system=3;i.external_attr=(0o100644&0xffff)<<16
  z.writestr(i,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
PY
(cd "$ROOT" && sha256sum gateq-windows-path-qualifier-v0.5.zip > gateq-windows-path-qualifier-v0.5.zip.sha256)
{
  printf 'container_image=%s\n' 'swift:6.2.1-jammy@sha256:6e33c70a59180c9b518f67728538312975cb3891177d20215cd2e31bdfe70791'
  printf 'platform=%s\n' 'linux/amd64'
  printf 'toolchain_discovery=%s\n' 'Existing tools discovered and used in the pinned official Swift image; no swiftlang/llvm-project source build was performed.'
  printf 'clang_path=%s\n' '/usr/bin/clang'
  printf 'clang_version=%s\n' "$(/usr/bin/clang --version | head -1)"
  printf 'lld_link_path=%s\n' '/usr/bin/lld-link'
  printf 'lld_link_version=%s\n' "$(/usr/bin/lld-link --version | head -1)"
  printf 'python_version=%s\n' "$(/opt/pyvenv/python3 --version 2>&1)"
  printf 'upstream_version_commit=%s\n' "${LLVM_SOURCE_COMMIT:?}"
  printf 'version_provenance=%s\n' 'Upstream revision embedded in exact Clang/LLD version strings; not a source-build input.'
  printf 'verification=%s\n' 'Complete Clang and LLD version strings matched the v0.4 expected values before build; mismatch fails closed.'
} > "$BUNDLE/evidence/TOOLCHAIN_INSTALLATION.txt"
python3 - "$BUNDLE" <<'PY'
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]); sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json').read_text()); e=json.loads((r/'evidence/A_B_BUILD_EXECUTION_V1.json').read_text())
b.update(binary_a_sha256=sha(r/'bin/A/windows_path_chain_qualifier.exe'),binary_b_sha256=sha(r/'bin/B/windows_path_chain_qualifier.exe'),normalized_object_a_sha256=sha(r/'bin/A/qualifier.obj'),normalized_object_b_sha256=sha(r/'bin/B/qualifier.obj'),import_kernel32_lib_sha256=sha(r/'bin/A/kernel32.lib'),import_ntdll_lib_sha256=sha(r/'bin/A/ntdll.lib'),object_ab_byte_identical=True,binary_ab_byte_identical=True,build_script_sha256=sha(r/'build/build_windows_path_qualifier.sh'),rebuild_ab_script_sha256=sha(r/'build/rebuild_ab.sh'))
(r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json').write_text(json.dumps(b,indent=2,ensure_ascii=False)+'\n')
e.update(head_commit=__import__('os').environ['GITHUB_HEAD_SHA'],run_id=int(__import__('os').environ['GITHUB_RUN_ID']),job_id=int(__import__('os').environ['GITHUB_JOB_ID']),job_name=__import__('os').environ['GITHUB_JOB'],prior_bundle_sha256='ee28c59ef131b994841f5884dac6cdcdc55625b95998893b50db547f34e2a092',result='REMEDIATED CANDIDATE PENDING FRESH RE-AUDIT',fresh_reaudit='PENDING',normalized_coff_a_sha256=sha(r/'bin/A/qualifier.obj'),normalized_coff_b_sha256=sha(r/'bin/B/qualifier.obj'),pe_a_sha256=sha(r/'bin/A/windows_path_chain_qualifier.exe'),pe_b_sha256=sha(r/'bin/B/windows_path_chain_qualifier.exe'),kernel32_lib_a_sha256=sha(r/'bin/A/kernel32.lib'),kernel32_lib_b_sha256=sha(r/'bin/B/kernel32.lib'),ntdll_lib_a_sha256=sha(r/'bin/A/ntdll.lib'),ntdll_lib_b_sha256=sha(r/'bin/B/ntdll.lib'),normalized_coff_ab_byte_identical=(r/'bin/A/qualifier.obj').read_bytes()==(r/'bin/B/qualifier.obj').read_bytes(),pe_ab_byte_identical=(r/'bin/A/windows_path_chain_qualifier.exe').read_bytes()==(r/'bin/B/windows_path_chain_qualifier.exe').read_bytes(),import_libs_ab_byte_identical=all((r/f'bin/A/{name}').read_bytes()==(r/f'bin/B/{name}').read_bytes() for name in ('kernel32.lib','ntdll.lib')))
(r/'evidence/A_B_BUILD_EXECUTION_V1.json').write_text(json.dumps(e,indent=2,sort_keys=True)+'\n')
for name in ('PE_FILE.txt','PE_IMPORTS.txt','TOOLCHAIN.txt'):
 (r/'evidence'/name).write_bytes((r/'bin/A'/name).read_bytes())
keys={
 'source':sha(r/'src/windows_path_chain_qualifier.c'),
 'build_script':sha(r/'build/build_windows_path_qualifier.sh'),
 'rebuild_ab_script':sha(r/'build/rebuild_ab.sh'),
 'binding':sha(r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json'),
 'PE_A':sha(r/'bin/A/windows_path_chain_qualifier.exe'),
 'PE_B':sha(r/'bin/B/windows_path_chain_qualifier.exe'),
 'normalized_COFF_A':sha(r/'bin/A/qualifier.obj'),
 'normalized_COFF_B':sha(r/'bin/B/qualifier.obj'),
 'kernel32_lib':sha(r/'bin/A/kernel32.lib'),
 'kernel32_lib_B':sha(r/'bin/B/kernel32.lib'),
 'ntdll_lib':sha(r/'bin/A/ntdll.lib'),
 'ntdll_lib_B':sha(r/'bin/B/ntdll.lib'),
}
(r/'evidence/KEY_SHA256.txt').write_text(''.join(f'{k}={v}\n' for k,v in keys.items()))
prompt='''# FRESH INDEPENDENT STATIC RE-AUDIT — GATE Q WINDOWS PATH QUALIFIER v0.5\n\nAudit the attached canonical v0.5 ZIP bytes independently. Recompute the ZIP SHA-256, verify ZIP integrity, entry set, and every payload in FILES.sha256. Do not trust author claims.\n\nBlocking prior finding: v0.4 F-09 only (MAJOR). Inspect `revalidate()` and verify exact, separate equality comparisons of saved `node.tag.FileAttributes` against current `current.tag.FileAttributes` and saved `node.tag.ReparseTag` against current `current.tag.ReparseTag`; verify mismatch causes fail-closed `FILE_ATTRIBUTES_DRIFT` and `REPARSE_TAG_DRIFT`.\n\nConfirm F-01–F-08 behavior and read-only boundaries remain unchanged from v0.4. Independently inspect source, scripts, build logs, A/B evidence, normalized COFF objects, PE images/imports/headers, binding, toolchain evidence, and all hashes. A/B must be separate fresh outputs and invocations; each lane must independently generate import libraries, compile, normalize only COFF header bytes 4..7 after asserting Machine 0x8664, link with /Brepro, inspect PE, and hash. Compare actual A/B normalized objects and PE bytes. Exact toolchain mismatches must fail closed.\n\nDo not execute the PE on Windows. Do not perform WSL, .wslconfig, Host Activation, Gate A, or Runtime actions. Do not infer Windows Host Qualification or Fresh Re-Audit PASS from build success. Explicitly assess whether the following build/evidence compatibility-only edits alter product behavior: FILE_TOOL changed from /usr/bin/file to /usr/bin/objdump -f for PE metadata, and the import-evidence regex accepts the decimal address-column format from objdump. Verify these are limited to evidence generation/parsing and that implementation source/compiler/linker behavior is unchanged.\n\nReturn an independent finding-by-finding result.\n'''
(r/'FRESH_RE_AUDIT_PROMPT_JA.md').write_text(prompt,encoding='utf-8')
# Verify normalized bytes and hashes before packaging.
assert (r/'bin/A/qualifier.obj').read_bytes()==(r/'bin/B/qualifier.obj').read_bytes()
assert (r/'bin/A/windows_path_chain_qualifier.exe').read_bytes()==(r/'bin/B/windows_path_chain_qualifier.exe').read_bytes()
files=[]
for p in sorted(x for x in r.rglob('*') if x.is_file() and x.name!='FILES.sha256'):
 rel=p.relative_to(r).as_posix(); files.append(f'{sha(p)}  {rel}')
(r/'FILES.sha256').write_text('\n'.join(files)+'\n')
PY
AUDIT="$ROOT/FRESH_RE_AUDIT_PROMPT_JA.md"
cp "$BUNDLE/FRESH_RE_AUDIT_PROMPT_JA.md" "$AUDIT"
python3 - "$BUNDLE" "$ROOT/gateq-windows-path-qualifier-v0.5.zip" <<'PY'
import pathlib,sys,zipfile
r=pathlib.Path(sys.argv[1]); dest=pathlib.Path(sys.argv[2])
with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in sorted(x for x in r.rglob('*') if x.is_file()):
  rel=pathlib.Path('gateq_windows_path_qualifier_v05')/p.relative_to(r)
  i=zipfile.ZipInfo(rel.as_posix(),(2026,1,1,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;i.create_system=3;i.external_attr=(0o100644&0xffff)<<16
  z.writestr(i,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
PY
(cd "$ROOT" && sha256sum gateq-windows-path-qualifier-v0.5.zip > gateq-windows-path-qualifier-v0.5.zip.sha256)
{
  printf 'container_image=%s\n' 'swift:6.2.1-jammy@sha256:6e33c70a59180c9b518f67728538312975cb3891177d20215cd2e31bdfe70791'
  printf 'platform=%s\n' 'linux/amd64'
  printf 'toolchain_discovery=%s\n' 'Existing tools discovered and used in the pinned official Swift image; no swiftlang/llvm-project source build was performed.'
  printf 'clang_path=%s\n' '/usr/bin/clang'
  printf 'clang_version=%s\n' "$(/usr/bin/clang --version | head -1)"
  printf 'lld_link_path=%s\n' '/usr/bin/lld-link'
  printf 'lld_link_version=%s\n' "$(/usr/bin/lld-link --version | head -1)"
  printf 'python_version=%s\n' "$(/opt/pyvenv/python3 --version 2>&1)"
  printf 'upstream_version_commit=%s\n' "${LLVM_SOURCE_COMMIT:?}"
  printf 'version_provenance=%s\n' 'Upstream revision embedded in exact Clang/LLD version strings; not a source-build input.'
  printf 'verification=%s\n' 'Complete Clang and LLD version strings matched the v0.4 expected values before build; mismatch fails closed.'
} > "$BUNDLE/evidence/TOOLCHAIN_INSTALLATION.txt"
python3 - "$BUNDLE" <<'PY'
import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]); sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json').read_text()); e=json.loads((r/'evidence/A_B_BUILD_EXECUTION_V1.json').read_text())
b.update(binary_a_sha256=sha(r/'bin/A/windows_path_chain_qualifier.exe'),binary_b_sha256=sha(r/'bin/B/windows_path_chain_qualifier.exe'),normalized_object_a_sha256=sha(r/'bin/A/qualifier.obj'),normalized_object_b_sha256=sha(r/'bin/B/qualifier.obj'),import_kernel32_lib_sha256=sha(r/'bin/A/kernel32.lib'),import_ntdll_lib_sha256=sha(r/'bin/A/ntdll.lib'),object_ab_byte_identical=True,binary_ab_byte_identical=True,build_script_sha256=sha(r/'build/build_windows_path_qualifier.sh'),rebuild_ab_script_sha256=sha(r/'build/rebuild_ab.sh'))
(r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json').write_text(json.dumps(b,indent=2,ensure_ascii=False)+'\n')
e.update(head_commit=__import__('os').environ['GITHUB_HEAD_SHA'],run_id=int(__import__('os').environ['GITHUB_RUN_ID']),job_id=int(__import__('os').environ['GITHUB_JOB_ID']),job_name=__import__('os').environ['GITHUB_JOB'],prior_bundle_sha256='ee28c59ef131b994841f5884dac6cdcdc55625b95998893b50db547f34e2a092',result='REMEDIATED CANDIDATE PENDING FRESH RE-AUDIT',fresh_reaudit='PENDING',normalized_coff_a_sha256=sha(r/'bin/A/qualifier.obj'),normalized_coff_b_sha256=sha(r/'bin/B/qualifier.obj'),pe_a_sha256=sha(r/'bin/A/windows_path_chain_qualifier.exe'),pe_b_sha256=sha(r/'bin/B/windows_path_chain_qualifier.exe'),kernel32_lib_a_sha256=sha(r/'bin/A/kernel32.lib'),kernel32_lib_b_sha256=sha(r/'bin/B/kernel32.lib'),ntdll_lib_a_sha256=sha(r/'bin/A/ntdll.lib'),ntdll_lib_b_sha256=sha(r/'bin/B/ntdll.lib'),normalized_coff_ab_byte_identical=(r/'bin/A/qualifier.obj').read_bytes()==(r/'bin/B/qualifier.obj').read_bytes(),pe_ab_byte_identical=(r/'bin/A/windows_path_chain_qualifier.exe').read_bytes()==(r/'bin/B/windows_path_chain_qualifier.exe').read_bytes(),import_libs_ab_byte_identical=all((r/f'bin/A/{name}').read_bytes()==(r/f'bin/B/{name}').read_bytes() for name in ('kernel32.lib','ntdll.lib')))
(r/'evidence/A_B_BUILD_EXECUTION_V1.json').write_text(json.dumps(e,indent=2,sort_keys=True)+'\n')
for name in ('PE_FILE.txt','PE_IMPORTS.txt','TOOLCHAIN.txt'):
 (r/'evidence'/name).write_bytes((r/'bin/A'/name).read_bytes())
keys={
 'source':sha(r/'src/windows_path_chain_qualifier.c'),
 'build_script':sha(r/'build/build_windows_path_qualifier.sh'),
 'rebuild_ab_script':sha(r/'build/rebuild_ab.sh'),
 'binding':sha(r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json'),
 'PE_A':sha(r/'bin/A/windows_path_chain_qualifier.exe'),
 'PE_B':sha(r/'bin/B/windows_path_chain_qualifier.exe'),
 'normalized_COFF_A':sha(r/'bin/A/qualifier.obj'),
 'normalized_COFF_B':sha(r/'bin/B/qualifier.obj'),
 'kernel32_lib':sha(r/'bin/A/kernel32.lib'),
 'kernel32_lib_B':sha(r/'bin/B/kernel32.lib'),
 'ntdll_lib':sha(r/'bin/A/ntdll.lib'),
 'ntdll_lib_B':sha(r/'bin/B/ntdll.lib'),
}
(r/'evidence/KEY_SHA256.txt').write_text(''.join(f'{k}={v}\n' for k,v in keys.items()))
prompt='''# FRESH INDEPENDENT STATIC RE-AUDIT — GATE Q WINDOWS PATH QUALIFIER v0.5\n\nAudit the attached canonical v0.5 ZIP bytes independently. Recompute the ZIP SHA-256, verify ZIP integrity, entry set, and every payload in FILES.sha256. Do not trust author claims.\n\nBlocking prior finding: v0.4 F-09 only (MAJOR). Inspect `revalidate()` and verify exact, separate equality comparisons of saved `node.tag.FileAttributes` against current `current.tag.FileAttributes` and saved `node.tag.ReparseTag` against current `current.tag.ReparseTag`; verify mismatch causes fail-closed `FILE_ATTRIBUTES_DRIFT` and `REPARSE_TAG_DRIFT`.\n\nConfirm F-01–F-08 behavior and read-only boundaries remain unchanged from v0.4. Independently inspect source, scripts, build logs, A/B evidence, normalized COFF objects, PE images/imports/headers, binding, toolchain evidence, and all hashes. A/B must be separate fresh outputs and invocations; each lane must independently generate import libraries, compile, normalize only COFF header bytes 4..7 after asserting Machine 0x8664, link with /Brepro, inspect PE, and hash. Compare actual A/B normalized objects and PE bytes. Exact toolchain mismatches must fail closed.\n\nDo not execute the PE on Windows. Do not perform WSL, .wslconfig, Host Activation, Gate A, or Runtime actions. Do not infer Windows Host Qualification or Fresh Re-Audit PASS from build success. Explicitly assess whether the following build/evidence compatibility-only edits alter product behavior: FILE_TOOL changed from /usr/bin/file to /usr/bin/objdump -f for PE metadata, and the import-evidence regex accepts the decimal address-column format from objdump. Verify these are limited to evidence generation/parsing and that implementation source/compiler/linker behavior is unchanged.\n\nReturn an independent finding-by-finding result.\n'''
(r/'FRESH_RE_AUDIT_PROMPT_JA.md').write_text(prompt,encoding='utf-8')
# Verify normalized bytes and hashes before packaging.
assert (r/'bin/A/qualifier.obj').read_bytes()==(r/'bin/B/qualifier.obj').read_bytes()
assert (r/'bin/A/windows_path_chain_qualifier.exe').read_bytes()==(r/'bin/B/windows_path_chain_qualifier.exe').read_bytes()
files=[]
for p in sorted(x for x in r.rglob('*') if x.is_file() and x.name!='FILES.sha256'):
 rel=p.relative_to(r).as_posix(); files.append(f'{sha(p)}  {rel}')
(r/'FILES.sha256').write_text('\n'.join(files)+'\n')
PY
AUDIT="$ROOT/FRESH_RE_AUDIT_PROMPT_JA.md"
cp "$BUNDLE/FRESH_RE_AUDIT_PROMPT_JA.md" "$AUDIT"
python3 - "$BUNDLE" "$ROOT/gateq-windows-path-qualifier-v0.5.zip" <<'PY'
import pathlib,sys,zipfile
r=pathlib.Path(sys.argv[1]); dest=pathlib.Path(sys.argv[2])
with zipfile.ZipFile(dest,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in sorted(x for x in r.rglob('*') if x.is_file()):
  rel=pathlib.Path('gateq_windows_path_qualifier_v05')/p.relative_to(r)
  i=zipfile.ZipInfo(rel.as_posix(),(2026,1,1,0,0,0));i.compress_type=zipfile.ZIP_DEFLATED;i.create_system=3;i.external_attr=(0o100644&0xffff)<<16
  z.writestr(i,p.read_bytes(),compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
PY
(cd "$ROOT" && sha256sum gateq-windows-path-qualifier-v0.5.zip > gateq-windows-path-qualifier-v0.5.zip.sha256)
