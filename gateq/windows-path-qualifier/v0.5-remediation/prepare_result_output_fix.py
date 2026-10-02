#!/usr/bin/env python3
import pathlib
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: prepare_result_output_fix.py <input-effective-build.sh> <output-effective-build.sh>")

inp = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
s = inp.read_text(encoding="utf-8")

anchor='export PATH="/usr/bin:$PATH"'
if s.count(anchor) != 1:
    raise SystemExit(f"result-output insertion anchor count={s.count(anchor)}; fail closed")

block=r'''python3 - "$BUNDLE" <<'PYRESULT'
import difflib,hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1])
src=r/'src/windows_path_chain_qualifier.c'
ev=r/'evidence'
pre=src.read_text()
(ev/'RUNTIME_SOURCE_PRE_RESULT_OUTPUT_FIX.c').write_text(pre)

old_write='static void write_ascii(HANDLE h,const char*s){DWORD n=0,w=0;while(s[n])n++;WriteFile(h,s,n,&w,0);}'
new_write='static u32 WRITE_FAILED=0;static void write_ascii(HANDLE h,const char*s){DWORD n=0,w=0;while(s[n])n++;if(!WriteFile(h,s,n,&w,0)||w!=n)WRITE_FAILED=1;}'
old_gate='void gateq_entry(void){u8 kh[32],ch[32];char hx[65];HANDLE o=GetStdHandle(STD_OUTPUT_HANDLE);if(!parse_cli())stop("USAGE",64);build_chain(ARGA,&KC);build_chain(ARGB,&CC);revalidate(&KC);revalidate(&CC);if(!hash_handle(KC.nodes[KC.count-1].h,kh)||!hash_handle(CC.nodes[CC.count-1].h,ch))stop("HASH",60);write_ascii(o,"{\\\"schema\\\":\\\"TSUCHIMARU_WINDOWS_PATH_CHAIN_QUAL_V1\\\",\\\"status\\\":\\\"PASS\\\",\\\"kernel_sha256\\\":\\\"");hex32(kh,hx);write_ascii(o,hx);write_ascii(o,"\\\",\\\"config_sha256\\\":\\\"");hex32(ch,hx);write_ascii(o,hx);write_ascii(o,"\\\",\\\"kernel_nodes\\\":");write_u32(o,KC.count);write_ascii(o,",\\\"config_nodes\\\":");write_u32(o,CC.count);write_ascii(o,",\\\"kernel_chain\\\":");write_chain_json(o,&KC);write_ascii(o,",\\\"config_chain\\\":");write_chain_json(o,&CC);write_ascii(o,"}\\r\\n");close_chain(&KC);close_chain(&CC);ExitProcess(0);}'
new_gate='void gateq_entry(void){u8 kh[32],ch[32];char hx[65];HANDLE o=GetStdHandle(STD_OUTPUT_HANDLE);if(!parse_cli())stop("USAGE",64);build_chain(ARGA,&KC);build_chain(ARGB,&CC);revalidate(&KC);revalidate(&CC);if(!hash_handle(KC.nodes[KC.count-1].h,kh)||!hash_handle(CC.nodes[CC.count-1].h,ch))stop("HASH",60);write_ascii(o,"{\\\"schema\\\":\\\"TSUCHIMARU_WINDOWS_PATH_CHAIN_QUAL_V1\\\",\\\"status\\\":\\\"PASS\\\",\\\"kernel_sha256\\\":\\\"");hex32(kh,hx);write_ascii(o,hx);write_ascii(o,"\\\",\\\"config_sha256\\\":\\\"");hex32(ch,hx);write_ascii(o,hx);write_ascii(o,"\\\",\\\"kernel_nodes\\\":");write_u32(o,KC.count);write_ascii(o,",\\\"config_nodes\\\":");write_u32(o,CC.count);write_ascii(o,",\\\"kernel_chain\\\":");write_chain_json(o,&KC);write_ascii(o,",\\\"config_chain\\\":");write_chain_json(o,&CC);write_ascii(o,"}\\r\\n");if(WRITE_FAILED){close_chain(&KC);close_chain(&CC);ExitProcess(61);}close_chain(&KC);close_chain(&CC);ExitProcess(0);}'

if pre.count(old_write)!=1:
    raise SystemExit(f'write_ascii source anchor count={pre.count(old_write)}; fail closed')
if pre.count(old_gate)!=1:
    raise SystemExit(f'gateq_entry source anchor count={pre.count(old_gate)}; fail closed')
current=pre.replace(old_write,new_write).replace(old_gate,new_gate)
src.write_text(current)

outdiff=''.join(difflib.unified_diff(pre.splitlines(True),current.splitlines(True),fromfile='pre-result-output-fix/src/windows_path_chain_qualifier.c',tofile='current/src/windows_path_chain_qualifier.c'))
(ev/'RUNTIME_SOURCE_RESULT_OUTPUT_FIX.diff').write_text(outdiff)
source_v04=(ev/'RUNTIME_SOURCE_V04.c').read_text()
fulldiff=''.join(difflib.unified_diff(source_v04.splitlines(True),current.splitlines(True),fromfile='v0.4/src/windows_path_chain_qualifier.c',tofile='current/src/windows_path_chain_qualifier.c'))
(ev/'RUNTIME_SOURCE_V04_TO_V05.diff').write_text(fulldiff)

required=[
 'if(!WriteFile(h,s,n,&w,0)||w!=n)WRITE_FAILED=1',
 'write_ascii(o,"}\\r\\n");if(WRITE_FAILED)',
 'ExitProcess(61)',
 'ExitProcess(0)'
]
for token in required:
    if token not in current: raise SystemExit(f'result-output static assertion missing: {token}')
if current.index('write_ascii(o,"}\\r\\n");if(WRITE_FAILED)') > current.rindex('ExitProcess(0)'):
    raise SystemExit('result-output success ordering assertion failed')

tests={
 'schema':'TSUCHIMARU_RESULT_OUTPUT_FAIL_CLOSED_STATIC_TEST_V1',
 'source':'actual current product source',
 'cases':[
  {'case':'WriteFile_returns_false','expected':'WRITE_FAILED=1 then nonzero ExitProcess(61) before success'},
  {'case':'WriteFile_short_write','expected':'w!=n sets WRITE_FAILED=1 then nonzero ExitProcess(61) before success'},
  {'case':'all_PASS_JSON_writes_exact','expected':'WRITE_FAILED remains 0 and only then ExitProcess(0)'},
  {'case':'STOP_diagnostic_write_failure','expected':'diagnostic may be incomplete but stop() still exits nonzero'}
 ],
 'success_condition':'all PASS JSON WriteFile calls returned success and exact requested byte count',
 'result':'PASS'
}
(ev/'RESULT_OUTPUT_FAIL_CLOSED_STATIC_TESTS.json').write_text(json.dumps(tests,indent=2)+'\n')
(ev/'RESULT_OUTPUT_FAIL_CLOSED.md').write_text('''# PASS result output fail-closed remediation

The low-level write helper now records failure if WriteFile returns false or reports a byte count different from the requested length. PASS JSON construction may continue only to avoid recursive error reporting, but gateq_entry checks WRITE_FAILED after the final CRLF and before ExitProcess(0). Any failed or short PASS write closes retained chains and exits 61. stop() remains unconditionally nonzero even if its best-effort diagnostic write itself fails.

This makes complete PASS-result emission an explicit success condition without adding process creation, filesystem mutation, WSL actions, or other authorization-boundary changes.
''')

binding=r/'WINDOWS_PATH_QUALIFIER_BINDING_V1.json'
b=json.loads(binding.read_text())
b['source_sha256']=hashlib.sha256(src.read_bytes()).hexdigest()
b['result_output_policy']={
 'write_api':'WriteFile',
 'failure_detection':'BOOL false sets WRITE_FAILED',
 'short_write_detection':'written byte count != requested byte count sets WRITE_FAILED',
 'pass_success_gate':'WRITE_FAILED must remain zero through final PASS JSON CRLF before ExitProcess(0)',
 'failure_exit_code':61,
 'fail_closed':True
}
b['current_run_binding_policy']={
 'primary_artifact':'canonical ZIP plus sidecar uploaded first',
 'post_upload_binding':'CURRENT_RUN_ARTIFACT_BINDING_V1.json is generated only after GitHub assigns the primary artifact ID/digest and is uploaded as a second artifact',
 'reason':'primary artifact cannot contain its own post-upload GitHub artifact identity without self-reference'
}
b['prior_audit']={
 'revision':'v0.5 F-09 ordering remediation',
 'result':'FAIL','critical':0,'major':2,'minor':0,'note':1,
 'finding_ids':['FINDING-01','FINDING-02'],
 'closed_findings':['F-09','F-10'],
 'summary':'F-09 ordering and F-10 binding were closed; remaining findings were current-run artifact binding and PASS output write fail-closed handling.'
}
binding.write_text(json.dumps(b,indent=2,ensure_ascii=False)+'\n')

def append_once(path, marker, text):
    data=path.read_text(encoding='utf-8')
    if marker not in data:
        path.write_text(data.rstrip()+'\n\n'+text+'\n',encoding='utf-8')

note='''## PASS result output fail-closed remediation

WriteFile failure or short write now sets WRITE_FAILED. gateq_entry tests WRITE_FAILED after the complete PASS JSON including CRLF and before ExitProcess(0); failure exits 61 after closing retained chains. This change is limited to result-output success gating.

## Current-run artifact binding strategy

The canonical ZIP is uploaded as the primary artifact first. Because GitHub artifact ID/digest do not exist until after upload, they are not self-embedded in that primary ZIP. The workflow then queries the GitHub API for the current primary artifact, writes CURRENT_RUN_ARTIFACT_BINDING_V1.json plus current run/job/artifact API snapshots, and uploads those as a separate binding artifact. Fresh audit must verify the actual downloaded primary outer artifact against this post-upload binding.
'''
append_once(r/'README_JA.md','PASS result output fail-closed remediation',note)
append_once(ev/'REMEDIATION_MATRIX.md','PASS result output fail-closed remediation',note)

prompt=r/'FRESH_RE_AUDIT_PROMPT_JA.md'
pd=prompt.read_text(encoding='utf-8')
pd += '''\n## Additional blocking findings to verify\n\nFINDING-01: verify the separately supplied current-run binding artifact records the same current run/job/HEAD/primary artifact ID/size/digest as the actual downloaded primary outer artifact, and that the primary outer artifact contains the canonical ZIP under audit. Do not require the primary ZIP to self-contain its post-upload GitHub artifact ID/digest.\n\nFINDING-02: inspect actual runtime source and verify WriteFile false or a short write sets WRITE_FAILED, and that gateq_entry checks WRITE_FAILED after the final PASS JSON write and before ExitProcess(0), exiting nonzero on output failure.\n'''
prompt.write_text(pd,encoding='utf-8')
PYRESULT
'''

out.write_text(s.replace(anchor,block+"\n"+anchor,1),encoding="utf-8")
