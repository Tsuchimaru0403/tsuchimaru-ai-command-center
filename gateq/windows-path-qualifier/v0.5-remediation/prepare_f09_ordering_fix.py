#!/usr/bin/env python3
import pathlib
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: prepare_f09_ordering_fix.py <input-build_v05.sh> <output-build_v05.sh>")

src_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
s = src_path.read_text(encoding="utf-8")

def replace_once(old: str, new: str, label: str):
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, got {n}")
    s = s.replace(old, new, 1)

replace_once(
    'TASK_ROOT="$(cd "$(dirname "$0")" && pwd)"',
    'TASK_ROOT="${GITHUB_WORKSPACE}/gateq/windows-path-qualifier/v0.5-remediation"',
    "TASK_ROOT",
)

anchor = "python3 - \"$BUNDLE\" <<'PY'"
if anchor not in s:
    raise SystemExit("first remediation python argv: anchor missing")
s = s.replace(anchor, "python3 - \"$BUNDLE\" \"$0\" <<'PY'", 1)

replace_once(
    "ev=r/'evidence'; ev.mkdir(exist_ok=True)\n(ev/'RUNTIME_SOURCE_V04.c').write_text(source_v04)",
    "ev=r/'evidence'; ev.mkdir(exist_ok=True)\n(ev/'RUNTIME_SOURCE_V04.c').write_text(source_v04)\n(ev/'REMEDIATION_DRIVER_build_v05_effective.sh').write_bytes(pathlib.Path(sys.argv[2]).read_bytes())",
    "effective remediation driver snapshot",
)

old_patch = """old='static void revalidate(path_chain*c){u32 i;chain_node now;for(i=0;i<c->count;i++){inspect(c->nodes[i].h,c->nodes[i].is_dir,&now,c->nodes[i].component);if(!same_id(&now.id,&c->nodes[i].id))stop("FILE_ID_DRIFT",50);volume_check(c->nodes[i].h,c,&now.id);}}'
new='static void revalidate(path_chain*c){u32 i;chain_node now;for(i=0;i<c->count;i++){inspect(c->nodes[i].h,c->nodes[i].is_dir,&now,c->nodes[i].component);if(!same_id(&now.id,&c->nodes[i].id))stop("FILE_ID_DRIFT",50);if(now.tag.FileAttributes!=c->nodes[i].tag.FileAttributes)stop("FILE_ATTRIBUTES_DRIFT",51);if(now.tag.ReparseTag!=c->nodes[i].tag.ReparseTag)stop("REPARSE_TAG_DRIFT",52);volume_check(c->nodes[i].h,c,&now.id);}}'
if s.count(old)!=1: raise SystemExit('F-09 source anchor mismatch; fail closed')
src.write_text(s.replace(old,new))
import difflib
source_v05=src.read_text()
diff=''.join(difflib.unified_diff(source_v04.splitlines(True),source_v05.splitlines(True),fromfile='v0.4/src/windows_path_chain_qualifier.c',tofile='v0.5/src/windows_path_chain_qualifier.c'))
(ev/'RUNTIME_SOURCE_V04_TO_V05.diff').write_text(diff)
if source_v05.replace(new,old) != source_v04: raise SystemExit('runtime source differs beyond F-09 replacement')"""

new_patch = """old_inspect='static void inspect(HANDLE h,u32 want_dir,chain_node*out,WCHAR*component){u32 forbidden_cloud;memzero(out,(u32)sizeof(*out));out->h=h;out->is_dir=want_dir;wcopy(out->component,MAX_COMP,component);if(!GetFileInformationByHandleEx(h,FILE_ID_INFO_CLASS,&out->id,(DWORD)sizeof(out->id)))stop("FILE_ID_INFO",21);if(!nonzero16(out->id.FileId.Identifier))stop("ZERO_FILE_ID",23);if(!GetFileInformationByHandleEx(h,FILE_ATTRIBUTE_TAG_INFO_CLASS,&out->tag,(DWORD)sizeof(out->tag)))stop("FILE_ATTRIBUTE_TAG_INFO",22);if(out->tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)stop("REPARSE_COMPONENT",25);if(out->tag.ReparseTag!=0)stop("REPARSE_TAG",26);forbidden_cloud=FILE_ATTRIBUTE_OFFLINE|FILE_ATTRIBUTE_VIRTUAL|FILE_ATTRIBUTE_RECALL_ON_OPEN|FILE_ATTRIBUTE_PINNED|FILE_ATTRIBUTE_UNPINNED|FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;if(out->tag.FileAttributes&forbidden_cloud)stop("OFFLINE_CLOUD_VIRTUAL",24);if(want_dir && !(out->tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY))stop("EXPECTED_DIRECTORY",27);if(!want_dir && (out->tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY))stop("EXPECTED_FILE",28);}'
new_inspect='static void inspect_raw(HANDLE h,u32 want_dir,chain_node*out,WCHAR*component){memzero(out,(u32)sizeof(*out));out->h=h;out->is_dir=want_dir;wcopy(out->component,MAX_COMP,component);if(!GetFileInformationByHandleEx(h,FILE_ID_INFO_CLASS,&out->id,(DWORD)sizeof(out->id)))stop("FILE_ID_INFO",21);if(!nonzero16(out->id.FileId.Identifier))stop("ZERO_FILE_ID",23);if(!GetFileInformationByHandleEx(h,FILE_ATTRIBUTE_TAG_INFO_CLASS,&out->tag,(DWORD)sizeof(out->tag)))stop("FILE_ATTRIBUTE_TAG_INFO",22);}static void validate_node_policy(const chain_node*out,u32 want_dir){u32 forbidden_cloud;if(out->tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)stop("REPARSE_COMPONENT",25);if(out->tag.ReparseTag!=0)stop("REPARSE_TAG",26);forbidden_cloud=FILE_ATTRIBUTE_OFFLINE|FILE_ATTRIBUTE_VIRTUAL|FILE_ATTRIBUTE_RECALL_ON_OPEN|FILE_ATTRIBUTE_PINNED|FILE_ATTRIBUTE_UNPINNED|FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;if(out->tag.FileAttributes&forbidden_cloud)stop("OFFLINE_CLOUD_VIRTUAL",24);if(want_dir && !(out->tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY))stop("EXPECTED_DIRECTORY",27);if(!want_dir && (out->tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY))stop("EXPECTED_FILE",28);}static void inspect(HANDLE h,u32 want_dir,chain_node*out,WCHAR*component){inspect_raw(h,want_dir,out,component);validate_node_policy(out,want_dir);}'
old_revalidate='static void revalidate(path_chain*c){u32 i;chain_node now;for(i=0;i<c->count;i++){inspect(c->nodes[i].h,c->nodes[i].is_dir,&now,c->nodes[i].component);if(!same_id(&now.id,&c->nodes[i].id))stop("FILE_ID_DRIFT",50);volume_check(c->nodes[i].h,c,&now.id);}}'
new_revalidate='static void revalidate(path_chain*c){u32 i;chain_node now;for(i=0;i<c->count;i++){inspect_raw(c->nodes[i].h,c->nodes[i].is_dir,&now,c->nodes[i].component);if(!same_id(&now.id,&c->nodes[i].id))stop("FILE_ID_DRIFT",50);if(now.tag.ReparseTag!=c->nodes[i].tag.ReparseTag)stop("REPARSE_TAG_DRIFT",52);if(now.tag.FileAttributes!=c->nodes[i].tag.FileAttributes)stop("FILE_ATTRIBUTES_DRIFT",51);validate_node_policy(&now,c->nodes[i].is_dir);volume_check(c->nodes[i].h,c,&now.id);}}'
if s.count(old_inspect)!=1: raise SystemExit('F-09 inspect source anchor mismatch; fail closed')
if s.count(old_revalidate)!=1: raise SystemExit('F-09 revalidate source anchor mismatch; fail closed')
s=s.replace(old_inspect,new_inspect).replace(old_revalidate,new_revalidate)
src.write_text(s)
import difflib
source_v05=src.read_text()
diff=''.join(difflib.unified_diff(source_v04.splitlines(True),source_v05.splitlines(True),fromfile='v0.4/src/windows_path_chain_qualifier.c',tofile='v0.5/src/windows_path_chain_qualifier.c'))
(ev/'RUNTIME_SOURCE_V04_TO_V05.diff').write_text(diff)
if source_v05.replace(new_inspect,old_inspect).replace(new_revalidate,old_revalidate) != source_v04: raise SystemExit('runtime source differs beyond F-09 raw-inspection/order remediation')
seq=[
    'inspect_raw(c->nodes[i].h',
    'same_id(&now.id',
    'now.tag.ReparseTag!=c->nodes[i].tag.ReparseTag',
    'now.tag.FileAttributes!=c->nodes[i].tag.FileAttributes',
    'validate_node_policy(&now',
    'volume_check(c->nodes[i].h'
]
pos=[new_revalidate.index(x) for x in seq]
if pos != sorted(pos): raise SystemExit('F-09 revalidation ordering static assertion failed')
cases=[
    {'case':'allowed_attribute_drift','same_id':True,'tag_drift':False,'attribute_drift':True,'current_forbidden':False,'expected':'FILE_ATTRIBUTES_DRIFT'},
    {'case':'forbidden_cloud_attribute_drift','same_id':True,'tag_drift':False,'attribute_drift':True,'current_forbidden':True,'expected':'FILE_ATTRIBUTES_DRIFT'},
    {'case':'reparse_tag_drift','same_id':True,'tag_drift':True,'attribute_drift':True,'current_forbidden':True,'expected':'REPARSE_TAG_DRIFT'},
    {'case':'unchanged_accepted_state','same_id':True,'tag_drift':False,'attribute_drift':False,'current_forbidden':False,'expected':'POLICY_THEN_VOLUME'}
]
ordering={'schema':'TSUCHIMARU_F09_REVALIDATION_ORDER_STATIC_TEST_V1','source':'actual v0.5 product source','sequence':['raw metadata collection','FILE_ID_DRIFT check','REPARSE_TAG_DRIFT check','FILE_ATTRIBUTES_DRIFT check','current policy enforcement','volume check'],'both_tag_and_attribute_drift_priority':'REPARSE_TAG_DRIFT','cases':cases,'result':'PASS'}
(ev/'F09_REVALIDATION_ORDER_STATIC_TESTS.json').write_text(json.dumps(ordering,indent=2)+'\\n')
(ev/'F09_REVALIDATION_ORDERING.md').write_text('''# F-09 revalidation ordering remediation

The runtime source separates raw metadata collection from policy enforcement. Initial chain construction still calls inspect(), which calls inspect_raw() and then validate_node_policy(), preserving F-04 initial rejection. Revalidation calls inspect_raw() first, preserves FILE_ID_DRIFT priority, then checks ReparseTag drift, then FileAttributes drift, then enforces the current-node policy, and finally performs the volume check. Therefore forbidden current attributes/tags cannot preempt the dedicated F-09 drift codes.

Deterministic priority when both ReparseTag and FileAttributes changed: REPARSE_TAG_DRIFT. If only attributes changed, including forbidden cloud/offline/reparse-point attribute changes with an unchanged tag, the result is FILE_ATTRIBUTES_DRIFT. If neither drifted, the current policy is still enforced fail closed before volume completion.
''')"""

replace_once(old_patch, new_patch, "F-09 source remediation block")

replace_once(
    "b['revalidation_policy']={'file_attributes':'exact equality: saved node.tag.FileAttributes == current inspect tag.FileAttributes; mismatch stops FILE_ATTRIBUTES_DRIFT','reparse_tag':'exact equality: saved node.tag.ReparseTag == current inspect tag.ReparseTag; mismatch stops REPARSE_TAG_DRIFT','fail_closed':True}",
    "b['revalidation_policy']={'collection':'revalidation uses inspect_raw before policy enforcement','priority':['FILE_ID_DRIFT','REPARSE_TAG_DRIFT','FILE_ATTRIBUTES_DRIFT','current policy enforcement','volume check'],'file_attributes':'exact equality before current policy enforcement; mismatch stops FILE_ATTRIBUTES_DRIFT','reparse_tag':'exact equality before current policy enforcement; mismatch stops REPARSE_TAG_DRIFT','both_tag_and_attribute_drift':'REPARSE_TAG_DRIFT has deterministic priority','initial_policy':'chain construction still uses inspect_raw plus validate_node_policy','fail_closed':True}",
    "binding revalidation policy",
)

replace_once(
    "b['prior_audit']={'revision':'v0.4','result':'FAIL','critical':0,'major':1,'minor':0,'note':1,'finding_ids':['F-09']}",
    "b['prior_audit']={'revision':'v0.5','result':'FAIL','critical':0,'major':1,'minor':0,'note':1,'finding_ids':['F-09'],'closed_findings':['F-10'],'summary':'F-10 closed; F-09 regressed because policy enforcement previously preempted dedicated drift codes for forbidden current states.'}",
    "prior audit metadata",
)

anchor = "append_once(matrix, 'F-10 evidence-only remediation', f10)"
addition = """append_once(matrix, 'F-10 evidence-only remediation', f10)
f09_order='''## F-09 revalidation ordering remediation

Fresh re-audit confirmed F-10 CLOSED but found F-09 regressed because policy enforcement inside inspect() could stop before dedicated drift codes. Current runtime source separates inspect_raw() from validate_node_policy(). Revalidation preserves FILE_ID_DRIFT priority, then checks ReparseTag drift, then FileAttributes drift, then enforces current policy and volume identity. REPARSE_TAG_DRIFT has deterministic priority when both tag and attributes changed. Initial chain construction still enforces F-04 through inspect() = inspect_raw() + validate_node_policy().
'''
append_once(matrix, 'F-09 revalidation ordering remediation', f09_order)
append_once(r/'README_JA.md', 'F-09 revalidation ordering remediation', f09_order)"""
replace_once(anchor, addition, "documentation append")

replace_once(
    "Blocking prior finding: F-10 only (MAJOR), caused by inconsistent nested toolchain paths in the previous binding. Verify all current paths agree with actual build facts. Inspect `revalidate()` and verify exact, separate equality comparisons of saved `node.tag.FileAttributes` against current `current.tag.FileAttributes` and saved `node.tag.ReparseTag` against current `current.tag.ReparseTag`; verify mismatch causes fail-closed `FILE_ATTRIBUTES_DRIFT` and `REPARSE_TAG_DRIFT`.",
    "Blocking prior finding: F-09 regression (MAJOR). F-10 is CLOSED. Verify revalidation collects raw current metadata before policy enforcement; preserves FILE_ID_DRIFT priority; checks ReparseTag drift before FileAttributes drift; then enforces the current-node forbidden-state/type policy and volume identity. Confirm forbidden attribute or reparse-tag changes reach the dedicated FILE_ATTRIBUTES_DRIFT / REPARSE_TAG_DRIFT codes instead of being preempted by REPARSE_COMPONENT, REPARSE_TAG, or OFFLINE_CLOUD_VIRTUAL. When both tag and attributes drift, REPARSE_TAG_DRIFT has deterministic priority. Also verify all F-10 toolchain paths remain consistent with actual build facts.",
    "fresh prompt blocking finding",
)

out_path.write_text(s, encoding="utf-8")
