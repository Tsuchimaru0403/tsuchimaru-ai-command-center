#!/usr/bin/env python3
from __future__ import annotations
import copy
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile
import zlib
from pathlib import Path

ROOT=Path(__file__).resolve().parent
INPUT=ROOT/"inputs"
STATIC=ROOT/"static"
ATTR_MAP=ROOT/"V07_SOURCE_ATTRIBUTION_MAP.json"
DERIV=Path(sys.argv[1]).resolve()
BUILD=ROOT/"build"/"GateQ-Kernel-Compatibility-Requalification-v0.7-candidate"
DIST=ROOT/"dist"

SOURCE_COMMIT="14794180686c2fb6307fbe359c359bec765249f3"
SOURCE_TREE="3b5ec33f7fd60f23d01064150f7c7020d2e6af99"
BASELINE_SHA="4e1eb0e493bc9e1b8dba715084834119743eb509e6c43773ce6cd74e19cf1139"
PRE_SHA="a8395a7dd589801a7c45ec2d42699ec55a64ea19e3ba8f8f3849820ccdff7f5c"
FINAL_SHA="7415e92062b1fe82232e50e2d483f955c4fd80a3794e1a39191a7dc12d00f405"
DERIV_RUN=37116020695
DERIV_ARTIFACT=11270544510
DERIV_DIGEST="sha256:f3a4d4b29e5610c71119d83df8046b147131b7fde136f9ffe744c312dc9bacf2"
TOOLCHAIN_RUN=36947817583

def sha(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda:f.read(1048576),b""):
            h.update(c)
    return h.hexdigest()

def write_json(p,o):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(o,indent=2,ensure_ascii=False,sort_keys=True)+"\n",encoding="utf-8")

def parse_cfg(p):
    out={}
    for line in p.read_text(encoding="utf-8").splitlines():
        m=re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$",line)
        if m:
            out[m.group(1)]=m.group(2)
            continue
        m=re.match(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$",line)
        if m:
            out[m.group(1)]="n"
    return out

def find_list(o):
    if isinstance(o,list):
        return o
    for k in ("deltas","decisions","items","symbols","classifications","changes"):
        if isinstance(o.get(k),list):
            return o[k]
    raise RuntimeError("list payload not found")

def files(root):
    return sorted((p for p in root.rglob("*") if p.is_file()),key=lambda p:p.relative_to(root).as_posix())

if BUILD.exists():
    shutil.rmtree(BUILD)
BUILD.mkdir(parents=True)
DIST.mkdir(parents=True,exist_ok=True)

# Preserve corrected derivation evidence as an independently verifiable subtree.
evidence=BUILD/"derivation-evidence-v07"
shutil.copytree(DERIV,evidence)

required=[
"K0_BASELINE.config","K0_NORMALIZED_CONTROL.config","K1_PRE_OLDDEFCONFIG.config",
"K1_POST_OLDDEFCONFIG.config","K1_M_SYMBOLS.txt","NORMALIZATION_RESULT.json",
"NORMALIZATION_COMMANDS.json","V06_REGEX_GAP_REMEDIATION.json",
"TOOLCHAIN_EFFECTIVE_IDENTITY.json","ACTIONS_RUN_BINDING.json","REMOTE_FILES.sha256"]
for n in required:
    assert (evidence/n).is_file(),n

for line in (evidence/"REMOTE_FILES.sha256").read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    h,name=line.split(None,1)
    p=evidence/name.strip().lstrip("*")
    assert p.resolve().is_relative_to(evidence.resolve())
    assert p.is_file()
    assert sha(p)==h,(name,h,sha(p))

assert sha(evidence/"K0_BASELINE.config")==BASELINE_SHA
assert sha(evidence/"K1_PRE_OLDDEFCONFIG.config")==PRE_SHA
assert sha(evidence/"K1_POST_OLDDEFCONFIG.config")==FINAL_SHA

base=parse_cfg(evidence/"K0_BASELINE.config")
pre=parse_cfg(evidence/"K1_PRE_OLDDEFCONFIG.config")
post=parse_cfg(evidence/"K1_POST_OLDDEFCONFIG.config")

raw_modules=sorted(k for k,v in base.items() if v=="m")
pre_modules=sorted(k for k,v in pre.items() if v=="m")
post_modules=sorted(k for k,v in post.items() if v=="m")
assert len(raw_modules)==760
assert len(pre_modules)==0
assert len(post_modules)==0

base_text=(evidence/"K0_BASELINE.config").read_text(encoding="utf-8")
uppercase_modules=[m.group(1) for m in re.finditer(r"^(CONFIG_[A-Z0-9_]+)=m$",base_text,re.M)]
missed=sorted(set(raw_modules)-set(uppercase_modules))
expected_missed=sorted([
"CONFIG_MT76x02_LIB","CONFIG_MT76x02_USB","CONFIG_MT792x_LIB","CONFIG_MT792x_USB",
"CONFIG_MT76x0_COMMON","CONFIG_MT76x0U","CONFIG_MT76x2_COMMON","CONFIG_MT76x2U"])
assert len(uppercase_modules)==752
assert missed==expected_missed

gap=json.loads((evidence/"V06_REGEX_GAP_REMEDIATION.json").read_text(encoding="utf-8"))
assert gap["baseline_raw_m_count"]==760
assert gap["v06_uppercase_regex_count"]==752
assert gap["missed_count"]==8
assert sorted(gap["missed_symbols"])==expected_missed

norm=json.loads((evidence/"NORMALIZATION_RESULT.json").read_text(encoding="utf-8"))
assert norm["status"]=="PASS_CONFIG_NORMALIZATION_ONLY"
assert norm["baseline_module_entries"]==760
assert norm["v06_uppercase_regex_entries"]==752
assert norm["v06_regex_gap_count"]==8
assert norm["pre_config_sha256"]==PRE_SHA
assert norm["K1"]["config_sha256"]==FINAL_SHA
assert norm["K1"]["second_normalization_byte_identical"] is True
assert norm["K1"]["kernel_objects"]==[]
assert norm["K1"]["kernel_outputs"]==[]
assert norm["K0_control"]["second_normalization_byte_identical"] is True
assert norm["K0_control"]["kernel_outputs"]==[]

# Promote authoritative corrected configs and policy/reference to the candidate root.
for src,dst in [
(evidence/"K0_BASELINE.config",BUILD/"K0_BASELINE.config"),
(evidence/"K1_PRE_OLDDEFCONFIG.config",BUILD/"K1_PRE_OLDDEFCONFIG.config"),
(evidence/"K1_POST_OLDDEFCONFIG.config",BUILD/"K1_POST_OLDDEFCONFIG.config"),
(evidence/"K1_POST_OLDDEFCONFIG.config",BUILD/"K1_FINAL.config"),
(evidence/"K1_M_SYMBOLS.txt",BUILD/"K1_M_SYMBOLS_V07.txt"),
(INPUT/"TARGET_KERNEL_CONFIG_POLICY.json",BUILD/"TARGET_KERNEL_CONFIG_POLICY.json"),
(INPUT/"QUALIFIED_HARDENING_REFERENCE.config",BUILD/"QUALIFIED_HARDENING_REFERENCE.config"),
(INPUT/"K0_SOURCE_PROVENANCE_V06.json",BUILD/"K0_SOURCE_PROVENANCE_V06.json")]:
    shutil.copy2(src,dst)

# Historical records retained only as history.
history=BUILD/"history-v06"
history.mkdir()
for n in [
"K1_DEPENDENCY_DELTA_V06.json","K1_DELTA_DECISIONS_V06.json",
"K1_REPRODUCIBILITY_STATUS_V06.json","K2_REMAINING_SET_R_V06.json",
"K2_CLASSIFICATION_V06.json","K2_PROGRESSION_TREE_V06.json"]:
    shutil.copy2(INPUT/n,history/n)

# Corrected direct transform manifest.
ordered=[m.group(1) for m in re.finditer(r"^(CONFIG_[A-Za-z0-9_]+)=m$",base_text,re.M)]
assert len(ordered)==760 and len(set(ordered))==760
assert base.get("CONFIG_MODULES")=="y"
changes=[{"symbol":s,"from":"m","to":"y"} for s in ordered]
changes.append({"symbol":"CONFIG_MODULES","from":"y","to":"n"})
write_json(BUILD/"K1_TRANSFORM_MANIFEST_V07.json",{
"schema":"gateq-k1-transform-v07",
"status":"CORRECTED_CASE_COMPLETE_NORMALIZED_CANDIDATE",
"source_commit":SOURCE_COMMIT,
"source_tree":SOURCE_TREE,
"baseline_sha256":BASELINE_SHA,
"pre_olddefconfig_sha256":PRE_SHA,
"post_olddefconfig_sha256":FINAL_SHA,
"final_config_sha256":FINAL_SHA,
"baseline_raw_module_symbol_count":760,
"v06_uppercase_regex_count":752,
"v06_regex_gap_count":8,
"v06_missed_symbols":expected_missed,
"module_promotions_count":760,
"total_direct_changes_count":761,
"changes":changes,
"normalization_fixed_point":True,
"qualified_toolchain_run":TOOLCHAIN_RUN,
"derivation_run":DERIV_RUN})

# Corrected case-complete pre/post semantic delta.
delta_symbols=sorted(k for k in set(pre)|set(post) if pre.get(k,"<absent>")!=post.get(k,"<absent>"))
assert len(delta_symbols)==72
delta=[{"symbol":s,"pre_value":pre.get(s,"<absent>"),"post_value":post.get(s,"<absent>")} for s in delta_symbols]
assert not set(expected_missed).intersection(delta_symbols)
write_json(BUILD/"K1_DEPENDENCY_DELTA_V07.json",{
"schema":"gateq-k1-dependency-delta-v07",
"status":"COMPLETE",
"count":72,
"case_complete_symbol_parser":"[A-Za-z0-9_]+",
"deltas":delta})

# Close prior 48 source-attribution gaps against corrected delta bytes.
old_obj=json.loads((history/"K1_DELTA_DECISIONS_V06.json").read_text(encoding="utf-8"))
old_items=find_list(old_obj)
old_by={x["symbol"]:x for x in old_items}
assert set(delta_symbols)==set(old_by)
pending={x["symbol"] for x in old_items if "REJECT_PENDING" in str(x.get("decision",""))}
assert len(pending)==48

amap=json.loads(ATTR_MAP.read_text(encoding="utf-8"))
assert amap["source_commit"]==SOURCE_COMMIT
amap_by={x["symbol"]:x for x in amap["entries"]}
assert set(amap_by)==pending
assert amap["group_counts"]=={
"MODULES_SCOPE_OR_DEPENDENCY":20,
"MODULES_INDIRECT_ARCH_EFFECT":2,
"MODULE_ONLY_DEPENDS_ON_M":6,
"VISIBILITY_OR_DEFAULT_CHANGE_AFTER_M_TO_Y":20}

attributions=[]
decisions=[]
for d in delta:
    s=d["symbol"]
    x=copy.deepcopy(old_by[s])
    x["pre_value"]=d["pre_value"]
    x["post_value"]=d["post_value"]
    x["corrected_v07_pre_post_binding"]=True
    if s in amap_by:
        a=amap_by[s]
        x["decision"]="ACCEPT_EXPECTED_KCONFIG_NORMALIZATION"
        x["attribution_status"]="CLOSED_EXACT_SOURCE"
        x["attribution_group"]=a["group"]
        x["source_path"]=a["source_path"]
        x["source_condition"]=a["source_condition"]
        x["source_commit"]=SOURCE_COMMIT
        attributions.append({
        "symbol":s,"pre_value":d["pre_value"],"post_value":d["post_value"],
        "group":a["group"],"source_path":a["source_path"],"source_condition":a["source_condition"],
        "source_commit":SOURCE_COMMIT,"decision":"ACCEPT_EXPECTED_KCONFIG_NORMALIZATION"})
    decisions.append(x)

assert len(attributions)==48
assert not [x for x in decisions if "PENDING" in str(x.get("decision",""))]
write_json(BUILD/"K1_SOURCE_ATTRIBUTION_V07.json",{
"schema":"gateq-k1-source-attribution-v07",
"status":"PASS_STATIC_SOURCE_ATTRIBUTION",
"source_commit":SOURCE_COMMIT,
"source_tree":SOURCE_TREE,
"delta_total":72,
"formerly_pending_count":48,
"closed_count":48,
"group_counts":amap["group_counts"],
"attributions":attributions})
write_json(BUILD/"K1_DELTA_DECISIONS_V07.json",{
"schema":"gateq-k1-delta-decisions-v07",
"status":"ALL_72_DECISIONS_CLOSED",
"count":72,
"source_attribution_pending":0,
"decisions":decisions})

write_json(BUILD/"K1_REPRODUCIBILITY_STATUS_V07.json",{
"schema":"gateq-k1-status-v07",
"status":"PASS_CONFIG_DERIVATION_ONLY_AWAITING_FRESH_STATIC_REAUDIT",
"source_commit":SOURCE_COMMIT,
"source_tree":SOURCE_TREE,
"baseline_config_sha256":BASELINE_SHA,
"baseline_raw_module_entries":760,
"v06_uppercase_regex_entries":752,
"v06_regex_gap_count":8,
"v06_missed_symbols":expected_missed,
"pre_normalization_config_sha256":PRE_SHA,
"post_olddefconfig_config_sha256":FINAL_SHA,
"final_config_sha256":FINAL_SHA,
"post_equals_v06_final_hash":True,
"second_normalization_byte_identical":True,
"dependency_delta_count":72,
"delta_accept_reject_decisions_closed":72,
"source_attribution_closed":48,
"source_attribution_pending":0,
"final_module_entries":0,
"kernel_outputs":[],
"derivation_run":DERIV_RUN,
"derivation_artifact_id":DERIV_ARTIFACT,
"derivation_artifact_digest":DERIV_DIGEST,
"build_approved":False,
"runtime_approved":False,
"gate_q":"HOLD"})

# Recompute R from corrected final versus qualified hardening reference.
ref=parse_cfg(BUILD/"QUALIFIED_HARDENING_REFERENCE.config")
final=parse_cfg(BUILD/"K1_FINAL.config")
r_symbols=sorted(k for k in set(final)|set(ref) if final.get(k,"<absent>")!=ref.get(k,"<absent>"))
assert len(r_symbols)==92
r_rows=[{"symbol":s,"k1_value":final.get(s,"<absent>"),"reference_value":ref.get(s,"<absent>")} for s in r_symbols]
write_json(BUILD/"K2_REMAINING_SET_R_V07.json",{
"schema":"gateq-k2-remaining-r-v07",
"status":"RECOMPUTED_FROM_CORRECTED_K1_FINAL_AND_QUALIFIED_REFERENCE",
"count":92,
"symbols":r_rows})

policy=json.loads((BUILD/"TARGET_KERNEL_CONFIG_POLICY.json").read_text(encoding="utf-8"))
mandatory=policy["mandatory_assertions"]
roots=[]
for x in r_rows:
    s=x["symbol"]
    if s in mandatory and str(x["k1_value"])!=str(mandatory[s]):
        roots.append({
        "symbol":s,"k1_value":x["k1_value"],"target_value":mandatory[s],
        "qualified_reference_value":x["reference_value"],"direct_mutation":True})
root_set={x["symbol"] for x in roots}
assert root_set=={"CONFIG_KEXEC_FILE","CONFIG_KPROBES","CONFIG_BPF_SYSCALL","CONFIG_SECURITY"}

pahole={"CONFIG_PAHOLE_VERSION","CONFIG_PAHOLE_HAS_SPLIT_BTF","CONFIG_PAHOLE_HAS_LANG_EXCLUDE"}
nonroots=[]
for x in r_rows:
    if x["symbol"] in root_set:
        continue
    nonroots.append({
    "symbol":x["symbol"],"k1_value":x["k1_value"],
    "qualified_reference_value":x["reference_value"],
    "classification":"TOOLCHAIN_ENVIRONMENT_OBSERVATION" if x["symbol"] in pahole else "NONROOT_OBSERVATION_ONLY",
    "direct_mutation":False,
    "planned_action":"OBSERVE_AFTER_ROOT_NORMALIZATION_ONLY"})
assert len(roots)==4 and len(nonroots)==88
assert sum(x["classification"]=="TOOLCHAIN_ENVIRONMENT_OBSERVATION" for x in nonroots)==3

write_json(BUILD/"K2_ROOT_CLASSIFICATION_V07.json",{
"schema":"gateq-k2-root-classification-v07",
"status":"ROOT_SET_DERIVED_FROM_BOUND_TARGET_POLICY",
"source_R_count":92,
"root_count":4,
"nonroot_observation_count":88,
"toolchain_environment_count":3,
"derivation_rule":"Direct roots are exactly R symbols explicitly mandated by target policy where corrected K1 differs from target.",
"direct_roots":sorted(roots,key=lambda x:x["symbol"]),
"nonroots":sorted(nonroots,key=lambda x:x["symbol"]),
"supersedes":"history-v06/K2_CLASSIFICATION_V06.json for progression authority"})

order=["CONFIG_KEXEC_FILE","CONFIG_KPROBES","CONFIG_BPF_SYSCALL","CONFIG_SECURITY"]
lookup={x["symbol"]:x for x in roots}
stages=[]
for i,s in enumerate(order,1):
    stages.append({
    "stage":i,
    "root_symbol":s,
    "from_value":lookup[s]["k1_value"],
    "target_value":lookup[s]["target_value"],
    "direct_mutations":[s],
    "normalization":"PLAN_ONLY; separately authorized config-only olddefconfig later",
    "capture":"record all resulting changes as induced_delta; never directly mutate nonroots",
    "status":"PLANNED_NOT_EXECUTED"})
write_json(BUILD/"K2_ROOT_PROGRESSION_V07.json",{
"schema":"gateq-k2-root-progression-v07",
"status":"PLAN_ONLY_NOT_EXECUTED",
"Gate_Q":"HOLD",
"build_authorized":False,
"runtime_authorized":False,
"root_order":order,
"stages":stages,
"nonroot_policy":"All other 88 R symbols are observation-only and MUST NOT be direct mutation targets.",
"toolchain_environment_policy":"The three PAHOLE symbols are environment evidence only.",
"failure_isolation":{
"singleton_rule":"one root mutation per stage",
"interaction_test":"future separately-authorized failure: compare root from K1 parent and immediate prior accepted parent",
"interaction_fallback":"deterministic subset/complement only across previously accepted roots under separate authorization",
"no_92_symbol_bisect":"v0.6 92-symbol direct-mutation plan is superseded"}})

write_json(BUILD/"DERIVATION_STATUS_V07.json",{
"schema":"gateq-derivation-status-v07",
"status":"READY_FOR_FRESH_INDEPENDENT_STATIC_REAUDIT",
"Gate_Q":"HOLD",
"source_commit":SOURCE_COMMIT,
"source_tree":SOURCE_TREE,
"qualified_toolchain_run":TOOLCHAIN_RUN,
"derivation_run":DERIV_RUN,
"baseline_raw_module_entries":760,
"v06_uppercase_regex_entries":752,
"v06_regex_gap_count":8,
"final_module_entries":0,
"K1_fixed_point":True,
"K1_delta_count":72,
"K1_source_attribution_closed":48,
"K1_source_attribution_pending":0,
"K1_final_sha256":FINAL_SHA,
"R_count":92,
"K2_direct_root_count":4,
"K2_nonroot_observation_count":88,
"K2_progression_executed":False,
"kernel_outputs":[],
"prohibited_operations_performed":[],
"build_authorized":{"K0":False,"K1":False,"K2":False},
"host_activation_authorized":False,
"gate_a_authorized":False,
"runtime_authorized":False})

# Static review docs.
for n in ["README_JA.md","REMEDIATION_V07.md","FRESH_INDEPENDENT_STATIC_REAUDIT_PROMPT_V07.md"]:
    shutil.copy2(STATIC/n,BUILD/n)

write_json(BUILD/"PACKAGE_BUILD_PROVENANCE_V07.json",{
"schema":"gateq-package-build-provenance-v07",
"generator":"gateq-v07/generate_v07_corrected.py",
"github_repository":os.environ.get("GITHUB_REPOSITORY"),
"github_sha":os.environ.get("GITHUB_SHA"),
"github_ref":os.environ.get("GITHUB_REF"),
"corrected_derivation_run":DERIV_RUN,
"corrected_derivation_artifact_id":DERIV_ARTIFACT,
"corrected_derivation_artifact_digest":DERIV_DIGEST,
"kernel_build_performed":False,
"wsl_performed":False,
"runtime_performed":False,
"Gate_Q":"HOLD"})

# Recursive package manifests.
sub=[p for p in files(BUILD) if p.name not in {"INPUT_BINDING_V07.json","CRC_VERIFICATION_V07.json","FILES.sha256"}]
write_json(BUILD/"INPUT_BINDING_V07.json",{
"schema":"gateq-input-binding-v07",
"status":"COMPLETE",
"source_commit":SOURCE_COMMIT,
"source_tree":SOURCE_TREE,
"files":[{"path":p.relative_to(BUILD).as_posix(),"size":p.stat().st_size,"sha256":sha(p)} for p in sub]})

targets=[p for p in files(BUILD) if p.name not in {"CRC_VERIFICATION_V07.json","FILES.sha256"}]
rows=[]
for p in targets:
    data=p.read_bytes()
    rows.append({
    "path":p.relative_to(BUILD).as_posix(),
    "size":len(data),
    "crc32":format(zlib.crc32(data)&0xffffffff,"08x"),
    "sha256":hashlib.sha256(data).hexdigest()})
write_json(BUILD/"CRC_VERIFICATION_V07.json",{
"schema":"gateq-crc-verification-v07",
"status":"PASS",
"coverage_rule":"all candidate members except CRC_VERIFICATION_V07.json and FILES.sha256, self-excluded",
"members":rows})

manifest_members=[p for p in files(BUILD) if p.name!="FILES.sha256"]
(BUILD/"FILES.sha256").write_text(
"".join(sha(p)+"  "+p.relative_to(BUILD).as_posix()+"\n" for p in manifest_members),
encoding="utf-8")

zip_path=DIST/"GateQ-Kernel-Compatibility-Requalification-v0.7-candidate.zip"
with zipfile.ZipFile(zip_path,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in files(BUILD):
        arc=p.relative_to(BUILD).as_posix()
        zi=zipfile.ZipInfo(arc,date_time=(2026,10,3,0,0,0))
        zi.compress_type=zipfile.ZIP_DEFLATED
        zi.external_attr=0o644<<16
        z.writestr(zi,p.read_bytes())

with zipfile.ZipFile(zip_path) as z:
    assert z.testzip() is None
    names=z.namelist()
    assert len(names)==len(set(names))
    assert all(not n.startswith(("/","\\")) and ".." not in Path(n).parts for n in names)

outer=sha(zip_path)
(DIST/(zip_path.name+".sha256")).write_text(
outer+"  "+zip_path.name+"\n",encoding="utf-8")
print(json.dumps({
"status":"PASS_STATIC_PACKAGE_ASSEMBLY",
"zip":zip_path.name,
"zip_sha256":outer,
"members":len(names),
"baseline_raw_module_entries":760,
"corrected_pre_sha256":PRE_SHA,
"final_sha256":FINAL_SHA,
"corrected_delta_count":72,
"R_count":92,
"K2_direct_roots":4,
"Gate_Q":"HOLD",
"kernel_build_authorized":False,
"runtime_authorized":False},indent=2))
