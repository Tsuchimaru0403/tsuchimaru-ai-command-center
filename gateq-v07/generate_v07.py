#!/usr/bin/env python3
from __future__ import annotations
import copy, hashlib, json, os, re, shutil, zipfile, zlib
from pathlib import Path

ROOT=Path(__file__).resolve().parent
INPUT=ROOT/"inputs"
BUILD=ROOT/"build"/"GateQ-Kernel-Compatibility-Requalification-v0.7-candidate"
DIST=ROOT/"dist"
SOURCE_COMMIT="14794180686c2fb6307fbe359c359bec765249f3"
SOURCE_TREE="3b5ec33f7fd60f23d01064150f7c7020d2e6af99"
BASELINE_SHA="4e1eb0e493bc9e1b8dba715084834119743eb509e6c43773ce6cd74e19cf1139"
PRE_SHA="6ef416bdb66cc87141a4d7cdedc9b8d8d7feb91a752012313f7ded78fe69e3c1"
FINAL_SHA="7415e92062b1fe82232e50e2d483f955c4fd80a3794e1a39191a7dc12d00f405"

def sha256(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for c in iter(lambda:f.read(1048576),b""): h.update(c)
    return h.hexdigest()

def write_json(p,o):
    p.write_text(json.dumps(o,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")

def cfg(p):
    o={}
    for line in p.read_text(encoding="utf-8").splitlines():
        m=re.match(r"CONFIG_([A-Za-z0-9_]+)=(.*)$",line)
        if m: o["CONFIG_"+m.group(1)]=m.group(2); continue
        m=re.match(r"# CONFIG_([A-Za-z0-9_]+) is not set$",line)
        if m: o["CONFIG_"+m.group(1)]="n"
    return o

def list_items(o):
    if isinstance(o,list): return o
    for k in ("deltas","decisions","items","symbols","classifications","changes"):
        if isinstance(o.get(k),list): return o[k]
    raise RuntimeError("list not found")

if BUILD.exists(): shutil.rmtree(BUILD)
BUILD.mkdir(parents=True)
DIST.mkdir(parents=True,exist_ok=True)

names=[
"K0_SOURCE_PROVENANCE_V06.json","K0_BASELINE.config","K1_PRE_OLDDEFCONFIG.config",
"K1_POST_OLDDEFCONFIG.config","K1_FINAL.config","K1_TRANSFORM_MANIFEST_V06.json",
"K1_DEPENDENCY_DELTA_V06.json","K1_DELTA_DECISIONS_V06.json",
"K1_REPRODUCIBILITY_STATUS_V06.json","NORMALIZATION_RESULT_V06.json",
"QUALIFIED_KCONFIG_RUN_V06.json","TARGET_KERNEL_CONFIG_POLICY.json",
"K2_REMAINING_SET_R_V06.json","K2_CLASSIFICATION_V06.json","K2_PROGRESSION_TREE_V06.json"]
for n in names: shutil.copy2(INPUT/n,BUILD/n)

assert sha256(BUILD/"K0_BASELINE.config")==BASELINE_SHA
assert sha256(BUILD/"K1_PRE_OLDDEFCONFIG.config")==PRE_SHA
assert sha256(BUILD/"K1_POST_OLDDEFCONFIG.config")==FINAL_SHA
assert sha256(BUILD/"K1_FINAL.config")==FINAL_SHA
assert (BUILD/"K1_POST_OLDDEFCONFIG.config").read_bytes()==(BUILD/"K1_FINAL.config").read_bytes()

b=cfg(BUILD/"K0_BASELINE.config")
pre=cfg(BUILD/"K1_PRE_OLDDEFCONFIG.config")
post=cfg(BUILD/"K1_POST_OLDDEFCONFIG.config")
base_m=sorted(k for k,v in b.items() if v=="m")
final_m=sorted(k for k,v in post.items() if v=="m")
assert len(base_m)==752 and len(final_m)==0

tr=json.loads((BUILD/"K1_TRANSFORM_MANIFEST_V06.json").read_text())
changes=tr["changes"]
assert len(changes)==752
assert sorted(x["symbol"] for x in changes)==base_m
assert all(x["from"]=="m" and x["to"]=="y" for x in changes)
(BUILD/"K1_M_SYMBOLS_V07.txt").write_text("\n".join(base_m)+"\n",encoding="utf-8")

dep=json.loads((BUILD/"K1_DEPENDENCY_DELTA_V06.json").read_text())
assert len(list_items(dep))==72
sem=sorted(k for k in set(pre)|set(post) if pre.get(k,"<absent>")!=post.get(k,"<absent>"))
assert len(sem)==72

groups={
"MODULES_SCOPE_OR_DEPENDENCY":[
"CONFIG_ASM_MODVERSIONS","CONFIG_BASIC_MODVERSIONS","CONFIG_EXTENDED_MODVERSIONS","CONFIG_GENDWARFKSYMS","CONFIG_GENKSYMS",
"CONFIG_MODPROBE_PATH","CONFIG_MODULES_TREE_LOOKUP","CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS","CONFIG_MODULE_COMPRESS","CONFIG_MODULE_DEBUG",
"CONFIG_MODULE_FORCE_LOAD","CONFIG_MODULE_FORCE_UNLOAD","CONFIG_MODULE_SIG","CONFIG_MODULE_SRCVERSION_ALL","CONFIG_MODULE_UNLOAD",
"CONFIG_MODULE_UNLOAD_TAINT_TRACKING","CONFIG_MODVERSIONS","CONFIG_TRIM_UNUSED_KSYMS","CONFIG_LIVEPATCH","CONFIG_MEDIA_ATTACH"],
"MODULES_INDIRECT_ARCH_EFFECT":["CONFIG_STRICT_MODULE_RWX","CONFIG_ARCH_HAS_EXECMEM_ROX"],
"MODULE_ONLY_DEPENDS_ON_M":["CONFIG_I2C_STUB","CONFIG_KPROBE_EVENT_GEN_TEST","CONFIG_PREEMPTIRQ_DELAY_TEST","CONFIG_SYNTH_EVENT_GEN_TEST","CONFIG_TEST_ASYNC_DRIVER_PROBE","CONFIG_TEST_LOCKUP"],
"VISIBILITY_OR_DEFAULT_CHANGE_AFTER_M_TO_Y":[
"CONFIG_ACPI_TINY_POWER_BUTTON","CONFIG_DEFAULT_BBR","CONFIG_DEFAULT_BIC","CONFIG_DEFAULT_CDG","CONFIG_DEFAULT_DCTCP","CONFIG_DEFAULT_HTCP",
"CONFIG_DEFAULT_HYBLA","CONFIG_DEFAULT_VEGAS","CONFIG_DEFAULT_VENO","CONFIG_DEFAULT_WESTWOOD","CONFIG_INTEL_SOC_PMIC",
"CONFIG_INTEL_SOC_PMIC_CHTDC_TI","CONFIG_INTEL_SOC_PMIC_CHTWC","CONFIG_MD_AUTODETECT","CONFIG_NVDIMM_KEYS","CONFIG_NVDIMM_SECURITY_TEST",
"CONFIG_PCI_NPEM","CONFIG_USB_KBD","CONFIG_USB_MOUSE","CONFIG_USB_SERIAL_CONSOLE"]}
assert sum(map(len,groups.values()))==48

ev={}
for s in groups["MODULES_SCOPE_OR_DEPENDENCY"]:
    if s=="CONFIG_LIVEPATCH": ev[s]=("kernel/livepatch/Kconfig","depends on MODULES")
    elif s=="CONFIG_MEDIA_ATTACH": ev[s]=("drivers/media/Kconfig","depends on MODULES")
    else: ev[s]=("kernel/module/Kconfig","module-specific symbol within MODULES scope")
ev["CONFIG_STRICT_MODULE_RWX"]=("arch/Kconfig","depends on ARCH_HAS_STRICT_MODULE_RWX && MODULES")
ev["CONFIG_ARCH_HAS_EXECMEM_ROX"]=("arch/x86/Kconfig","selected when X86_64 && STRICT_MODULE_RWX")
for s,p in {
"CONFIG_I2C_STUB":"drivers/i2c/Kconfig","CONFIG_KPROBE_EVENT_GEN_TEST":"kernel/trace/Kconfig",
"CONFIG_PREEMPTIRQ_DELAY_TEST":"kernel/trace/Kconfig","CONFIG_SYNTH_EVENT_GEN_TEST":"kernel/trace/Kconfig",
"CONFIG_TEST_ASYNC_DRIVER_PROBE":"drivers/base/test/Kconfig","CONFIG_TEST_LOCKUP":"lib/Kconfig.debug"}.items():
    ev[s]=(p,"depends on m")
ev.update({
"CONFIG_ACPI_TINY_POWER_BUTTON":("drivers/acpi/Kconfig","ACPI_BUTTON m to y makes depends on !ACPI_BUTTON false"),
"CONFIG_DEFAULT_BBR":("net/ipv4/Kconfig","TCP_CONG_BBR m to y exposes DEFAULT_BBR choice"),
"CONFIG_DEFAULT_BIC":("net/ipv4/Kconfig","TCP_CONG_BIC m to y exposes DEFAULT_BIC choice"),
"CONFIG_DEFAULT_CDG":("net/ipv4/Kconfig","TCP_CONG_CDG m to y exposes DEFAULT_CDG choice"),
"CONFIG_DEFAULT_DCTCP":("net/ipv4/Kconfig","TCP_CONG_DCTCP m to y exposes DEFAULT_DCTCP choice"),
"CONFIG_DEFAULT_HTCP":("net/ipv4/Kconfig","TCP_CONG_HTCP m to y exposes DEFAULT_HTCP choice"),
"CONFIG_DEFAULT_HYBLA":("net/ipv4/Kconfig","TCP_CONG_HYBLA m to y exposes DEFAULT_HYBLA choice"),
"CONFIG_DEFAULT_VEGAS":("net/ipv4/Kconfig","TCP_CONG_VEGAS m to y exposes DEFAULT_VEGAS choice"),
"CONFIG_DEFAULT_VENO":("net/ipv4/Kconfig","TCP_CONG_VENO m to y exposes DEFAULT_VENO choice"),
"CONFIG_DEFAULT_WESTWOOD":("net/ipv4/Kconfig","TCP_CONG_WESTWOOD m to y exposes DEFAULT_WESTWOOD choice"),
"CONFIG_INTEL_SOC_PMIC":("drivers/mfd/Kconfig","I2C_DESIGNWARE_PLATFORM m to y satisfies dependency"),
"CONFIG_INTEL_SOC_PMIC_CHTDC_TI":("drivers/mfd/Kconfig","I2C_DESIGNWARE_PLATFORM m to y satisfies dependency"),
"CONFIG_INTEL_SOC_PMIC_CHTWC":("drivers/mfd/Kconfig","I2C_DESIGNWARE_PLATFORM m to y satisfies dependency"),
"CONFIG_MD_AUTODETECT":("drivers/md/Kconfig","BLK_DEV_MD m to y exposes/defaults MD_AUTODETECT"),
"CONFIG_NVDIMM_KEYS":("drivers/nvdimm/Kconfig","ENCRYPTED_KEYS m to y with LIBNVDIMM=y satisfies equality"),
"CONFIG_NVDIMM_SECURITY_TEST":("drivers/nvdimm/Kconfig","visible because NVDIMM_KEYS becomes y"),
"CONFIG_PCI_NPEM":("drivers/pci/Kconfig","LEDS_CLASS m to y satisfies LEDS_CLASS=y"),
"CONFIG_USB_KBD":("drivers/hid/usbhid/Kconfig","USB_HID m to y hides boot-protocol menu"),
"CONFIG_USB_MOUSE":("drivers/hid/usbhid/Kconfig","USB_HID m to y hides boot-protocol menu"),
"CONFIG_USB_SERIAL_CONSOLE":("drivers/usb/serial/Kconfig","USB_SERIAL m to y exposes console option")})
assert len(ev)==48

d06=json.loads((BUILD/"K1_DELTA_DECISIONS_V06.json").read_text())
items=list_items(d06)
pending=[x["symbol"] for x in items if "REJECT_PENDING" in str(x.get("decision",""))]
assert len(pending)==48 and set(pending)==set(ev)
d07=copy.deepcopy(d06)
attrs=[]
for x in list_items(d07):
    s=x["symbol"]
    if s not in ev: continue
    g=next(g for g,ls in groups.items() if s in ls)
    p,c=ev[s]
    x.update({"decision":"ACCEPT_EXPECTED_KCONFIG_NORMALIZATION","attribution_status":"CLOSED_EXACT_SOURCE","attribution_group":g,"source_path":p,"source_condition":c,"source_commit":SOURCE_COMMIT})
    attrs.append({"symbol":s,"pre_value":x.get("pre_value"),"post_value":x.get("post_value"),"group":g,"source_path":p,"source_condition":c,"source_commit":SOURCE_COMMIT,"decision":"ACCEPT_EXPECTED_KCONFIG_NORMALIZATION"})
if isinstance(d07,dict):
    d07["schema"]="gateq-k1-delta-decisions-v07"
    d07["status"]="ALL_72_DECISIONS_CLOSED_STATIC_ATTRIBUTION_COMPLETE"
    d07["source_attribution_pending"]=0
write_json(BUILD/"K1_DELTA_DECISIONS_V07.json",d07)
write_json(BUILD/"K1_SOURCE_ATTRIBUTION_V07.json",{"schema":"gateq-k1-source-attribution-v07","status":"PASS_STATIC_SOURCE_ATTRIBUTION","source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,"delta_total":72,"formerly_pending_count":48,"closed_count":48,"group_counts":{k:len(v) for k,v in groups.items()},"attributions":attrs})
write_json(BUILD/"K1_REPRODUCIBILITY_STATUS_V07.json",{"schema":"gateq-k1-status-v07","status":"PASS_CONFIG_DERIVATION_ONLY_AWAITING_FRESH_STATIC_REAUDIT","source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,"baseline_config_sha256":BASELINE_SHA,"baseline_module_entries":752,"pre_normalization_config_sha256":PRE_SHA,"post_olddefconfig_config_sha256":FINAL_SHA,"final_config_sha256":FINAL_SHA,"second_normalization_byte_identical":True,"dependency_delta_count":72,"delta_accept_reject_decisions_closed":72,"source_attribution_closed":48,"source_attribution_pending":0,"final_module_entries":0,"kernel_outputs":[],"build_approved":False,"runtime_approved":False,"gate_q":"HOLD"})

policy=json.loads((BUILD/"TARGET_KERNEL_CONFIG_POLICY.json").read_text())
r=json.loads((BUILD/"K2_REMAINING_SET_R_V06.json").read_text())
ri=list_items(r)
assert len(ri)==92
mandatory=policy["mandatory_assertions"]
roots=[]
for x in ri:
    s=x["symbol"]
    if s in mandatory and str(x.get("k1_value"))!=str(mandatory[s]):
        roots.append({"symbol":s,"k1_value":x.get("k1_value"),"target_value":mandatory[s],"qualified_reference_value":x.get("reference_value"),"direct_mutation":True})
rootset={x["symbol"] for x in roots}
assert rootset=={"CONFIG_KEXEC_FILE","CONFIG_KPROBES","CONFIG_BPF_SYSCALL","CONFIG_SECURITY"}
pahole={"CONFIG_PAHOLE_VERSION","CONFIG_PAHOLE_HAS_SPLIT_BTF","CONFIG_PAHOLE_HAS_LANG_EXCLUDE"}
non=[]
for x in ri:
    if x["symbol"] in rootset: continue
    non.append({"symbol":x["symbol"],"k1_value":x.get("k1_value"),"qualified_reference_value":x.get("reference_value"),"classification":"TOOLCHAIN_ENVIRONMENT_OBSERVATION" if x["symbol"] in pahole else "NONROOT_OBSERVATION_ONLY","direct_mutation":False,"planned_action":"OBSERVE_AFTER_ROOT_NORMALIZATION_ONLY"})
assert len(roots)==4 and len(non)==88
write_json(BUILD/"K2_ROOT_CLASSIFICATION_V07.json",{"schema":"gateq-k2-root-classification-v07","status":"ROOT_SET_DERIVED_FROM_BOUND_TARGET_POLICY","source_R_count":92,"root_count":4,"nonroot_observation_count":88,"toolchain_environment_count":3,"derivation_rule":"Direct roots are exactly R symbols explicitly mandated by target policy where K1 differs from target.","direct_roots":sorted(roots,key=lambda x:x["symbol"]),"nonroots":sorted(non,key=lambda x:x["symbol"]),"supersedes":"K2_CLASSIFICATION_V06.json for progression authority"})
order=["CONFIG_KEXEC_FILE","CONFIG_KPROBES","CONFIG_BPF_SYSCALL","CONFIG_SECURITY"]
lookup={x["symbol"]:x for x in roots}
stages=[{"stage":i,"root_symbol":s,"from_value":lookup[s]["k1_value"],"target_value":lookup[s]["target_value"],"direct_mutations":[s],"normalization":"PLAN_ONLY; separately authorized olddefconfig/config-only later","capture":"induced_delta only; never mutate nonroots directly","status":"PLANNED_NOT_EXECUTED"} for i,s in enumerate(order,1)]
write_json(BUILD/"K2_ROOT_PROGRESSION_V07.json",{"schema":"gateq-k2-root-progression-v07","status":"PLAN_ONLY_NOT_EXECUTED","Gate_Q":"HOLD","build_authorized":False,"runtime_authorized":False,"root_order":order,"stages":stages,"nonroot_policy":"All other 88 R symbols are observation-only and MUST NOT be direct mutation targets.","toolchain_environment_policy":"PAHOLE_VERSION, PAHOLE_HAS_SPLIT_BTF and PAHOLE_HAS_LANG_EXCLUDE are environment evidence only.","failure_isolation":{"singleton_rule":"one root mutation per stage","interaction_test":"compare failing root from K1 parent versus immediately prior accepted parent","interaction_fallback":"deterministic subset/complement only across previously accepted roots under separate authorization","no_92_symbol_bisect":"v0.6 92-symbol direct mutation plan superseded"}})

write_json(BUILD/"DERIVATION_STATUS_V07.json",{"schema":"gateq-derivation-status-v07","status":"READY_FOR_FRESH_INDEPENDENT_STATIC_REAUDIT","Gate_Q":"HOLD","source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,"qualified_toolchain_run":36947817583,"derivation_run":37109392120,"baseline_module_entries":752,"final_module_entries":0,"K1_fixed_point":True,"K1_delta_count":72,"K1_source_attribution_closed":48,"K1_source_attribution_pending":0,"K1_final_sha256":FINAL_SHA,"R_count":92,"K2_direct_root_count":4,"K2_nonroot_observation_count":88,"K2_progression_executed":False,"kernel_outputs":[],"prohibited_operations_performed":[],"build_authorized":{"K0":False,"K1":False,"K2":False},"host_activation_authorized":False,"gate_a_authorized":False,"runtime_authorized":False})

(BUILD/"README_JA.md").write_text("""# Gate Q Kernel Compatibility Re-Qualification v0.7 candidate
Static remediation candidate. K1 48 source-attribution gaps are closed without changing K1 config bytes. The stale K1 status is superseded. The v0.6 92-symbol direct-mutation K2 plan is superseded by a four-root plan. No K2 stage is executed. Gate Q remains HOLD; builds, WSL/custom-kernel activation, Host Activation, Gate A and Runtime are not authorized.
""",encoding="utf-8")
(BUILD/"REMEDIATION_V07.md").write_text("""# REMEDIATION_V07
- K1: 48/48 former pending deltas attributed against the exact source commit in four groups 20+2+6+20.
- K1 authoritative status: completed normalization state, 752 baseline module entries, 0 final module entries, 72 deltas, fixed point, zero kernel outputs.
- K2: R=92 is not a mutation list. Direct policy roots are CONFIG_KEXEC_FILE=n, CONFIG_KPROBES=n, CONFIG_BPF_SYSCALL=n, CONFIG_SECURITY=n. Other 88 are observation-only. PAHOLE 3 are environment-only.
- v0.6 92-symbol direct mutation/bisection plan is superseded.
- Gate Q remains HOLD. Build, WSL, activation, Gate A and Runtime remain unauthorized.
""",encoding="utf-8")
(BUILD/"FRESH_INDEPENDENT_STATIC_REAUDIT_PROMPT_V07.md").write_text(f"""# FRESH INDEPENDENT STATIC RE-AUDIT v0.7
READ-ONLY STATIC ONLY. Gate Q remains HOLD.
Verify package SHA/CRC/safe paths/FILES.sha256/INPUT_BINDING. Recompute baseline m=752, transform count=752, pre hash={PRE_SHA}, post/final byte identity and hash={FINAL_SHA}, K1 semantic delta=72, fixed point and zero kernel outputs. Recompute former pending set=48 and verify all 48 exact-source attributions with group totals 20+2+6+20 and zero pending in v0.7. Verify authoritative status consistency. Recompute R=92 and direct roots as R intersect target-policy mandatory assertions where K1 differs from target. Root set must be exactly CONFIG_KEXEC_FILE, CONFIG_KPROBES, CONFIG_BPF_SYSCALL, CONFIG_SECURITY. Verify 4 roots, 88 nonroots, PAHOLE 3 environment-only, one root per planned stage, no direct nonroot mutation, and explicit supersession of v0.6 92-symbol plan. PASS requires CRITICAL=0 and MAJOR=0.
""",encoding="utf-8")
write_json(BUILD/"PACKAGE_BUILD_PROVENANCE_V07.json",{"schema":"gateq-package-build-provenance-v07","generator":"gateq-v07/generate_v07.py","github_repository":os.environ.get("GITHUB_REPOSITORY"),"github_sha":os.environ.get("GITHUB_SHA"),"github_ref":os.environ.get("GITHUB_REF"),"purpose":"static package assembly only","kernel_build_performed":False,"wsl_performed":False,"runtime_performed":False,"Gate_Q":"HOLD"})

sub=sorted(p for p in BUILD.iterdir() if p.is_file() and p.name not in {"INPUT_BINDING_V07.json","CRC_VERIFICATION_V07.json","FILES.sha256"})
write_json(BUILD/"INPUT_BINDING_V07.json",{"schema":"gateq-input-binding-v07","status":"COMPLETE","source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,"files":[{"path":p.name,"size":p.stat().st_size,"sha256":sha256(p)} for p in sub]})
targets=sorted(p for p in BUILD.iterdir() if p.is_file() and p.name not in {"CRC_VERIFICATION_V07.json","FILES.sha256"})
rows=[]
for p in targets:
    data=p.read_bytes()
    rows.append({"path":p.name,"size":len(data),"crc32":f"{zlib.crc32(data)&0xffffffff:08x}","sha256":hashlib.sha256(data).hexdigest()})
write_json(BUILD/"CRC_VERIFICATION_V07.json",{"schema":"gateq-crc-verification-v07","status":"PASS","coverage_rule":"all candidate files except CRC_VERIFICATION_V07.json and FILES.sha256, self-excluded","members":rows})
members=sorted(p for p in BUILD.iterdir() if p.is_file() and p.name!="FILES.sha256")
(BUILD/"FILES.sha256").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in members),encoding="utf-8")

zip_path=DIST/"GateQ-Kernel-Compatibility-Requalification-v0.7-candidate.zip"
with zipfile.ZipFile(zip_path,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in sorted(BUILD.iterdir(),key=lambda q:q.name):
        if p.is_file():
            zi=zipfile.ZipInfo(p.name,date_time=(2026,10,3,0,0,0))
            zi.compress_type=zipfile.ZIP_DEFLATED
            zi.external_attr=0o644<<16
            z.writestr(zi,p.read_bytes())
with zipfile.ZipFile(zip_path,"r") as z:
    assert z.testzip() is None
    ns=z.namelist()
    assert len(ns)==len(set(ns))
    assert all(not n.startswith(("/","\\")) and ".." not in Path(n).parts for n in ns)
outer=sha256(zip_path)
(DIST/(zip_path.name+".sha256")).write_text(f"{outer}  {zip_path.name}\n",encoding="utf-8")
print(json.dumps({"status":"PASS_STATIC_PACKAGE_ASSEMBLY","zip":zip_path.name,"zip_sha256":outer,"members":len(ns),"Gate_Q":"HOLD","build_authorized":False,"runtime_authorized":False},indent=2))
