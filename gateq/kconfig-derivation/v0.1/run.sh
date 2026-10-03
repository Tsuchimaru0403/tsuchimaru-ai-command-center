#!/usr/bin/env bash
set -euo pipefail

: "${SOURCE_COMMIT:?}"
: "${SOURCE_TREE:?}"
: "${K0_CONFIG_SHA256:?}"
: "${QUALIFIED_FINAL_CONFIG_SHA256:?}"
: "${CC:=gcc-13}"
: "${HOSTCC:=gcc-13}"
export ARCH=x86_64 CC HOSTCC LC_ALL=C LANG=C TZ=UTC

ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
OUT="$ROOT/out"
mkdir -p "$OUT"

command -v "$CC"
command -v make

{
  echo "authorization=KCONFIG_DERIVATION_ONLY"
  echo "kernel_compile=false"
  echo "bzImage=false"
  echo "wsl=false"
  echo "wslconfig=false"
  echo "custom_kernel_activation=false"
  echo "host_activation=false"
  echo "gate_a=false"
  echo "runtime=false"
} > "$OUT/AUTHORIZATION_BOUNDARY.txt"

for d in "$ROOT/linux-A" "$ROOT/linux-B"; do
  test "$(git -C "$d" rev-parse HEAD)" = "$SOURCE_COMMIT"
  test "$(git -C "$d" rev-parse HEAD^{tree})" = "$SOURCE_TREE"
  test -f "$d/arch/x86/configs/config-wsl"
  test "$(sha256sum "$d/arch/x86/configs/config-wsl" | awk '{print $1}')" = "$K0_CONFIG_SHA256"
  test -x "$d/scripts/config"
done

{
  echo "gcc=$($CC --version | head -1)"
  echo "make=$(make --version | head -1)"
  echo "source_commit=$SOURCE_COMMIT"
  echo "source_tree=$SOURCE_TREE"
  echo "k0_config_sha256=$K0_CONFIG_SHA256"
  echo "qualified_final_config_sha256=$QUALIFIED_FINAL_CONFIG_SHA256"
} > "$OUT/DERIVATION_ENVIRONMENT.txt"

derive_k1() {
  local src="$1"
  local outdir="$2"
  mkdir -p "$outdir"

  cp "$src/arch/x86/configs/config-wsl" "$outdir/K0_BASELINE.config"
  grep -E '^CONFIG_[A-Za-z0-9_]+=m$' "$outdir/K0_BASELINE.config" | sort > "$outdir/K1_M_SYMBOLS.txt"

  python3 - "$outdir/K1_M_SYMBOLS.txt" "$outdir/K1_TRANSFORM_MANIFEST.json" <<'PY'
import json, pathlib, sys
lines=[x.strip() for x in pathlib.Path(sys.argv[1]).read_text().splitlines() if x.strip()]
items=[]
for line in lines:
    symbol=line.split("=",1)[0]
    items.append({"symbol":symbol,"from":"m","to":"y","operation":"promote_existing_module_selection"})
obj={
  "schema":"TSUCHIMARU_K1_TRANSFORM_MANIFEST_V1",
  "baseline":"K0 Microsoft config-wsl",
  "module_promotions":items,
  "module_promotion_count":len(items),
  "explicit_operations":[{"symbol":"CONFIG_MODULES","to":"n"}]
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
PY

  cp "$outdir/K0_BASELINE.config" "$src/.config"
  sed -i -E 's/^(CONFIG_[A-Za-z0-9_]+)=m$/\1=y/' "$src/.config"
  "$src/scripts/config" --file "$src/.config" --disable MODULES
  cp "$src/.config" "$outdir/K1_PRE_OLDDEFCONFIG.config"

  make -C "$src" olddefconfig
  cp "$src/.config" "$outdir/K1_POST_OLDDEFCONFIG.config"

  python3 - "$outdir/K0_BASELINE.config" "$outdir/K1_PRE_OLDDEFCONFIG.config" "$outdir/K1_POST_OLDDEFCONFIG.config" "$outdir/K1_M_SYMBOLS.txt" "$outdir/K1_DEPENDENCY_DELTA.json" "$outdir/K1_DELTA_DECISIONS.json" <<'PY'
import json, pathlib, re, sys

def parse(path):
    d={}
    for raw in pathlib.Path(path).read_text().splitlines():
        m=re.match(r'^(CONFIG_[A-Za-z0-9_]+)=(.*)$',raw)
        if m:
            d[m.group(1)]=m.group(2); continue
        m=re.match(r'^# (CONFIG_[A-Za-z0-9_]+) is not set$',raw)
        if m:
            d[m.group(1)]='n'
    return d

base,pre,post=map(parse,sys.argv[1:4])
orig_m={x.split('=',1)[0] for x in pathlib.Path(sys.argv[4]).read_text().splitlines() if x.strip()}
syms=sorted(set(pre)|set(post))
delta=[]
decisions=[]
rejects=[]
for s in syms:
    a=pre.get(s,'ABSENT'); b=post.get(s,'ABSENT')
    if a==b:
        continue
    rec={"symbol":s,"before":a,"after":b,"baseline":base.get(s,'ABSENT'),"originally_module":s in orig_m}
    delta.append(rec)
    if b == 'm':
        decision='REJECT'
        reason='post-olddefconfig module selection remains'
        rejects.append(s)
    else:
        decision='ACCEPT'
        reason='deterministic Kconfig dependency/default closure after only registered K1 edits'
    decisions.append({**rec,"decision":decision,"reason":reason})

post_m=sorted(s for s,v in post.items() if v=='m')
if post.get('CONFIG_MODULES','n') not in ('n','ABSENT'):
    rejects.append('CONFIG_MODULES')
if post_m:
    rejects.extend(post_m)

pathlib.Path(sys.argv[5]).write_text(json.dumps({
 "schema":"TSUCHIMARU_K1_DEPENDENCY_DELTA_V1",
 "count":len(delta),
 "entries":delta
},indent=2,sort_keys=True)+"\n")
pathlib.Path(sys.argv[6]).write_text(json.dumps({
 "schema":"TSUCHIMARU_K1_DELTA_DECISIONS_V1",
 "acceptance_rule":"Every pre->post change must be deterministic Kconfig closure from the registered K1 edits; any resulting =m or CONFIG_MODULES enabled is rejected.",
 "entries":decisions,
 "rejects":sorted(set(rejects)),
 "result":"PASS" if not rejects else "FAIL"
},indent=2,sort_keys=True)+"\n")
if rejects:
    raise SystemExit("K1 dependency decision rejected symbols: "+",".join(sorted(set(rejects))))
PY
}

derive_k1 "$ROOT/linux-A" "$OUT/A"
derive_k1 "$ROOT/linux-B" "$OUT/B"

cmp "$OUT/A/K0_BASELINE.config" "$OUT/B/K0_BASELINE.config"
cmp "$OUT/A/K1_M_SYMBOLS.txt" "$OUT/B/K1_M_SYMBOLS.txt"
cmp "$OUT/A/K1_TRANSFORM_MANIFEST.json" "$OUT/B/K1_TRANSFORM_MANIFEST.json"
cmp "$OUT/A/K1_PRE_OLDDEFCONFIG.config" "$OUT/B/K1_PRE_OLDDEFCONFIG.config"
cmp "$OUT/A/K1_POST_OLDDEFCONFIG.config" "$OUT/B/K1_POST_OLDDEFCONFIG.config"
cmp "$OUT/A/K1_DEPENDENCY_DELTA.json" "$OUT/B/K1_DEPENDENCY_DELTA.json"
cmp "$OUT/A/K1_DELTA_DECISIONS.json" "$OUT/B/K1_DELTA_DECISIONS.json"

cp "$OUT/A/K0_BASELINE.config" "$OUT/K0_BASELINE.config"
cp "$OUT/A/K1_M_SYMBOLS.txt" "$OUT/K1_M_SYMBOLS.txt"
cp "$OUT/A/K1_TRANSFORM_MANIFEST.json" "$OUT/K1_TRANSFORM_MANIFEST.json"
cp "$OUT/A/K1_PRE_OLDDEFCONFIG.config" "$OUT/K1_PRE_OLDDEFCONFIG.config"
cp "$OUT/A/K1_POST_OLDDEFCONFIG.config" "$OUT/K1_POST_OLDDEFCONFIG.config"
cp "$OUT/A/K1_DEPENDENCY_DELTA.json" "$OUT/K1_DEPENDENCY_DELTA.json"
cp "$OUT/A/K1_DELTA_DECISIONS.json" "$OUT/K1_DELTA_DECISIONS.json"
cp "$OUT/A/K1_POST_OLDDEFCONFIG.config" "$OUT/K1_FINAL.config"

{
  sha256sum "$OUT/A/K1_POST_OLDDEFCONFIG.config"
  sha256sum "$OUT/B/K1_POST_OLDDEFCONFIG.config"
} > "$OUT/K1_AB_SHA256.txt"

# Replay exact historical qualified config policy, config-only.
src="$ROOT/linux-A"
cp "$OUT/K1_FINAL.config" "$src/.config"
"$src/scripts/config" --file "$src/.config" --disable SECURITY
"$src/scripts/config" --file "$src/.config" --disable BPF_SYSCALL
"$src/scripts/config" --file "$src/.config" --disable KPROBES
"$src/scripts/config" --file "$src/.config" --disable LIVEPATCH
"$src/scripts/config" --file "$src/.config" --disable KEXEC
"$src/scripts/config" --file "$src/.config" --disable KEXEC_FILE
"$src/scripts/config" --file "$src/.config" --enable EXT4_FS
"$src/scripts/config" --file "$src/.config" --enable EXT4_FS_POSIX_ACL
"$src/scripts/config" --file "$src/.config" --enable IKCONFIG
"$src/scripts/config" --file "$src/.config" --enable IKCONFIG_PROC
"$src/scripts/config" --file "$src/.config" --enable PROC_FS
"$src/scripts/config" --file "$src/.config" --enable SYSFS
"$src/scripts/config" --file "$src/.config" --disable LOCALVERSION_AUTO
"$src/scripts/config" --file "$src/.config" --enable RANDSTRUCT_NONE
"$src/scripts/config" --file "$src/.config" --disable RANDSTRUCT_FULL
"$src/scripts/config" --file "$src/.config" --disable RANDSTRUCT_PERFORMANCE
"$src/scripts/config" --file "$src/.config" --set-str SYSTEM_TRUSTED_KEYS ""
"$src/scripts/config" --file "$src/.config" --set-str SYSTEM_REVOCATION_KEYS ""
"$src/scripts/config" --file "$src/.config" --set-str BUILD_SALT ""
cp "$src/.config" "$OUT/TARGET_PRE_OLDDEFCONFIG.config"
make -C "$src" olddefconfig
cp "$src/.config" "$OUT/TARGET_QUALIFIED_REPLAY.config"
actual="$(sha256sum "$OUT/TARGET_QUALIFIED_REPLAY.config" | awk '{print $1}')"
printf '%s  TARGET_QUALIFIED_REPLAY.config\n' "$actual" > "$OUT/TARGET_QUALIFIED_REPLAY.sha256"
test "$actual" = "$QUALIFIED_FINAL_CONFIG_SHA256"

cat > /tmp/progression.py <<'PY'
import json, pathlib, re, subprocess, os, hashlib

ROOT=pathlib.Path(os.environ['GITHUB_WORKSPACE'])
SRC=ROOT/'linux-A'
OUT=ROOT/'out'
K1=OUT/'K1_FINAL.config'
TARGET=OUT/'TARGET_QUALIFIED_REPLAY.config'

def parse(path):
    d={}
    for raw in pathlib.Path(path).read_text().splitlines():
        m=re.match(r'^(CONFIG_[A-Za-z0-9_]+)=(.*)$',raw)
        if m:
            d[m.group(1)]=m.group(2); continue
        m=re.match(r'^# (CONFIG_[A-Za-z0-9_]+) is not set$',raw)
        if m:
            d[m.group(1)]='n'
    return d

ops=[
 ("CONFIG_SECURITY","n","security"),
 ("CONFIG_BPF_SYSCALL","n","bpf"),
 ("CONFIG_KPROBES","n","kprobes"),
 ("CONFIG_LIVEPATCH","n","livepatch"),
 ("CONFIG_KEXEC","n","kexec"),
 ("CONFIG_KEXEC_FILE","n","kexec"),
 ("CONFIG_EXT4_FS","y","filesystem"),
 ("CONFIG_EXT4_FS_POSIX_ACL","y","filesystem"),
 ("CONFIG_IKCONFIG","y","introspection"),
 ("CONFIG_IKCONFIG_PROC","y","introspection"),
 ("CONFIG_PROC_FS","y","filesystem"),
 ("CONFIG_SYSFS","y","filesystem"),
 ("CONFIG_LOCALVERSION_AUTO","n","determinism"),
 ("CONFIG_RANDSTRUCT_NONE","y","randstruct"),
 ("CONFIG_RANDSTRUCT_FULL","n","randstruct"),
 ("CONFIG_RANDSTRUCT_PERFORMANCE","n","randstruct"),
 ("CONFIG_SYSTEM_TRUSTED_KEYS",'""',"determinism"),
 ("CONFIG_SYSTEM_REVOCATION_KEYS",'""',"determinism"),
 ("CONFIG_BUILD_SALT",'""',"determinism"),
]
opmap={s:{"requested":v,"group":g,"order":i+1} for i,(s,v,g) in enumerate(ops)}

k1=parse(K1)
target=parse(TARGET)
r=[]
for s in sorted(set(k1)|set(target)):
    a=k1.get(s,'ABSENT')
    b=target.get(s,'ABSENT')
    if a!=b:
        cls='direct_registered_override' if s in opmap else 'dependency_induced'
        r.append({"symbol":s,"k1":a,"target":b,"classification":cls,"registered_operation":opmap.get(s)})
(OUT/'K2_REMAINING_SET_R.json').write_text(json.dumps({
 "schema":"TSUCHIMARU_K2_REMAINING_SET_R_V1",
 "count":len(r),
 "entries":r
},indent=2,sort_keys=True)+"\n")

current=K1.read_bytes()
stages=[]
stage_dir=OUT/'K2_STAGES'
stage_dir.mkdir(exist_ok=True)
for idx,(symbol,value,group) in enumerate(ops,1):
    (SRC/'.config').write_bytes(current)
    before=parse(SRC/'.config')
    short=symbol.removeprefix('CONFIG_')
    if value=='n':
        subprocess.run([str(SRC/'scripts/config'),'--file',str(SRC/'.config'),'--disable',short],check=True)
    elif value=='y':
        subprocess.run([str(SRC/'scripts/config'),'--file',str(SRC/'.config'),'--enable',short],check=True)
    else:
        subprocess.run([str(SRC/'scripts/config'),'--file',str(SRC/'.config'),'--set-str',short,''],check=True)
    pre=(SRC/'.config').read_bytes()
    subprocess.run(['make','-C',str(SRC),'olddefconfig'],check=True,env=os.environ.copy())
    post=(SRC/'.config').read_bytes()
    after=parse(SRC/'.config')
    delta=[]
    for s in sorted(set(before)|set(after)):
        a=before.get(s,'ABSENT')
        b=after.get(s,'ABSENT')
        if a!=b:
            delta.append({"symbol":s,"before":a,"after":b,"classification":"direct" if s==symbol else "dependency_induced"})
    effective=(post!=current)
    name=f"K2_{idx:02d}_{symbol}"
    (stage_dir/f"{name}_PRE.config").write_bytes(pre)
    (stage_dir/f"{name}_POST.config").write_bytes(post)
    (stage_dir/f"{name}_DELTA.json").write_text(json.dumps(delta,indent=2,sort_keys=True)+"\n")
    stages.append({
      "stage":idx,
      "symbol":symbol,
      "requested":value,
      "group":group,
      "effective_change":effective,
      "pre_sha256":hashlib.sha256(pre).hexdigest(),
      "post_sha256":hashlib.sha256(post).hexdigest(),
      "delta_count":len(delta),
      "delta_file":f"K2_STAGES/{name}_DELTA.json"
    })
    current=post

final_hash=hashlib.sha256(current).hexdigest()
if final_hash!=os.environ['QUALIFIED_FINAL_CONFIG_SHA256']:
    raise SystemExit('sequential progression final config does not match canonical qualified final config hash')

plan={
 "schema":"TSUCHIMARU_K2_PROGRESSION_TREE_V1",
 "base":"K1_FINAL.config",
 "strategy":"one registered direct operation per normalization stage in exact historical policy order",
 "stages":stages,
 "runtime_failure_fallback":{
   "step_1":"Stop immediately at first boot/runtime FAIL; no later stage is eligible.",
   "step_2":"Re-test the failing direct operation alone from K1 in a separately authorized future build/boot candidate.",
   "step_3":"If failing operation alone PASSes, classify as interaction and hold that operation fixed while binary-searching the previously active direct-operation set.",
   "step_4":"For a multi-symbol dependency closure, do not manipulate dependency-induced symbols directly; the registered direct operation is the intervention boundary.",
   "step_5":"No causal attribution is allowed until the minimal failing direct-operation subset is reproduced."
 },
 "final_sha256":final_hash
}
(OUT/'K2_PROGRESSION_TREE.json').write_text(json.dumps(plan,indent=2,sort_keys=True)+"\n")

classification={}
for e in r:
    classification.setdefault(e['classification'],[]).append(e['symbol'])
(OUT/'K2_CLASSIFICATION.json').write_text(json.dumps({
 "schema":"TSUCHIMARU_K2_CLASSIFICATION_V1",
 "classes":classification,
 "direct_operation_order":[{"symbol":s,"requested":v,"group":g} for s,v,g in ops]
},indent=2,sort_keys=True)+"\n")
PY
python3 /tmp/progression.py

python3 - <<'PY'
import hashlib, json, pathlib, os
out=pathlib.Path('out')
files=[]
for p in sorted(out.rglob('*')):
    if p.is_file() and p.name not in {'FILES.sha256','DERIVATION_SUMMARY.json'}:
        b=p.read_bytes()
        files.append({"path":p.relative_to(out).as_posix(),"size":len(b),"sha256":hashlib.sha256(b).hexdigest()})
(out/'DERIVATION_SUMMARY.json').write_text(json.dumps({
 "schema":"TSUCHIMARU_GATEQ_KCONFIG_DERIVATION_V1",
 "status":"DERIVATION_COMPLETE_NOT_BUILD_AUTHORIZATION",
 "source_commit":os.environ['SOURCE_COMMIT'],
 "source_tree":os.environ['SOURCE_TREE'],
 "k0_config_sha256":os.environ['K0_CONFIG_SHA256'],
 "qualified_final_config_sha256":os.environ['QUALIFIED_FINAL_CONFIG_SHA256'],
 "member_count_excluding_manifest_and_summary":len(files),
 "files":files,
 "authorization":{
   "kconfig_derivation_only":True,
   "kernel_compile":False,
   "bzimage":False,
   "wsl":False,
   "wslconfig":False,
   "custom_kernel_activation":False,
   "host_activation":False,
   "gate_a":False,
   "runtime":False
 }
},indent=2,sort_keys=True)+"\n")
PY

(
  cd "$OUT"
  find . -type f ! -name FILES.sha256 -print0 | sort -z | xargs -0 sha256sum
) > "$OUT/FILES.sha256"

sha256sum   "$OUT/K0_BASELINE.config"   "$OUT/K1_FINAL.config"   "$OUT/TARGET_QUALIFIED_REPLAY.config"   "$OUT/K2_REMAINING_SET_R.json"   "$OUT/K2_PROGRESSION_TREE.json"
