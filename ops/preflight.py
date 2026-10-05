#!/usr/bin/env python3
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "ops" / "states"
REGISTRY = ROOT / "ops" / "regression" / "KNOWN_FINDINGS.json"

REQUIRED = {
    "version","project_id","display_name","as_of","risk_tier","current_stage","status",
    "canonical","locked","last_pass","open_findings","next_action",
    "human_approval_required","audit_mode","model_route","source_of_truth","migration_note"
}
VALID_RISK = {"LOW","MEDIUM","HIGH"}

errors = []
seen_ids = set()

for path in sorted(STATE_DIR.glob("*.json")):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"{path}: invalid JSON: {e}")
        continue

    missing = sorted(REQUIRED - data.keys())
    if missing:
        errors.append(f"{path}: missing required keys: {missing}")

    pid = data.get("project_id")
    if not isinstance(pid, str) or not pid:
        errors.append(f"{path}: project_id must be a non-empty string")
    elif pid in seen_ids:
        errors.append(f"{path}: duplicate project_id: {pid}")
    else:
        seen_ids.add(pid)

    risk = data.get("risk_tier")
    if risk not in VALID_RISK:
        errors.append(f"{path}: invalid risk_tier: {risk}")

    if risk == "HIGH" and data.get("human_approval_required") is not True:
        errors.append(f"{path}: HIGH risk must require Human approval")

    if data.get("locked") is True and not data.get("lock_ref"):
        errors.append(f"{path}: locked=true requires lock_ref")

    actions = data.get("next_action")
    if not isinstance(actions, list) or not actions or not all(isinstance(x,str) and x.strip() for x in actions):
        errors.append(f"{path}: next_action must be a non-empty list of strings")

    route = data.get("model_route")
    if not isinstance(route, dict) or not {"routine","analysis","final_gate"} <= set(route):
        errors.append(f"{path}: model_route requires routine/analysis/final_gate")

    sots = data.get("source_of_truth")
    if not isinstance(sots, list) or not sots:
        errors.append(f"{path}: source_of_truth must be non-empty")

try:
    reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
    findings = reg.get("findings", [])
    ids = [x.get("id") for x in findings if isinstance(x, dict)]
    real_ids = [x for x in ids if x]
    if len(real_ids) != len(set(real_ids)):
        errors.append(f"{REGISTRY}: duplicate regression finding IDs")
except Exception as e:
    errors.append(f"{REGISTRY}: invalid registry JSON: {e}")

if errors:
    print("OPS PREFLIGHT: FAIL")
    for e in errors:
        print(f"- {e}")
    sys.exit(1)

print(f"OPS PREFLIGHT: PASS ({len(seen_ids)} project states checked)")
