# FRESH INDEPENDENT STATIC RE-AUDIT — GATE Q KERNEL COMPATIBILITY v0.7

You are a Fresh Independent Static Auditor separate from the author/remediation lane.

READ-ONLY / STATIC ONLY. Gate Q remains HOLD. Do not execute kernel build, bzImage, WSL, wsl --shutdown, .wslconfig changes, custom-kernel activation, Docker workloads, PostgreSQL, SQL/migration, ACL/xattr mutation, Host Activation, Gate A or Runtime.

## Package
Verify outer ZIP sidecar SHA-256, safe paths/no duplicates, ZIP CRC, FILES.sha256 complete coverage, and INPUT_BINDING_V07.json.

## Corrected K1 derivation
1. Verify exact source commit 14794180686c2fb6307fbe359c359bec765249f3 and tree 3b5ec33f7fd60f23d01064150f7c7020d2e6af99.
2. Recompute exact baseline raw CONFIG_*=m count with case-complete Kconfig symbol syntax: expected 760.
3. Recompute the v0.6 uppercase-only [A-Z0-9_] count: expected 752.
4. Verify the exact eight missed symbols in V06_REGEX_GAP_REMEDIATION.json.
5. Verify K1_TRANSFORM_MANIFEST_V07.json: 760 m->y promotions plus CONFIG_MODULES y->n, total 761 direct changes.
6. Verify corrected pre SHA-256 a8395a7dd589801a7c45ec2d42699ec55a64ea19e3ba8f8f3849820ccdff7f5c.
7. Verify corrected post/final SHA-256 7415e92062b1fe82232e50e2d483f955c4fd80a3794e1a39191a7dc12d00f405, post==final bytes, final module entries=0, and final equals historical v0.6 final.
8. Verify olddefconfig fixed point and zero kernel outputs.
9. Recompute corrected pre/post semantic delta count 72 with [A-Za-z0-9_]. Confirm the eight formerly missed Mediatek symbols are not dependency deltas in corrected v0.7.

## K1 source attribution/status
1. Verify corrected 72-symbol delta set equals K1_DELTA_DECISIONS_V07.json.
2. Verify 48/48 former pending deltas against exact source and group totals 20+2+6+20.
3. Verify zero pending decisions.
4. Verify authoritative K1 status is consistent with baseline 760, final 0, 72 deltas, fixed point, and zero kernel outputs.

## K2
1. Recompute R from corrected K1 final versus QUALIFIED_HARDENING_REFERENCE.config; expected 92.
2. Compute direct roots as R intersect target-policy mandatory assertions where K1 differs from target.
3. Expected root set: CONFIG_KEXEC_FILE, CONFIG_KPROBES, CONFIG_BPF_SYSCALL, CONFIG_SECURITY.
4. Verify 4 roots / 88 nonroots / PAHOLE 3 environment-only.
5. Verify one root per planned stage, no direct nonroot mutation, and explicit supersession of the v0.6 92-symbol plan.

PASS requires CRITICAL=0 and MAJOR=0 plus all package/K1/K2 checks above.

A static PASS does not authorize any build/runtime operation.
