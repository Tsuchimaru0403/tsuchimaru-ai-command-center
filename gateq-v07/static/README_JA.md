# Gate Q Kernel Compatibility Re-Qualification v0.7 candidate

Static remediation candidate.

v0.7 corrects a v0.6 case-sensitive regex gap: the exact baseline has 760 CONFIG_*=m entries, while v0.6 matched only 752 and missed eight valid lowercase-x Kconfig symbols.

The corrected config-only derivation:
- promotes all 760 module selections to builtin before normalization,
- sets CONFIG_MODULES=n,
- reaches fixed point,
- leaves zero module entries,
- produces the same K1 final hash as v0.6,
- has 72 corrected pre/post semantic deltas.

K1 former source-attribution gaps are closed. K2 is redesigned as four direct policy roots with 88 observation-only nonroots.

No K2 stage or kernel build is executed. Gate Q remains HOLD.
