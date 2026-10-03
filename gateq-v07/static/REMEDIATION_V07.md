# REMEDIATION_V07

## v0.6 regex-gap closure

- Exact raw baseline CONFIG_*=m: 760
- v0.6 uppercase-only regex matched: 752
- Missed: 8 lowercase-x Mediatek symbols
- Corrected pre SHA-256: a8395a7dd589801a7c45ec2d42699ec55a64ea19e3ba8f8f3849820ccdff7f5c
- Corrected final SHA-256: 7415e92062b1fe82232e50e2d483f955c4fd80a3794e1a39191a7dc12d00f405
- Corrected final equals v0.6 final: true
- Corrected pre/post semantic delta: 72
- Final module entries: 0
- Fixed point: true
- Kernel outputs: none

## K1 attribution/status

The corrected 72-symbol delta set equals the prior 72-symbol decision set. The 48 formerly pending source attributions are closed against the exact source commit. All 72 decisions are closed. The stale v0.6 K1 status is historical only.

## K2

R is recomputed from corrected K1 final versus the qualified hardening reference and must equal 92.

Direct roots from target-policy mandatory assertions:
1. CONFIG_KEXEC_FILE=n
2. CONFIG_KPROBES=n
3. CONFIG_BPF_SYSCALL=n
4. CONFIG_SECURITY=n

The other 88 symbols are observation-only. The three PAHOLE symbols are environment-only. The v0.6 92-symbol direct-mutation plan is superseded.

## Boundary

Gate Q = HOLD. K0/K1/K2 kernel build, WSL/custom-kernel activation, Host Activation, Gate A and Runtime remain unauthorized.
