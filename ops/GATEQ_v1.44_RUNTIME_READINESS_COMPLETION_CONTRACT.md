# Gate Q v1.44 — Runtime Readiness Completion Contract

Status: ACTIVE PREPARATION CONTRACT  
Risk: HIGH  
Current qualification: **Fresh Independent Static Audit PASS — STATIC ONLY**  
Gate Q: **HOLD / NOT LOCKED**

## Objective

Complete every low-risk/read-only preparation step for Gate Q v1.44 Runtime Qualification, then stop only at the first true Human Owner Gate.

Do **not** re-audit v1.44 unless new bytes, new evidence, or a new substantive finding appears.

## Frozen identities

- Candidate ZIP SHA-256: `8AC30EB6D1F280FCC8AE7AFC159A12833B45655F3809F5AEB97A6644434EF3BD`
- Controller SHA-256: `C5B06C5DAD120D65DAD5A933DF122B015DF1646369FCA31542BE56B3D7BA37B5`
- Manifest SHA-256: `A273792F549F76596568AA0A38C3D4C19117F9B11AFBACEAE1D3A47B5F958A14`
- Fresh Audit Packet SHA-256: `FE166875407CFA605E0D074E450F362E326D18A63A93DB13929F73FA12CDA2B6`
- Complete Audit Bundle SHA-256: `DACA01B49FBA41813616F49D6994CDDCAF05456AD6023D5D18B156B7888ACCA9`

Frozen Runtime paths:

- `execution_root = C:\GateQ\v1.42\ExecutionRoot`
- `used_record_ledger = C:\GateQ\v1.42\Replay\gateq-v1.42.ledger`

Public trust anchor:

- CER SHA-256: `729B541F49C5C9A762BBF988E5642E3E290B4D407F19D2A2A8A051186F1D726F`
- Thumbprint: `455C20DCD8DEB26DC342B932DC722EFC26DA4E1D`
- Subject: `CN=Tsuchimaru AI Command Center Human Owner Runtime Authorization`

## Done when

- [ ] Candidate / Controller / Manifest hashes equal the frozen identities.
- [ ] Candidate package binding and controller three-way binding remain intact.
- [ ] Public trust-anchor identity is readable and matches the frozen public certificate; no private-key access occurs.
- [ ] `C:\GateQ\v1.42\ExecutionRoot` live read-only revalidation PASS.
- [ ] `C:\GateQ\v1.42\Replay` live read-only revalidation PASS.
- [ ] Full ancestry validation PASS.
- [ ] Replay ledger is absent.
- [ ] Ledger lock is absent.
- [ ] Replay tmp is absent.
- [ ] Qualification child is absent.
- [ ] Signed-path / CLI mapping for v1.44 is resolved and frozen.
- [ ] Exact signing and Runtime command inputs are staged without generating a live authorization.
- [ ] No five-minute authorization has been created yet.
- [ ] PROJECT_STATE still reflects v1.44 static PASS and the next Human Gate.
- [ ] Final result is either `READY FOR HUMAN OWNER SIGNING GATE` or a concrete fail-closed blocker.

## Allowed actions

- Read files and hashes.
- Inspect Candidate/Manifest/controller/package bindings.
- Inspect the public trust anchor only.
- Read filesystem type, path identity, owner, ACL, reparse state and ancestry.
- Check absence/presence of ledger/lock/tmp/qualification child.
- Run machine preflight and deterministic regressions that do not mutate Runtime state.
- Prepare non-live templates, exact commands, evidence paths and signing/Runtime handoff material.
- Correct low-risk preparation-document mistakes and rerun deterministic preflight.

## Forbidden actions

- Rebuilding or re-auditing v1.44 without new evidence/change.
- Accessing the private key.
- Exporting key material.
- Creating detached CMS.
- Generating a live five-minute authorization.
- Executing the Runtime controller entry point.
- Creating or modifying Replay Ledger / lock / tmp / qualification child.
- Modifying `C:\GateQ` ACLs or owners.
- Modifying `C:\` ACLs or owners.
- WSL or `.wslconfig` changes.
- Gate Q LOCK.
- Gate A.
- Stage 0B Runtime.
- Production.

## Required execution order

1. **Machine preflight** — frozen hash/package/public-cert checks.
2. **Live read-only Windows preflight** — exact frozen paths, filesystem, owner/ACL, ancestry, no Runtime artifacts.
3. **Invocation staging** — resolve exact v1.44 controller/Candidate inputs and frozen CLI paths.
4. **Authorization staging** — prepare schema-shaped non-live material only; do not generate timestamps/nonce/record_id intended for live use.
5. **Final readiness check** — confirm the next operation requiring Human Owner approval is private-key use / exact-byte signing.
6. **STOP** with `READY FOR HUMAN OWNER SIGNING GATE`.

The five-minute authorization must be generated only after the Human Owner is ready to approve signing and Runtime can follow immediately. This avoids consuming the validity window during preparation.

## Stop conditions

Stop before the normal end only if:

1. a true Human Gate is reached;
2. permissions are insufficient;
3. specifications conflict;
4. a major unknown cannot be resolved from evidence;
5. a frozen identity/path differs.

Any identity/path/security mismatch is fail-closed and must not be auto-remediated by changing the frozen Candidate or provisioned paths.

## Evidence required

Report:

- Candidate / Controller / Manifest identity results
- public trust-anchor result
- ExecutionRoot and Replay parent live read-only results
- ancestry result
- ledger / lock / tmp / qualification-child absence
- exact staged CLI path values
- confirmation that private key was not accessed
- confirmation that no live authorization was generated
- confirmation that Runtime was not executed
- any remaining blocker

## Output summary

Return only:

1. what preparation completed;
2. automatically corrected low-risk preparation issues, if any;
3. remaining blocker, if any;
4. exact next Human Owner decision.

Expected successful terminal state:

`READY FOR HUMAN OWNER SIGNING GATE`
