# GATE Q v1.45 — FRESH INDEPENDENT STATIC AUDIT CONTRACT

Status: READY FOR FRESH INDEPENDENT STATIC AUDIT  
Risk: HIGH  
Scope: STATIC ONLY  
Gate Q: HOLD / NOT LOCKED

## Frozen v1.45 identities

- Candidate ZIP SHA-256: `7F618AC23500B8D6618C80188575D7D872F70A713E046C0D2A3016804FD16178`
- Controller SHA-256: `33B42F4ABC5F4FC331070ADE36D4E87E54222CCF4686889D5830CDB9A069B57D`
- Manifest SHA-256: `5584B6D3193C3BCB3A3B929E065A01392CB7B87C3545A13EA21EC51620D299EB`
- Fresh Audit Packet SHA-256: `9FDC9D6BB41C7C7CA2350BAA8573B2285C32F94CD42D8519CA62BAC2103E4BC7`
- Complete Audit Bundle SHA-256: `75ACE37C1A231EB5D7650F1276CDD11DDFA91460865554C94A6AB03EAD0B0F68`

Frozen Runtime paths remain:

- `C:\GateQ\v1.42\ExecutionRoot`
- `C:\GateQ\v1.42\Replay\gateq-v1.42.ledger`

## Historical facts that must remain failures/history

- v1.44 Fresh Independent Static Audit: PASS — STATIC ONLY.
- v1.44 Runtime Qualification: FAIL-CLOSED.
- v1.44 runtime compatibility defect: legacy seven-argument `FileStream` constructor unavailable in PowerShell 7.6.6 / current .NET.
- v1.44 Replay Ledger was not committed; no surviving child/lock/tmp.
- Codex workspace-write executor path was rejected for Runtime because its sandbox mechanism introduced extra DACL ACEs; the approved Runtime execution path is normal non-admin PowerShell, not the Gate Q writable-root Codex profile.

Do not rewrite these historical failures as passes.

## Primary Fresh Audit objective

Independently determine whether the frozen v1.45 Candidate is statically eligible for the next Runtime-readiness stage.

Do not accept author conclusions without independently checking the actual bytes/evidence.

## Mandatory audit input gate

Before semantic review:

1. Read Candidate ZIP, Fresh Audit Packet, Complete Audit Bundle.
2. Recompute all five frozen hashes above.
3. Open Candidate and reconcile complete member inventory.
4. Open/read loose or extracted Controller and Manifest.
5. Locate machine-preflight report, author build report, packaging receipt, source diff, fixtures, and Human Owner PS7.6.6 evidence JSON/log.

If required artifacts cannot be read, report input/evidence failure. Do not score implementation defects from missing evidence.

## Mandatory independent checks

### A. v1.45 package and identity

- Candidate archive inventory has no duplicates/unexpected private-key material.
- Manifest path/size/SHA-256 rows reconcile to Candidate members.
- Controller actual bytes == Manifest controller row == frozen Controller identity.
- Manifest identity == frozen Manifest identity.
- Candidate identity == frozen Candidate identity.
- Audit packet and complete bundle hashes match frozen values.

### B. MAJOR-RT-FILESTREAM-NET-COMPAT-01

Independently inspect actual v1.45 production code.

Require:

- no legacy seven-argument `[IO.FileStream]::new(... FileSystemRights ... FileSecurity)` production call;
- replacement API/overload exists in the supported current .NET surface;
- production helper preserves:
  - `FileMode.CreateNew`
  - `FileSystemRights.FullControl`
  - `FileShare.None`
  - buffer size 4096
  - `FileOptions.WriteThrough`
  - supplied `FileSecurity`
  - security applied at creation, not in a post-create ACL window;
- duplicate path remains fail-closed;
- stream lifecycle/flush/dispose semantics remain correct.

Independently classify whether v1.44→v1.45 diff is minimal and contains no unrelated security-semantic changes.

### C. Human Owner PowerShell 7.6.6 evidence

Independently inspect both JSON and log evidence.

Require evidence for:

- PowerShell 7.6.6
- .NET 10.0.12
- non-elevated execution
- Candidate/Controller/Manifest frozen hash equality
- production controller AST parse
- legacy seven-argument constructor absent
- replacement overload reflection
- actual production helper execution
- create-time FileSecurity / protected DACL / expected 3 ACE
- WriteThrough and stream lifecycle
- duplicate CreateNew fail-closed
- OS-temp-only test artifact
- cleanup complete

Treat this as runtime-environment machine-preflight evidence, not as live Gate Q Runtime Qualification.

### D. Regression suite

Inspect and classify all 15 fixtures. Do not merely count exit codes.

Require preservation of prior invariants, including:

- null-sentinel regression
- exact frozen runtime path pinning
- authorization/schema invariants
- public trust-anchor invariants
- filesystem/ACL/ancestor invariants
- replay lifecycle/marker invariants
- qualification-child invariants
- Manifest/package bindings
- Runtime-prefix dry validation
- new current-.NET runtime compatibility regression

State which fixtures execute production functions versus source assertions/local models.

### E. Existing v1.44 security semantics retained

Verify v1.45 did not broaden or change:

- authorization scope/lifetime/replay policy
- trust anchor
- exact Runtime paths
- ACL/owner contract
- ancestor/reparse contract
- Replay Ledger semantics
- qualification child cleanup semantics
- Gate Q / Gate A / Stage 0B / Production boundaries

### F. Runtime execution path policy

Confirm audit artifacts/documentation do not instruct use of the Gate Q `workspace-write` Codex profile for live Runtime.

The later live Runtime path must remain normal non-admin PowerShell with read-only readiness/effective-access checks before signing.

### G. Precheck wrapper/process regression

If v1.45 artifacts include the process regression introduced after the v1.44 attempts, independently verify:

- machine-readable evidence/staged values are used instead of manually copied SHA literals where intended;
- precheck + invocation are one fail-closed flow;
- a failed precheck cannot be followed accidentally by Runtime invocation inside the same wrapper;
- no live authorization/signing/runtime is performed during this static audit.

If this regression is absent from the frozen artifacts, report that fact accurately rather than inventing it.

## Static mutation boundary

During this Fresh Audit:

- no private-key access
- no authorization generation
- no CMS signing
- no Runtime controller entrypoint
- no Replay Ledger/lock/tmp/qualification-child creation
- no ACL/owner change
- no Gate Q LOCK
- no WSL/.wslconfig
- no Gate A
- no Stage 0B
- no Production

Safe OS-temp-only execution of packaged static fixtures is allowed only if it is explicitly designed as non-GateQ test evidence and does not touch `C:\GateQ`.

## Severity

Report:

- CRITICAL
- MAJOR
- MINOR
- NOTE

Any security-boundary, identity, authorization, path-pin, replay, ACL, package-binding, or current-.NET compatibility defect that can block or invalidate Runtime qualification is at least MAJOR.

## Required final report

# FRESH INDEPENDENT STATIC AUDIT — GATE Q v1.45

Overall:
`PASS — STATIC ONLY` | `FAIL`

CRITICAL: n  
MAJOR: n  
MINOR: n  
NOTE: n

Audit input access: PASS/FAIL  
Artifact transfer integrity: PASS/FAIL

Candidate SHA-256: <actual>  
Controller SHA-256: <actual>  
Manifest SHA-256: <actual>  
Fresh Audit Packet SHA-256: <actual>  
Complete Audit Bundle SHA-256: <actual>

Candidate identity: PASS/FAIL  
Controller identity: PASS/FAIL  
Manifest identity: PASS/FAIL  
Controller three-way binding: PASS/FAIL  
Candidate member/hash binding: PASS/FAIL

MAJOR-RT-FILESTREAM-NET-COMPAT-01: CLOSED/OPEN  
PowerShell 7.6.6 evidence: PASS/FAIL  
15/15 fixtures independently acceptable: PASS/FAIL

Null-sentinel regression: PASS/FAIL  
Frozen path pin: PASS/FAIL  
Authorization invariants: PASS/FAIL  
Trust-anchor invariants: PASS/FAIL  
Filesystem/ACL/ancestry invariants: PASS/FAIL  
Replay invariants: PASS/FAIL  
Qualification-child invariants: PASS/FAIL  
Runtime execution-path policy: PASS/FAIL

Private key material present: NO/YES  
Runtime executed: NO/YES  
Replay Ledger modified: NO/YES  
Signing performed: NO/YES  
Gate Q locked: NO/YES

Findings:
<none or detailed findings>

Final state:

If clean:
`STATIC QUALIFICATION PASS — AWAITING NEXT-STAGE READINESS`

Otherwise:
`STATIC QUALIFICATION FAIL — REMEDIATION REQUIRED`

A PASS authorizes only the next read-only Runtime-readiness stage. It does not authorize signing, Runtime Qualification, Gate Q LOCK, Gate A, Stage 0B, WSL changes, or Production.
