# Gate Q v1.44 — Dedicated Executor Profile Human Gate

Status: EXECUTOR CONTEXT CHANGE NOT APPLIED — AWAITING HUMAN ACTION  
Finding: `MAJOR-RT-CHILD-CREATE-ACCESS-01`  
Root cause: `WINDOWS_EFFECTIVE_ACCESS_BLOCKER`  
Static status: `v1.44 Fresh Independent Static Audit PASS — STATIC ONLY; PRESERVED`  
Runtime status: `FAIL-CLOSED`

## Current state

The single authorized v1.44 Runtime Qualification attempt stopped at qualification-child creation with access denied. Read-only diagnostics proved that the current Codex `workspace-write` restricted token lacks effective child-create access to the frozen ExecutionRoot. The read-only handle check returned Win32 error `5` / HRESULT `0x80070005`.

The current desktop executor cannot change its writable roots or relaunch itself into a new profile. No executor-context change has been applied. The Human Gate remains pending until a Human Owner launches a new Codex executor with the narrowly scoped profile below.

The static ACL policy passed, and no ACL or owner repair is indicated. v1.44 Candidate, Controller, Manifest, Runtime paths, and existing ACLs/owners remain frozen. No Replay Ledger commit occurred. Gate Q remains NOT LOCKED.

## Next Human action

Create or use a dedicated `workspace-write` profile that adds exactly these two writable roots, and launch a new Codex executor with that profile:

- `C:\GateQ\v1.42\ExecutionRoot`
- `C:\GateQ\v1.42\Replay`

These are the only additional writable roots authorized for this remediation.

Do not select `danger-full-access`, elevated/Administrator execution, broad `C:\` or `C:\GateQ` writable scopes, or make ACL/owner changes. If the profile cannot express exactly the two approved roots, stop and report the available alternatives for Human Owner review.

The existing desktop executor must not attempt to mutate its own configuration or relaunch itself; it cannot perform those actions from this session.

## New executor: read-only readiness only

After launching the new executor, perform read-only checks and report:

- executor/sandbox mode and exact writable roots
- process user SID, restricted-token status, and integrity level
- effective child-create access to the existing ExecutionRoot
- controller-required write access to the existing Replay directory
- ExecutionRoot and Replay owner, DACL, reparse status, and ancestry unchanged
- ledger, lock, tmp, and qualification child absent
- filesystem and ACL/owner mutations during verification: NONE

Do not create a test directory or child. Do not create or modify a ledger, lock, or tmp file.

If all checks pass, stop at:

`EXECUTOR CONTEXT READY — RETURN TO READINESS / SIGNING FLOW`

This status only returns the project to read-only readiness. It does not authorize live authorization generation, private-key access, signing, or Runtime Qualification execution.

## Explicitly prohibited

- unrestricted/full-access sandbox disable or broader writable scope
- elevated or Administrator execution
- ACL/owner changes, takeown, or permission grants
- Defender/CFA changes
- Candidate, Controller, Manifest, or frozen Runtime path changes
- test child or Replay Ledger/lock/tmp creation
- private-key access, authorization generation, or CMS signing
- Runtime Qualification execution or Replay Ledger commit
- Gate Q LOCK, WSL/.wslconfig changes, Gate A, Stage 0B, or Production

The expired and consumed authorization record:

`GQv144-c50877e336da4668ad9dcf1f078b5c35`

must never be reused. Any later signing and Runtime attempt requires separate Human Owner authorization at its respective gate.
