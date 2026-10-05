# Gate Q v1.44 — Executor Context Remediation Human Gate

Status: AWAITING HUMAN OWNER DECISION  
Finding: `MAJOR-RT-CHILD-CREATE-ACCESS-01`  
Root cause: `WINDOWS_EFFECTIVE_ACCESS_BLOCKER`

## Proven cause

The frozen v1.44 controller and static ACL policy are not the blocker.

The actual Codex Runtime executor used a restricted `workspace-write` token. Its writable roots excluded:

- `C:\GateQ\v1.42\ExecutionRoot`
- `C:\GateQ\v1.42\Replay`

Read-only effective-access testing against the existing ExecutionRoot returned:

- Win32: `5`
- HRESULT: `0x80070005`

The current user SID has an explicit Full Control ACE in the frozen DACL, but the restricted token's restricting SID set does not satisfy that Allow ACE. Therefore the actual Runtime process cannot create the qualification child.

No ACL repair is indicated.

## Proposed minimal remediation

Permit a new executor/sandbox context for the frozen v1.44 Runtime Qualification whose additional writable scope is limited to exactly:

- `C:\GateQ\v1.42\ExecutionRoot`
- `C:\GateQ\v1.42\Replay`

Do not authorize a general unrestricted filesystem context.

Do not authorize ACL/owner changes.

Do not authorize Administrator elevation merely to bypass this blocker.

If the execution system cannot express these exact writable roots without a materially broader permission expansion, STOP and return the supported permission alternatives for Human Owner review.

## Human Owner approval covers only

1. changing the executor/sandbox writable-root context so the two frozen Runtime paths above are writable;
2. restarting/relaunching the local Codex execution context if required for that scoped configuration to take effect;
3. read-only verification of the new token/context and effective access after the change.

## Not authorized by this gate

- private-key access
- signing
- live authorization generation
- Runtime Qualification execution
- Replay Ledger commit
- test child creation
- ACL/owner changes
- Defender/CFA changes
- unrestricted sandbox disable
- Administrator elevation
- Candidate/controller modification
- Gate Q LOCK
- WSL/.wslconfig
- Gate A
- Stage 0B
- Production

## Required result after approved context change

Before any new signing/runtime authorization, report:

- executor/sandbox mode
- exact writable roots
- process user SID
- restricted-token status
- integrity level
- effective access result for child creation on ExecutionRoot
- effective access result for controller-required Replay writes
- ExecutionRoot / Replay owner and DACL unchanged
- ledger / lock / tmp / qualification child absent
- filesystem mutations during verification: NONE

Successful terminal state:

`EXECUTOR CONTEXT READY — RETURN TO READINESS / SIGNING FLOW`

A new live authorization must be generated later. The expired/consumed authorization record:

`GQv144-c50877e336da4668ad9dcf1f078b5c35`

must never be reused.
