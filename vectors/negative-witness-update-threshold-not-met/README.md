# negative-witness-update-threshold-not-met

**Spec rule:** A witness list change takes effect only after its entry is published,
so the *previous* witness list governs that entry.
**Expected error:** `invalidDid`

## Scenario

A DID is created with a 2-of-2 witness configuration (wit-0 and wit-1).
An update entry reduces this to 1-of-1 (wit-0 only).

The `did-witness.json` contains:

- Version 1: proofs from both wit-0 and wit-1 — threshold met ✅
- Version 2: proof from wit-0 **only** — wit-1 is missing ❌

## Why this must be rejected

When the update entry changes the witness list, the *previous* list (2-of-2) governs
approval of that entry. The new list (1-of-1) does not take effect until after the
entry is committed. Only wit-0 has approved the update, leaving the threshold of 2
unmet. A conforming resolver must reject the log as `invalidDid`.

## Relationship to `witness-update` positive vector

The `vectors/witness-update/` positive scenario uses the same keys, domain, timestamps,
and witness configuration. The difference is in `did-witness.json`: the positive vector
provides both witnesses' approvals for the update entry (correct); this negative vector
provides only one (incorrect).

## Implementation status

| Implementation | Expected | Notes |
|---|---|---|
| TypeScript | FAIL → PASS | Fixed by `aviarytech/didwebvh-ts` PR `fix/witness-spec-conformance` |
| Python | TBD | |
| Rust | TBD | |
| Java | TBD | |
| Java-EECC | TBD | |
