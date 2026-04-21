# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repo provides language-agnostic compliance test vectors for the [`did:webvh` specification](https://identity.foundation/didwebvh/v1.0/). It targets v1.0 of the spec.

The approach is a **DSL + committed artifacts** pattern:

1. Human-readable YAML scripts in `scripts/` describe the intent of each test scenario (which keys to use, which operations to perform, which options to activate).
2. A TypeScript generator reads those scripts and produces canonical signed artifacts — a `did.jsonl` log file and a `resolutionResult.json` — which are committed to `vectors/`.
3. Implementations import the committed artifacts and verify they can produce/resolve them correctly. No crypto is required on the consumer side — only the generator needs to sign.

## Repository Structure

```
scripts/           # YAML DSL scripts describing test scenarios
vectors/           # Committed, pre-generated artifacts (do not edit by hand)
  <scenario-name>/
    script.yaml        # copy of the source script (for auditability)
    did.jsonl          # the full DID log
    resolutionResult.json  # expected output of resolveDID at HEAD
    resolutionResult.<versionId>.json  # expected output at a specific version (optional)
implementations/
  ts/src/          # TypeScript generator (reference implementation)
    generator.ts   # reads scripts/, writes vectors/
    cryptography.ts  # deterministic Ed25519 signing from seed
    interfaces.ts  # types shared between generator and scripts
  python/          # Python compliance harness (pytest)
  rust/            # Rust compliance harness (cargo)
package.json
```

## Commands

```bash
# Install dependencies
bun install

# Regenerate all vectors from scripts
bun run generate

# Regenerate a single vector
bun run generate scripts/basic-create.yaml

# Verify committed vectors match what the generator would produce (CI check)
bun run verify
```

## DSL Script Format

Each script is a YAML file. Example:

```yaml
description: "Create a DID and resolve at genesis"
spec_ref: "https://identity.foundation/didwebvh/v1.0/#creating-a-did"

keys:
  - id: key-0
    type: ed25519
    # 32-byte hex seed — deterministic, never random
    seed: "0000000000000000000000000000000000000000000000000000000000000001"

steps:
  - op: create
    domain: example.com
    signer: key-0
    params:
      updateKeys: ["key-0"]

  - op: resolve
    # omitting 'versionId' means resolve at HEAD
    expect: resolutionResult.json
```

### Supported `op` values

| op | description |
|---|---|
| `create` | Create the DID log (first entry) |
| `update` | Append an update entry |
| `deactivate` | Append a deactivation entry |
| `resolve` | Assert resolution output matches the named `expect` file |

### Supported `params` (on `create` / `update`)

These map directly to did:webvh DID log entry parameters:

| param | type | notes |
|---|---|---|
| `updateKeys` | string[] | multikey identifiers of keys authorised for future updates |
| `nextKeyHashes` | string[] | pre-rotated key hashes (pre-rotation) |
| `witness` | object | `{threshold, witnesses:[{id,weight}]}` |
| `portable` | boolean | whether the DID is portable |
| `context` | string[] | additional `@context` entries |
| `alsoKnownAs` | string[] | `alsoKnownAs` entries |
| `services` | object[] | service endpoint entries |
| `verificationMethods` | object[] | additional verification methods |

### Key types supported

- `ed25519` — seeded with a 32-byte hex `seed`

Additional key types (e.g. `mldsa44`) may be added later as experimental extensions.

## Artifact Format

### `did.jsonl`

A newline-delimited JSON file. Each line is a complete DID log entry as defined by the did:webvh v1.0 spec. The file is the minimal valid input to any conforming resolver.

### `resolutionResult.json`

Follows the [DID Resolution](https://w3c-ccg.github.io/did-resolution/) response envelope:

```json
{
  "didDocument": { ... },
  "didDocumentMetadata": { ... },
  "didResolutionMetadata": { "contentType": "application/did+ld+json" }
}
```

## Adding a New Test Vector

1. Create `scripts/<scenario-name>.yaml` following the DSL format above.
2. Run `bun run generate scripts/<scenario-name>.yaml`.
3. Inspect the generated files in `vectors/<scenario-name>/`.
4. Commit both the script and the generated artifacts together.

## Scenario Coverage Goals

Happy-path scenarios (initially):

- `basic-create` — minimal create + resolve
- `basic-update` — create + single update + resolve
- `key-rotation` — create + update rotating the update key
- `pre-rotation` — create with `nextKeyHashes`, update consuming the pre-rotation
- `deactivate` — create + deactivate + resolve (deactivated state)
- `portable` — create with `portable: true`
- `witness-threshold` — create with a witness list, simulate witness proofs
- `multi-update` — create + several sequential updates, resolve at each version
- `services` — create with service endpoints, update adding/removing a service

Negative / error cases are out of scope for this repo — those are per-implementation unit tests. This repo only commits valid, resolvable logs.

## How Implementations Should Use This Repo

Consume the `vectors/` directory as a **git submodule** pinned to a specific commit. This ensures reproducibility: the exact set of vectors tested against is part of the implementation's git history.

```bash
# Add as submodule (run once in the implementation repo)
git submodule add https://github.com/decentralized-identity/didwebvh-test-suite vectors/compliance

# Update to latest vectors
git submodule update --remote vectors/compliance
```

Each implementation then writes a thin test harness that:
1. Walks `vectors/compliance/vectors/*/`
2. Calls its own `resolveDID(log)` on the `did.jsonl` in each directory
3. Compares the result to the corresponding `resolutionResult*.json`

## Future Work

### Negative / Error Test Vectors

The current DSL only produces valid, resolvable logs. Adding negative test coverage requires care because hand-editing a log entry invalidates its proof — implementations then reject on "bad signature" before reaching the semantic check under test.

The right approach is a `corrupt` DSL step that runs **before** signing, so the generator produces a valid proof over semantically broken content:

```yaml
- op: corrupt
  entry: 1
  mutation: replace-scid   # applied before signing → valid proof, bad SCID
  value: "QmWRONG000"
  when: before-sign

- op: resolve
  expectError: invalidDid
```

For proof-integrity tests (tampered entry, missing proof), `when: after-sign` corrupts the already-signed entry instead.

| Error category | `when` | Example mutation |
|---|---|---|
| SCID mismatch | before-sign | replace SCID placeholder |
| Broken hash chain | before-sign | replace `versionId` hash |
| Key not in `nextKeyHashes` | before-sign | wrong `updateKeys` on pre-rotation consume |
| Tampered entry | after-sign | flip a byte in the state |
| Wrong signing key | N/A | use `signer: unauthorized-key` |
| Missing proof | after-sign | delete proof field |

The `resolve` step would need an `expectError` field (instead of `expect`) naming the DID resolution error code. Invalid vectors would live alongside valid ones in `vectors/` or in a parallel `invalid-vectors/` tree.

The generator already holds all private keys, so signing broken content is fully feasible — this is the key advantage over hand-editing.

### Cross-Language Error Vectors

`implementations/python/test-suite/` contains hand-authored invalid logs (`invalid-json`, `invalid-method`, `invalid-scid`, `missing-proof`, `missing-witness`) and a `resolver-suite.json` test manifest. These are currently consumed only by the Python harness (`test_resolver_suite.py`).

To make them usable by the TS and Rust harnesses, three things are needed:

1. **Error-case `resolutionResult.json`** — extend the format to express failure:
   ```json
   { "didResolutionMetadata": { "error": "invalidDid" }, "didDocument": null }
   ```
2. **versionId/versionNumber parameterization** — the old suite tests resolution at specific versions (and conflict cases like `?versionNumber=1&versionId=2-...`). The Rust harness currently keys only on version number via filename (`resolutionResult.2.json`); exact versionId and conflict cases need a mechanism.
3. **Witness sidecar** — two scenarios include a `did-witness.json` sidecar; harnesses would need to look for it.

This groundwork is the same foundation needed for the `corrupt`-step approach above — the two efforts can be combined.

## Generator Design Notes

- Keys are always derived deterministically from the `seed` field — the generator never calls `crypto.getRandomValues()`. This guarantees that running the generator twice on the same script produces bit-for-bit identical artifacts.
- The generator imports the same `createDID` / `updateDID` / `deactivateDID` / `resolveDID` functions from the `didwebvh-ts` library (or a pinned version of it). It is intentionally thin — it only handles key management and script parsing; all DID logic lives in the library.
- Because artifacts are committed, a PR that changes the generator or the library and also changes the committed artifacts is self-documenting: the diff shows exactly what changed in the generated output.
