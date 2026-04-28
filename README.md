# didwebvh-test-suite

Language-agnostic compliance test vectors for the [`did:webvh` v1.0 specification](https://identity.foundation/didwebvh/v1.0/).

## Approach

**DSL + committed artifacts pattern:**

1. Human-readable YAML scripts in `scripts/` describe each test scenario (keys, operations, expected results).
2. A TypeScript generator reads those scripts and produces canonical signed artifacts — a `did.jsonl` log file and one or more `resolutionResult*.json` files — committed to `vectors/`.
3. Implementations consume the committed artifacts without needing to re-sign anything. Only the generator needs crypto.

Because artifacts are committed, a PR that changes the generator or the underlying library also diffs the generated output — making the impact of any change explicit.

## Repository Structure

```
scripts/           # YAML DSL scripts describing test scenarios
vectors/           # Committed, pre-generated artifacts (do not edit by hand)
  <scenario>/
    script.yaml            # copy of the source script (for auditability)
    did.jsonl              # the full DID log (newline-delimited JSON)
    resolutionResult.json  # expected resolution output at HEAD
    resolutionResult.<versionId>.json  # expected output at a specific version (optional)
implementations/
  ts/src/
    generator.ts   # reads scripts/, writes vectors/
    cryptography.ts  # deterministic Ed25519 signing from seed
    interfaces.ts    # TypeScript types for the YAML DSL
  python/          # Python compliance harness (pytest)
  rust/            # Rust compliance harness (cargo)
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

## Scenario Coverage

| Scenario | Description |
|---|---|
| `basic-create` | Minimal create + resolve at HEAD |
| `basic-update` | Create + single update + resolve |
| `key-rotation` | Create + update rotating the update key |
| `pre-rotation` | Create with `nextKeyHashes` commitment + resolve |
| `pre-rotation-consume` | Create with `nextKeyHashes`; update signed by the pre-rotated key |
| `deactivate` | Create + deactivate + resolve (deactivated state) |
| `portable` | Create with `portable: true` |
| `portable-move` | Create portable DID, update migrating to a new domain |
| `witness-threshold` | Create with a witness list + witness proofs |
| `witness-update` | Create with 2-of-2 witness config; update reducing to 1-of-1 |
| `multi-update` | Create + two updates, resolve at v1, v2, and HEAD |
| `multiple-update-keys` | Create with two `updateKeys`; update signed by the second key |
| `services` | Create with service endpoints, update adding a second service |

Negative / error cases are out of scope — those are per-implementation unit tests. This repo only commits valid, resolvable logs.

## DSL Script Format

### Top-level fields

| field | required | description |
|---|---|---|
| `description` | yes | Human-readable description of the scenario |
| `spec_ref` | no | URL to the relevant spec section |
| `keys` | yes | List of key definitions (see below) |
| `steps` | yes | Ordered list of operations to execute |

### `keys`

| field | description |
|---|---|
| `id` | Logical name used to reference the key in steps |
| `type` | Key algorithm — currently only `ed25519` |
| `seed` | 32-byte hex seed (left-padded with zeros if shorter). **Must be static** — keys are always derived deterministically from this seed so the generator never calls `crypto.getRandomValues()`, guaranteeing bit-for-bit identical output on every run. |

### Steps

Each step has an `op` field that determines its type.

#### `create`

Creates the first DID log entry.

| field | required | description |
|---|---|---|
| `domain` | yes | Domain for the DID (e.g. `example.com`) |
| `signer` | yes | Key ID to sign the entry with |
| `timestamp` | yes | ISO 8601 timestamp — must be static for reproducibility |
| `params` | no | DID log parameters (see below) |

#### `update`

Appends an update entry to the log.

| field | required | description |
|---|---|---|
| `signer` | yes | Key ID to sign the entry. Must be a current `updateKey`, or — when consuming a pre-rotation — a key whose hash appears in the previous entry's `nextKeyHashes`. |
| `timestamp` | yes | ISO 8601 timestamp — must be ≥ the previous entry's timestamp |
| `params` | no | DID log parameters (see below) |

#### `deactivate`

Appends a deactivation entry, permanently retiring the DID.

| field | required | description |
|---|---|---|
| `signer` | yes | Key ID to sign the entry |
| `timestamp` | yes | ISO 8601 timestamp |

#### `resolve`

Resolves the log and writes the result to `vectors/<scenario>/<expect>`. During `bun run verify` the regenerated result is compared against the committed file.

| field | required | description |
|---|---|---|
| `versionNumber` | no | Resolve at this version number (1-based). Omit to resolve at HEAD. |
| `versionId` | no | Resolve at this exact `versionId` string. Takes precedence over `versionNumber`. |
| `expect` | yes | Output filename (e.g. `resolutionResult.json`, `resolutionResult.1.json`) |

### `params` (on `create` and `update`)

| param | type | description |
|---|---|---|
| `updateKeys` | string[] | Key IDs authorised to sign future updates |
| `nextKeyHashes` | string[] | Key IDs whose public key hashes to commit for pre-rotation |
| `witness` | object | Witness configuration — see below |
| `portable` | boolean | Whether the DID is portable (allows domain migration) |
| `context` | string[] | Additional `@context` URIs to include in the DID document |
| `alsoKnownAs` | string[] | `alsoKnownAs` entries |
| `services` | object[] | Service endpoints — see below |
| `verificationMethods` | object[] | Additional verification methods — see below |

#### `witness`

```yaml
witness:
  threshold: 1        # minimum number of witness proofs required
  witnesses:
    - id: wit-0       # key ID from the keys section
      weight: 1       # optional, defaults to 1
```

#### `services`

```yaml
services:
  - id: "#linked-domain"
    type: "LinkedDomains"                    # string or array of strings
    serviceEndpoint: "https://example.com"   # string, array, or object
```

#### `verificationMethods`

```yaml
verificationMethods:
  - id: "#key-2"
    type: "Multikey"
    purpose: "assertionMethod"   # authentication | assertionMethod | keyAgreement | capabilityInvocation | capabilityDelegation
    publicKeyMultibase: "z..."   # if omitted, derived from the matching key in keys[]
```

### Minimal example

```yaml
description: "Create a DID and resolve at genesis"
spec_ref: "https://identity.foundation/didwebvh/v1.0/#creating-a-did"

keys:
  - id: key-0
    type: ed25519
    seed: "0000000000000000000000000000000000000000000000000000000000000001"

steps:
  - op: create
    domain: example.com
    signer: key-0
    timestamp: "2000-01-01T00:00:00Z"
    params:
      updateKeys: ["key-0"]

  - op: resolve
    expect: resolutionResult.json
```

## Compliance Harnesses

This repo includes reference harnesses that run the committed vectors through real resolver implementations.

### TypeScript (`implementations/ts/`)

The generator itself doubles as the TS reference — `bun run verify` re-derives every vector and diffs the output.

### Python (`implementations/python/`)

Requires Python 3.12+ and a virtual environment:

```bash
cd implementations/python
python -m venv .venv
.venv/bin/pip install did-webvh pytest pytest-asyncio
.venv/bin/pytest
```

Three test files:

| File | What it tests |
|---|---|
| `test_vectors.py` | Resolves every vector in `vectors/` against the Python resolver |
| `test_generate.py` | Regenerates each vector and checks the Python resolver agrees |
| `test_resolver_suite.py` | Runs the hand-authored error-case suite in `test-suite/` |

`test-suite/` contains hand-authored invalid logs (`invalid-json`, `invalid-method`, `invalid-scid`, `missing-proof`, `missing-witness`) plus a happy-path log (`short`) that covers resolution by versionId, versionNumber, and conflict cases. These are currently Python-only — see CLAUDE.md Future Work for the plan to make them cross-language.

### Rust (`implementations/rust/`)

```bash
cargo run --manifest-path implementations/rust/Cargo.toml --bin test-vectors
```

Resolves every vector in `vectors/` against the Rust `did-webvh` library.

### Java (`implementations/java/`)

Requires Java 11+ and Maven 3.6+.

```bash
cd implementations/java
mvn compile exec:java
```

Resolves every vector in `vectors/` against the [didwebvh-java](https://github.com/IVIR3zaM/didwebvh-java) library (v0.2.0).  See `implementations/java/README.md` for current test status and known compatibility issues.

### Roadmap

The harnesses in `implementations/` are intended to be **temporary homes**. The plan is to move each one into its respective implementation repository (e.g. `didwebvh-py`, `didwebvh-rs`) so that compliance testing runs as part of each project's own CI/CD pipeline, with this repo consumed as a git submodule pinned to a specific commit. Once migrated, `implementations/` will be removed from this repo.

## How Implementations Should Use This Repo

Consume `vectors/` as a **git submodule** pinned to a specific commit:

```bash
# Add as submodule (run once in the implementation repo)
git submodule add https://github.com/decentralized-identity/didwebvh-test-suite vectors/compliance

# Update to latest vectors
git submodule update --remote vectors/compliance
```

Then write a thin test harness that:
1. Walks `vectors/compliance/vectors/*/`
2. Calls your own `resolveDID(log)` on the `did.jsonl` in each directory
3. Compares the result to the corresponding `resolutionResult*.json`

## License

[Apache License Version 2.0](LICENSE)
