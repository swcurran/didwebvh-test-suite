# Cross-Resolution Diff Analysis

This document categorizes the differences found in each implementation's `diffs.txt` file — produced when that implementation's resolver processes every other implementation's committed `did.jsonl` logs and compares the result against the originating implementation's committed `resolutionResult.json`.

The goal is to distinguish:
- **Inconsequential** differences (output verbosity, envelope format, cosmetic) that do not affect interop
- **Spec ambiguities** where the spec is silent or unclear, producing legitimate divergence
- **Interop concerns** where one or more implementations appear to be wrong and should be fixed or flagged as issues

Each section has a status column you can update as items are resolved:

| Status | Meaning |
|---|---|
| 🔲 Open | Not yet acted on |
| 💬 Discussion | Raised as WG item or filed issue |
| ✅ Resolved | Fixed or agreed inconsequential |

---

## TS Resolver (`implementations/ts/diffs.txt`)

The TS resolver is the **actual** side in every diff. **Expected** is the originating implementation's own `resolutionResult.json`. All scenarios across all other implementations (dart, java, java-eecc, python, rust) appear in this file.

---

### Category 1 — Inconsequential: Extra `didDocumentMetadata` fields (other impls include; TS omits)

Other implementations write additional fields into `didDocumentMetadata` that the TS resolver does not. The spec does not mandate these fields, so this is an output verbosity difference, not a conformance failure.

| Status | Field | Impls that include it | TS behaviour |
|---|---|---|---|
| 🔲 | `scid` | dart, java, java-eecc | Omitted |
| 🔲 | `portable` (true/false) | java (always), java-eecc (sometimes) | Omitted |
| 🔲 | `deactivated: false` | python, rust (on non-deactivated DIDs) | Omitted; only emits `deactivated: true` when actually deactivated |
| 🔲 | `watchers: []` | python | Omitted |
| 🔲 | `witness: {}` / `null` | python, rust (on non-witness scenarios) | Omitted |
| 🔲 | `witness: {threshold, witnesses}` | python, rust (on witness scenarios) | Omitted |

**Notes:** The question to raise with the WG: should `portable`, `deactivated`, and `witness` always be present in resolution metadata with explicit default values (e.g. `false`, `null`, `{}`), or should they be omitted when not applicable?

---

### Category 2 — Inconsequential: Python response envelope format

Python wraps its resolution result in a different envelope structure:

- Adds `"@context": "https://w3id.org/did-resolution/v1"` as a top-level field
- Returns `"didResolutionMetadata": null` instead of `{ "contentType": "application/did+ld+json" }`

| Status | Item |
|---|---|
| 🔲 | Python top-level `@context` |
| 🔲 | Python `didResolutionMetadata: null` vs object |

**Notes:** Python appears to be following an older or extended DID Resolution spec envelope. The DID document content itself is unaffected. Python should align its envelope format with the other implementations.

---

### Category 3 — Spec ambiguity: Implicit service IDs (relative vs absolute)

The `#files` and `#whois` services are spec-defined implicit services injected at resolution time. Implementations disagree on whether the service `id` should be a relative fragment or a fully-qualified DID URL.

| Format | Impls |
|---|---|
| `"id": "#files"` (relative fragment) | TS, java-eecc |
| `"id": "did:webvh:<SCID>:example.com#files"` (absolute DID URL) | dart, java, python, rust |

| Status | Item |
|---|---|
| 🔲 | Raise WG discussion: relative vs absolute service ID for implicit services |

**Notes:** TS and java-eecc agree on relative; dart, java, python, rust agree on absolute. The spec needs to say explicitly which form is correct for implicit services added at resolution time.

---

### Category 4 — Minor / generator inconsistency: `serviceEndpoint` trailing slash

All non-TS/non-rust generators write `"serviceEndpoint": "https://example.com/"` (with trailing slash); the TS resolver returns `"https://example.com"` (no trailing slash). Rust generates without trailing slash, so rust/TS agree when rust logs are resolved.

| Status | Item |
|---|---|
| 🔲 | dart, java, python generators: strip trailing slash from service endpoint URLs |

**Notes:** This is a generator-side inconsistency in the source `did.jsonl`, not a resolver interpretation difference. The spec does not mandate trailing slash behaviour for service endpoints. The simplest fix is for the non-TS generators to omit the trailing slash, matching what TS produces.

---

### Category 5 — Interop concern: Deactivated DID resolution returns `null` vs full document

For the `deactivate` scenario, when TS resolves another implementation's deactivated DID log it returns `"didDocument": null`. Every other implementation's own resolution result contains the full last-known DID document.

| What | TS | dart | java | java-eecc | python | rust |
|---|---|---|---|---|---|---|
| `didDocument` for deactivated DID | `null` | full doc | full doc | full doc | full doc | full doc |

| Status | Item |
|---|---|
| 🔲 | Raise WG discussion / file issues against non-TS implementations |

**Notes:** The DID Core and DID Resolution specs say a deactivated DID should return `null` for `didDocument`. TS is likely spec-correct; all other implementations are returning the last-known document instead. This is the most significant interop divergence in this file and warrants a WG clarification and follow-up issues against the affected libraries.

---

### Category 6 — Interop concern: `updated` timestamp in historical resolution (multi-update)

When resolving at a specific `versionId` (v1 or v2 in the `multi-update` scenario):

| What | TS | rust | python |
|---|---|---|---|
| `updated` for v1 resolution | date of v1 (`2000-01-01`) | HEAD date (`2000-01-03`) | HEAD date (`2000-01-03`) |
| `updated` for v2 resolution | date of v2 (`2000-01-02`) | HEAD date (`2000-01-03`) | HEAD date (`2000-01-03`) |

| Status | Item |
|---|---|
| 🔲 | File issue against rust implementation |
| 🔲 | File issue against python implementation |

**Notes:** TS behaviour is spec-correct — `updated` in `didDocumentMetadata` should reflect when the *resolved version* was created, not the HEAD version. Rust and Python have a bug in historical resolution where they always return the HEAD metadata regardless of the requested version.

---

### Category 7 — Interop concern: `alsoKnownAs` bleed in Python historical resolution (multi-update)

When resolving Python's `multi-update` log at v1 and v2, Python's own resolution results include `alsoKnownAs` entries that are not present in those versions according to TS resolution:

| Version | Python | TS |
|---|---|---|
| v1 | `alsoKnownAs: ["did:web:example.com", "did:web:example.org"]` | no `alsoKnownAs` |
| v2 | `alsoKnownAs: ["did:web:example.com"]` | no `alsoKnownAs` |
| v3 (HEAD) | no `alsoKnownAs` | no `alsoKnownAs` |

| Status | Item |
|---|---|
| 🔲 | Investigate multi-update script to confirm which version introduces `alsoKnownAs` |
| 🔲 | File issue against python implementation if confirmed bug |

**Notes:** This looks like Python's historical resolution is incorrectly reading content from a version other than the one requested — likely carrying forward `alsoKnownAs` from an intermediate version. The HEAD result agrees between Python and TS (no `alsoKnownAs`), which suggests the issue is specific to historical resolution logic.

---

## Summary

| # | Category | Severity | Status |
|---|---|---|---|
| 1 | Extra `didDocumentMetadata` fields (`scid`, `portable`, `deactivated:false`, `watchers`, `witness`) | Inconsequential | 🔲 |
| 2 | Python response envelope (`@context`, `didResolutionMetadata: null`) | Inconsequential | 🔲 |
| 3 | Implicit service IDs (relative `#files` vs absolute DID URL) | Spec ambiguity | 🔲 |
| 4 | `serviceEndpoint` trailing slash | Generator inconsistency | 🔲 |
| 5 | Deactivated DID returns `null` vs full document | **Interop concern** | 🔲 |
| 6 | `updated` date in historical resolution (rust, python) | **Interop concern** | 🔲 |
| 7 | `alsoKnownAs` bleed in Python historical resolution | **Interop concern** | 🔲 |
