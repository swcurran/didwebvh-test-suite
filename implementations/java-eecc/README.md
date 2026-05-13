# Java Compliance Harness (EECC)

Compliance test harness for the [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/) using the [european-epc-competence-center/didwebvh](https://github.com/european-epc-competence-center/didwebvh) Java library.

## Library

**[european-epc-competence-center/didwebvh](https://github.com/european-epc-competence-center/didwebvh)** — Java implementation in the `didwebvh-java/` subdirectory.

This library is not yet published to Maven Central and must be installed to the local Maven repository before building this harness:

```bash
git clone https://github.com/european-epc-competence-center/didwebvh /path/to/didwebvh-java-eecc
cd /path/to/didwebvh-java-eecc/didwebvh-java
mvn install -DskipTests
```

The harness then depends on:

```xml
<dependency>
    <groupId>io.github.european-epc-competence-center</groupId>
    <artifactId>didwebvh-java</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Prerequisites

- Java 17 or later
- Maven 3.6 or later
- Library installed to local Maven repo (see above)

## Running

```bash
cd implementations/java-eecc
mvn compile exec:java
```

This walks `../../vectors/` and runs every committed test vector through the resolver.  Output follows the same `PASS` / `XFAIL` / `FAIL` convention used by the other harnesses.  Exit code is `0` when all results are pass or xfail; `1` if any test fails outright.

## Current Test Results

| Scenario | Result | Notes |
|---|---|---|
| `basic-create` | PASS | |
| `basic-update` | PASS | |
| `deactivate` | PASS | |
| `key-rotation` | PASS | |
| `multi-update` (×3) | PASS | |
| `multiple-update-keys` | PASS | |
| `portable` | PASS | |
| `portable-move` | PASS | |
| `pre-rotation` | PASS | |
| `pre-rotation-consume` | PASS | |
| `services` | PASS | |
| `witness-threshold` | PASS | |
| `witness-update` | XFAIL | See [Witness epoch validation](#witness-epoch-validation) below |

## Known Issues

### Witness epoch validation

The `witness-update` scenario creates a DID with a 2-of-2 witness configuration and then updates it to 1-of-1. The committed `did-witness.json` includes 2 witness proofs for the genesis entry and only 1 for the update entry (reflecting the new 1-of-1 config).

The library uses a strict epoch-based witness model: the 2-of-2 configuration governs the update entry as well (because a new witness configuration only becomes active *after* its entry is published, meaning there is no subsequent entry for the 1-of-1 config to cover). This means 2 witnesses must have signed at version 2, but only 1 did → resolution fails with `invalidDid`.

The TS generator produced the vectors assuming that the new 1-of-1 config applies immediately to the entry that introduces it. This is a spec interpretation difference. Until the vectors are regenerated or the library's epoch model is aligned, this scenario stays XFAIL.

### TS COMPAT normalizations applied by the harness

The harness applies two normalizations to compensate for known differences between the TS generator's output and the library's behavior:

- **`updated` field in historical queries**: The library sets `updated` to the latest log entry's `versionTime` regardless of the requested version. The TS vectors use the target version's `versionTime` as `updated`. The harness overrides `updated` with `versionTime`.

- **Deactivated DID document**: The library returns `null` for `didDocument` when a DID is deactivated; the TS vectors include the pre-deactivation DID document. The harness re-resolves at the last pre-deactivation version to obtain the document.

- **Service ID form**: The library's implicit service injector uses absolute DID URLs as service IDs (e.g. `did:webvh:…:example.com#files`). The TS vectors use bare fragments (`#files`). The harness normalizes absolute IDs to bare fragments.

- **Extra `didDocumentMetadata` fields**: The library emits fields not present in the TS vectors (`scid`, `portable`, `ttl`, `witness`, `watchers`). The harness compares only the keys present in the expected result.

## Structure

```
implementations/java-eecc/
  pom.xml                                                         # Maven project
  src/main/java/org/didwebvh/compliance/TestVectors.java          # harness
```
