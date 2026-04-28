# Java Compliance Harness

Compliance test harness for the [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/) using the Java [didwebvh-java](https://github.com/IVIR3zaM/didwebvh-java) library.

## Library

**[IVIR3zaM/didwebvh-java](https://github.com/IVIR3zaM/didwebvh-java) v0.2.0** — a multi-module Maven project published on Maven Central.

This harness depends on the `didwebvh-core` module:

```xml
<dependency>
    <groupId>io.github.ivir3zam</groupId>
    <artifactId>didwebvh-core</artifactId>
    <version>0.2.0</version>
</dependency>
```

## Prerequisites

- Java 11 or later
- Maven 3.6 or later

## Running

```bash
cd implementations/java
mvn compile exec:java
```

This walks `../../vectors/` and runs every committed test vector through the Java resolver.  Output follows the same `PASS` / `XFAIL` / `FAIL` convention used by the Python and Rust harnesses.  Exit code is `0` when all results are pass or xfail; `1` if any test fails outright.

## Current Test Results

| Scenario | Result | Notes |
|---|---|---|
| `basic-create` | PASS | |
| `basic-update` | XFAIL | See [TS COMPAT — nextKeyHashes](#ts-compat--nextkeyhashe-) below |
| `deactivate` | XFAIL | See nextKeyHashes note; also see [Deactivated DID document](#deactivated-did-document) |
| `key-rotation` | XFAIL | See nextKeyHashes note |
| `multiple-update-keys` | XFAIL | See nextKeyHashes note |
| `multi-update` (×3) | XFAIL | See nextKeyHashes note |
| `portable` | PASS | |
| `portable-move` | XFAIL | See nextKeyHashes note |
| `pre-rotation` | PASS | |
| `pre-rotation-consume` | PASS | |
| `services` | XFAIL | See nextKeyHashes note |
| `witness-threshold` | PASS | See [Witness support](#witness-support) below |
| `witness-update` | XFAIL | See nextKeyHashes note |

## Known Issues

### TS COMPAT — `nextKeyHashes: []`

The TypeScript generator serialises `nextKeyHashes: []` for every log entry that does not use pre-rotation (i.e. it always writes the field, defaulting to an empty list).  The Java library's chain validator rejects an empty list when processing the _next_ entry's pre-rotation check.

This affects all multi-entry logs that were not specifically written with pre-rotation in mind.  Single-entry logs (create-only: `basic-create`, `portable`, `pre-rotation`) and logs with non-empty `nextKeyHashes` throughout (`pre-rotation-consume`) are unaffected.

**Resolution needed:** either the TS generator should omit `nextKeyHashes` when the list is empty, or the library should treat `[]` as equivalent to absent.  The same issue is tracked in the Python and Rust harnesses.

### Witness support

`DidResolver.resolveFromLog()` does not expose a parameter for passing in-memory witness proofs — witness fetching is only wired up for HTTP resolution.  For scenarios that include a `did-witness.json` sidecar file, this harness uses Java reflection to call the package-private `LogProcessor.process()` method directly, passing the witness content as an argument.

This works on standard JVMs (Java 11–21) but may fail on future JDKs that tighten module encapsulation, in which case witness tests will degrade to XFAIL with a descriptive message.

A cleaner fix would be to add a public `resolveFromLog(String, String, ResolveOptions, String witnessContent)` overload to `DidResolver`.

### Deactivated DID document

When a DID is deactivated the Java library returns `null` for `didDocument` in the resolution result.  The committed TS vectors include the last DID document state even after deactivation (consistent with the DID Resolution spec).  The harness works around this by recovering the document directly from the matching log entry's `state` field using the public `LogEntry.fromJsonLine()` API.

This workaround is only needed for the `deactivate` scenario; however, that scenario is currently also masked by the `nextKeyHashes: []` XFAIL above.

## Structure

```
implementations/java/
  pom.xml                                                      # Maven project
  src/main/java/org/didwebvh/compliance/TestVectors.java       # harness
```
