# rust status

Implementation: didwebvh-rs 0.5.3 @ ad614934

## DID Creation

| Test Case | Result | Notes |
|---|---|---|
| basic-create | ✅ PASS |  |
| basic-update | ✅ PASS |  |
| deactivate | ✅ PASS |  |
| key-rotation | ✅ PASS |  |
| multi-update | ✅ PASS |  |
| multiple-update-keys | ✅ PASS |  |
| portable | ✅ PASS |  |
| portable-move | ✅ PASS |  |
| pre-rotation | ✅ PASS |  |
| pre-rotation-consume | ✅ PASS |  |
| services | ✅ PASS |  |
| witness-threshold | ✅ PASS |  |
| witness-update | ✅ PASS |  |

## Negative Resolution

| Test Case | Expected Error | Result | Notes |
|---|---|---|---|
| negative-cross-did-witness-replay | invalidDid | ✅ PASS |  |
| negative-did-key-body-fragment-mismatch | invalidProof | ✅ PASS |  |
| negative-duplicate-witness-ids | invalidParameters | ✅ PASS |  |
| negative-fragment-leaks-into-domain | invalidDid | ✅ PASS |  |
| negative-lowercase-pct-port-ip | invalidDid | ✅ PASS |  |
| negative-path-traversal-did | invalidDid | ✅ PASS |  |
| negative-pct-encoded-ip-host | invalidDid | ❌ FAIL | URL parser accepted invalid DID: did:webvh:Qm0000000000000000000000000000000000000000000000:127%2E0%2E0%2E1 |
| negative-pct-encoded-traversal | invalidDid | ✅ PASS |  |
| negative-portable-scid-swap | invalidDid | ✅ PASS |  |
| negative-pre-rotation-omit-updatekeys | invalidParameters | ✅ PASS |  |
| negative-scid-mismatch-genesis | invalidDid | ✅ PASS |  |
| negative-unknown-method-version | invalidDid | ✅ PASS |  |
| negative-versiontime-future | invalidDid | ✅ PASS |  |
| negative-versiontime-non-monotonic | invalidDid | ✅ PASS |  |
| negative-wrong-cryptosuite | invalidProof | ✅ PASS |  |
| negative-zero-witness-threshold | invalidParameters | ✅ PASS |  |

## Cross-Resolution

| Test Case | Log Source | Result | Notes |
|---|---|---|---|
| basic-create | java | 🔶 DIFF | see diffs.txt |
| basic-create | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-create | python | 🔶 DIFF | see diffs.txt |
| basic-create | rust (self) | ✅ PASS |  |
| basic-create | ts | 🔶 DIFF | see diffs.txt |
| basic-update | java | 🔶 DIFF | see diffs.txt |
| basic-update | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-update | python | 🔶 DIFF | see diffs.txt |
| basic-update | rust (self) | ✅ PASS |  |
| basic-update | ts | 🔶 DIFF | see diffs.txt |
| deactivate | java | 🔶 DIFF | see diffs.txt |
| deactivate | java-eecc | 🔶 DIFF | see diffs.txt |
| deactivate | python | 🔶 DIFF | see diffs.txt |
| deactivate | rust (self) | ✅ PASS |  |
| deactivate | ts | 🔶 DIFF | see diffs.txt |
| key-rotation | java | 🔶 DIFF | see diffs.txt |
| key-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| key-rotation | python | 🔶 DIFF | see diffs.txt |
| key-rotation | rust (self) | ✅ PASS |  |
| key-rotation | ts | 🔶 DIFF | see diffs.txt |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | python | 🔶 DIFF | see diffs.txt |
| multi-update | rust (self) | ✅ PASS |  |
| multi-update | ts | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | java | ⚠️ SKIP | no did.jsonl |
| multiple-update-keys | java-eecc | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | python | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | rust (self) | ✅ PASS |  |
| multiple-update-keys | ts | 🔶 DIFF | see diffs.txt |
| portable | java | 🔶 DIFF | see diffs.txt |
| portable | java-eecc | 🔶 DIFF | see diffs.txt |
| portable | python | 🔶 DIFF | see diffs.txt |
| portable | rust (self) | ✅ PASS |  |
| portable | ts | 🔶 DIFF | see diffs.txt |
| portable-move | java | 🔶 DIFF | see diffs.txt |
| portable-move | java-eecc | 🔶 DIFF | see diffs.txt |
| portable-move | python | 🔶 DIFF | see diffs.txt |
| portable-move | rust (self) | ✅ PASS |  |
| portable-move | ts | 🔶 DIFF | see diffs.txt |
| pre-rotation | java | 🔶 DIFF | see diffs.txt |
| pre-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation | python | 🔶 DIFF | see diffs.txt |
| pre-rotation | rust (self) | ✅ PASS |  |
| pre-rotation | ts | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | java | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | python | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | rust (self) | ✅ PASS |  |
| pre-rotation-consume | ts | 🔶 DIFF | see diffs.txt |
| services | java | 🔶 DIFF | see diffs.txt |
| services | java-eecc | 🔶 DIFF | see diffs.txt |
| services | python | 🔶 DIFF | see diffs.txt |
| services | rust (self) | ✅ PASS |  |
| services | ts | 🔶 DIFF | see diffs.txt |
| witness-threshold | java | 🔶 DIFF | see diffs.txt |
| witness-threshold | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-threshold | python | 🔶 DIFF | see diffs.txt |
| witness-threshold | rust (self) | ✅ PASS |  |
| witness-threshold | ts | 🔶 DIFF | see diffs.txt |
| witness-update | java | ❌ FAIL | resolve_log: WitnessProofError("Witness proof threshold (2) was not met. Only (1) proofs were validated") |
| witness-update | java-eecc | ❌ FAIL | resolve_log: WitnessProofError("Witness proof threshold (2) was not met. Only (1) proofs were validated") |
| witness-update | python | ❌ FAIL | resolve_log: WitnessProofError("Witness proof threshold (2) was not met. Only (1) proofs were validated") |
| witness-update | rust (self) | ✅ PASS |  |
| witness-update | ts | ❌ FAIL | resolve_log: WitnessProofError("Witness proof threshold (2) was not met. Only (1) proofs were validated") |

---
Built from: https://github.com/decentralized-identity/didwebvh-rs @ main (ad61493)
