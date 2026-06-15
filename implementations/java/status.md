# java status

Implementation: didwebvh-java 0.3.0-SNAPSHOT @ c50db5b

## DID Creation

| Test Case | Result | Notes |
|---|---|---|
| basic-create | ✅ PASS |  |
| basic-update | ✅ PASS |  |
| deactivate | ✅ PASS |  |
| key-rotation | ✅ PASS |  |
| multi-update | ✅ PASS |  |
| multiple-update-keys | ⚠️ SKIP | multiple-update-keys at create time not supported by didwebvh-java API |
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
| negative-pct-encoded-ip-host | invalidDid | ✅ PASS |  |
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
| basic-create | dart | 🔶 DIFF | see diffs.txt |
| basic-create | java (self) | ✅ PASS |  |
| basic-create | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-create | python | 🔶 DIFF | see diffs.txt |
| basic-create | rust | 🔶 DIFF | see diffs.txt |
| basic-create | ts | 🔶 DIFF | see diffs.txt |
| basic-update | dart | 🔶 DIFF | see diffs.txt |
| basic-update | java (self) | ✅ PASS |  |
| basic-update | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-update | python | 🔶 DIFF | see diffs.txt |
| basic-update | rust | 🔶 DIFF | see diffs.txt |
| basic-update | ts | 🔶 DIFF | see diffs.txt |
| deactivate | dart | 🔶 DIFF | see diffs.txt |
| deactivate | java (self) | ✅ PASS |  |
| deactivate | java-eecc | 🔶 DIFF | see diffs.txt |
| deactivate | python | 🔶 DIFF | see diffs.txt |
| deactivate | rust | 🔶 DIFF | see diffs.txt |
| deactivate | ts | 🔶 DIFF | see diffs.txt |
| key-rotation | dart | 🔶 DIFF | see diffs.txt |
| key-rotation | java (self) | ✅ PASS |  |
| key-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| key-rotation | python | 🔶 DIFF | see diffs.txt |
| key-rotation | rust | 🔶 DIFF | see diffs.txt |
| key-rotation | ts | 🔶 DIFF | see diffs.txt |
| multi-update | dart | 🔶 DIFF | see diffs.txt |
| multi-update | java (self) | ✅ PASS |  |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | python | 🔶 DIFF | see diffs.txt |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | ts | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | dart | ⚠️ SKIP | no did.jsonl present |
| multiple-update-keys | java | ⚠️ SKIP | no did.jsonl present |
| multiple-update-keys | java-eecc | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | python | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | rust | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | ts | 🔶 DIFF | see diffs.txt |
| portable | dart | ✅ PASS |  |
| portable | java (self) | ✅ PASS |  |
| portable | java-eecc | 🔶 DIFF | see diffs.txt |
| portable | python | 🔶 DIFF | see diffs.txt |
| portable | rust | 🔶 DIFF | see diffs.txt |
| portable | ts | 🔶 DIFF | see diffs.txt |
| portable-move | dart | ✅ PASS |  |
| portable-move | java (self) | ✅ PASS |  |
| portable-move | java-eecc | 🔶 DIFF | see diffs.txt |
| portable-move | python | 🔶 DIFF | see diffs.txt |
| portable-move | rust | 🔶 DIFF | see diffs.txt |
| portable-move | ts | 🔶 DIFF | see diffs.txt |
| pre-rotation | dart | 🔶 DIFF | see diffs.txt |
| pre-rotation | java (self) | ✅ PASS |  |
| pre-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation | python | 🔶 DIFF | see diffs.txt |
| pre-rotation | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation | ts | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | dart | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | java (self) | ✅ PASS |  |
| pre-rotation-consume | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | python | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | ts | 🔶 DIFF | see diffs.txt |
| services | dart | 🔶 DIFF | see diffs.txt |
| services | java (self) | ✅ PASS |  |
| services | java-eecc | 🔶 DIFF | see diffs.txt |
| services | python | 🔶 DIFF | see diffs.txt |
| services | rust | 🔶 DIFF | see diffs.txt |
| services | ts | 🔶 DIFF | see diffs.txt |
| witness-threshold | dart | 🔶 DIFF | see diffs.txt |
| witness-threshold | java (self) | ✅ PASS |  |
| witness-threshold | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-threshold | python | 🔶 DIFF | see diffs.txt |
| witness-threshold | rust | 🔶 DIFF | see diffs.txt |
| witness-threshold | ts | 🔶 DIFF | see diffs.txt |
| witness-update | dart | 🔶 DIFF | see diffs.txt |
| witness-update | java (self) | ✅ PASS |  |
| witness-update | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-update | python | 🔶 DIFF | see diffs.txt |
| witness-update | rust | 🔶 DIFF | see diffs.txt |
| witness-update | ts | 🔶 DIFF | see diffs.txt |

---
Built from: https://github.com/decentralized-identity/didwebvh-java @ main (220508b)
