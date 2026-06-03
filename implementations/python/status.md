# python status

Implementation: did-webvh python 1.0.0

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
| negative-fragment-leaks-into-domain | invalidDid | ⚠️ SKIP | URL-only test (no log) |
| negative-lowercase-pct-port-ip | invalidDid | ⚠️ SKIP | URL-only test (no log) |
| negative-path-traversal-did | invalidDid | ⚠️ SKIP | URL-only test (no log) |
| negative-pct-encoded-ip-host | invalidDid | ⚠️ SKIP | URL-only test (no log) |
| negative-pct-encoded-traversal | invalidDid | ⚠️ SKIP | URL-only test (no log) |
| negative-portable-scid-swap | invalidDid | ✅ PASS |  |
| negative-pre-rotation-omit-updatekeys | invalidParameters | ✅ PASS |  |
| negative-scid-mismatch-genesis | invalidDid | ✅ PASS |  |
| negative-unknown-method-version | invalidDid | ✅ PASS |  |
| negative-versiontime-future | invalidDid | ✅ PASS |  |
| negative-versiontime-non-monotonic | invalidDid | ❌ FAIL | resolver accepted invalid log |
| negative-wrong-cryptosuite | invalidProof | ✅ PASS |  |
| negative-zero-witness-threshold | invalidParameters | ❌ FAIL | resolver accepted invalid log |

## Cross-Resolution

| Test Case | Log Source | Result | Notes |
|---|---|---|---|
| basic-create | java | 🔶 DIFF | see diffs.txt |
| basic-create | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-create | python | 🔶 DIFF | see diffs.txt |
| basic-create | rust | 🔶 DIFF | see diffs.txt |
| basic-create | ts | ✅ PASS |  |
| basic-update | java | 🔶 DIFF | see diffs.txt |
| basic-update | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-update | python | 🔶 DIFF | see diffs.txt |
| basic-update | rust | 🔶 DIFF | see diffs.txt |
| basic-update | ts | ✅ PASS |  |
| deactivate | java | 🔶 DIFF | see diffs.txt |
| deactivate | java-eecc | 🔶 DIFF | see diffs.txt |
| deactivate | python | 🔶 DIFF | see diffs.txt |
| deactivate | rust | 🔶 DIFF | see diffs.txt |
| deactivate | ts | ✅ PASS |  |
| key-rotation | java | 🔶 DIFF | see diffs.txt |
| key-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| key-rotation | python | 🔶 DIFF | see diffs.txt |
| key-rotation | rust | 🔶 DIFF | see diffs.txt |
| key-rotation | ts | ✅ PASS |  |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | python | 🔶 DIFF | see diffs.txt |
| multi-update | python | 🔶 DIFF | see diffs.txt |
| multi-update | python | 🔶 DIFF | see diffs.txt |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | ts | 🔶 DIFF | see diffs.txt |
| multi-update | ts | 🔶 DIFF | see diffs.txt |
| multi-update | ts | ✅ PASS |  |
| multiple-update-keys | java-eecc | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | python | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | rust | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | ts | ✅ PASS |  |
| portable | java | 🔶 DIFF | see diffs.txt |
| portable | java-eecc | 🔶 DIFF | see diffs.txt |
| portable | python | 🔶 DIFF | see diffs.txt |
| portable | rust | 🔶 DIFF | see diffs.txt |
| portable | ts | ✅ PASS |  |
| portable-move | java | 🔶 DIFF | see diffs.txt |
| portable-move | java-eecc | 🔶 DIFF | see diffs.txt |
| portable-move | python | 🔶 DIFF | see diffs.txt |
| portable-move | rust | 🔶 DIFF | see diffs.txt |
| portable-move | ts | ✅ PASS |  |
| pre-rotation | java | 🔶 DIFF | see diffs.txt |
| pre-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation | python | 🔶 DIFF | see diffs.txt |
| pre-rotation | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation | ts | ✅ PASS |  |
| pre-rotation-consume | java | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | python | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | ts | ✅ PASS |  |
| services | java | 🔶 DIFF | see diffs.txt |
| services | java-eecc | 🔶 DIFF | see diffs.txt |
| services | python | 🔶 DIFF | see diffs.txt |
| services | rust | 🔶 DIFF | see diffs.txt |
| services | ts | ✅ PASS |  |
| witness-threshold | java | 🔶 DIFF | see diffs.txt |
| witness-threshold | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-threshold | python | 🔶 DIFF | see diffs.txt |
| witness-threshold | rust | 🔶 DIFF | see diffs.txt |
| witness-threshold | ts | ✅ PASS |  |
| witness-update | java | 🔶 DIFF | see diffs.txt |
| witness-update | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-update | python | ✅ PASS |  |
| witness-update | rust | 🔶 DIFF | see diffs.txt |
| witness-update | ts | 🔶 DIFF | see diffs.txt |

---
Built from: https://github.com/decentralized-identity/didwebvh-py @ main (dc32e19)
