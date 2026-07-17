# python status

Implementation: did-webvh python 1.0.1

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
| negative-versiontime-non-monotonic | invalidDid | ✅ PASS |  |
| negative-witness-update-threshold-not-met | invalidDid | ✅ PASS |  |
| negative-wrong-cryptosuite | invalidProof | ✅ PASS |  |
| negative-zero-witness-threshold | invalidParameters | ✅ PASS |  |

## Cross-Resolution

| Test Case | Log Source | Result | Notes |
|---|---|---|---|
| basic-create | dart | 🔶 DIFF | see diffs.txt |
| basic-create | java | 🔶 DIFF | see diffs.txt |
| basic-create | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-create | python | ✅ PASS |  |
| basic-create | rust | 🔶 DIFF | see diffs.txt |
| basic-create | ts | 🔶 DIFF | see diffs.txt |
| basic-update | dart | 🔶 DIFF | see diffs.txt |
| basic-update | java | 🔶 DIFF | see diffs.txt |
| basic-update | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-update | python | ✅ PASS |  |
| basic-update | rust | 🔶 DIFF | see diffs.txt |
| basic-update | ts | 🔶 DIFF | see diffs.txt |
| deactivate | dart | 🔶 DIFF | see diffs.txt |
| deactivate | java | 🔶 DIFF | see diffs.txt |
| deactivate | java-eecc | 🔶 DIFF | see diffs.txt |
| deactivate | python | ✅ PASS |  |
| deactivate | rust | 🔶 DIFF | see diffs.txt |
| deactivate | ts | 🔶 DIFF | see diffs.txt |
| key-rotation | dart | 🔶 DIFF | see diffs.txt |
| key-rotation | java | 🔶 DIFF | see diffs.txt |
| key-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| key-rotation | python | ✅ PASS |  |
| key-rotation | rust | 🔶 DIFF | see diffs.txt |
| key-rotation | ts | 🔶 DIFF | see diffs.txt |
| multi-update | dart | 🔶 DIFF | see diffs.txt |
| multi-update | dart | 🔶 DIFF | see diffs.txt |
| multi-update | dart | 🔶 DIFF | see diffs.txt |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | 🔶 DIFF | see diffs.txt |
| multi-update | python | ✅ PASS |  |
| multi-update | python | ✅ PASS |  |
| multi-update | python | ✅ PASS |  |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | ts | 🔶 DIFF | see diffs.txt |
| multi-update | ts | 🔶 DIFF | see diffs.txt |
| multi-update | ts | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | java-eecc | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | python | ✅ PASS |  |
| multiple-update-keys | rust | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | ts | 🔶 DIFF | see diffs.txt |
| portable | dart | 🔶 DIFF | see diffs.txt |
| portable | java | 🔶 DIFF | see diffs.txt |
| portable | java-eecc | 🔶 DIFF | see diffs.txt |
| portable | python | ✅ PASS |  |
| portable | rust | 🔶 DIFF | see diffs.txt |
| portable | ts | 🔶 DIFF | see diffs.txt |
| portable-move | dart | 🔶 DIFF | see diffs.txt |
| portable-move | java | 🔶 DIFF | see diffs.txt |
| portable-move | java-eecc | 🔶 DIFF | see diffs.txt |
| portable-move | python | ✅ PASS |  |
| portable-move | rust | 🔶 DIFF | see diffs.txt |
| portable-move | ts | 🔶 DIFF | see diffs.txt |
| pre-rotation | dart | 🔶 DIFF | see diffs.txt |
| pre-rotation | java | 🔶 DIFF | see diffs.txt |
| pre-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation | python | ✅ PASS |  |
| pre-rotation | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation | ts | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | dart | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | java | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | python | ✅ PASS |  |
| pre-rotation-consume | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | ts | 🔶 DIFF | see diffs.txt |
| services | dart | 🔶 DIFF | see diffs.txt |
| services | java | 🔶 DIFF | see diffs.txt |
| services | java-eecc | 🔶 DIFF | see diffs.txt |
| services | python | ✅ PASS |  |
| services | rust | 🔶 DIFF | see diffs.txt |
| services | ts | 🔶 DIFF | see diffs.txt |
| witness-threshold | dart | 🔶 DIFF | see diffs.txt |
| witness-threshold | java | 🔶 DIFF | see diffs.txt |
| witness-threshold | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-threshold | python | ✅ PASS |  |
| witness-threshold | rust | 🔶 DIFF | see diffs.txt |
| witness-threshold | ts | 🔶 DIFF | see diffs.txt |
| witness-update | dart | 🔶 DIFF | see diffs.txt |
| witness-update | java | 🔶 DIFF | see diffs.txt |
| witness-update | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-update | python | ✅ PASS |  |
| witness-update | rust | 🔶 DIFF | see diffs.txt |
| witness-update | ts | 🔶 DIFF | see diffs.txt |

---
Built from: https://github.com/decentralized-identity/didwebvh-py @ main (249e47a)
