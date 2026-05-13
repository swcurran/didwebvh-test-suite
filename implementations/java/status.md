# java cross-resolution status

| Test Case | Log Source | Result | Notes |
|---|---|---|---|
| basic-create | java (self) | ✅ PASS |  |
| basic-create | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-create | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| basic-create | rust | 🔶 DIFF | see diffs.txt |
| basic-create | ts | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| basic-update | java (self) | ✅ PASS |  |
| basic-update | java-eecc | ❌ FAIL | resolve error: Invalid DID log: versionTime must be after previous entry at entry 2 |
| basic-update | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| basic-update | rust | 🔶 DIFF | see diffs.txt |
| basic-update | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
| deactivate | java (self) | ✅ PASS |  |
| deactivate | java-eecc | ❌ FAIL | resolve error: Invalid DID log: versionTime must be after previous entry at entry 2 |
| deactivate | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| deactivate | rust | 🔶 DIFF | see diffs.txt |
| deactivate | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
| key-rotation | java (self) | ✅ PASS |  |
| key-rotation | java-eecc | ❌ FAIL | resolve error: Invalid DID log: versionTime must be after previous entry at entry 2 |
| key-rotation | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| key-rotation | rust | 🔶 DIFF | see diffs.txt |
| key-rotation | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
| multi-update | java (self) | ✅ PASS |  |
| multi-update | java-eecc | ❌ FAIL | resolve error: Invalid DID log: versionTime must be after previous entry at entry 3 |
| multi-update | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| multi-update | rust | 🔶 DIFF | see diffs.txt |
| multi-update | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
| multiple-update-keys | java | ⚠️ SKIP | no did.jsonl present |
| multiple-update-keys | java-eecc | ❌ FAIL | resolve error: Invalid DID log: versionTime must be after previous entry at entry 2 |
| multiple-update-keys | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| multiple-update-keys | rust | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
| portable | java (self) | ✅ PASS |  |
| portable | java-eecc | 🔶 DIFF | see diffs.txt |
| portable | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| portable | rust | 🔶 DIFF | see diffs.txt |
| portable | ts | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| portable-move | java (self) | ✅ PASS |  |
| portable-move | java-eecc | ⚠️ SKIP | no did.jsonl present |
| portable-move | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| portable-move | rust | 🔶 DIFF | see diffs.txt |
| portable-move | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
| pre-rotation | java (self) | ✅ PASS |  |
| pre-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| pre-rotation | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation | ts | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| pre-rotation-consume | java | ⚠️ SKIP | no did.jsonl present |
| pre-rotation-consume | java-eecc | ❌ FAIL | resolve error: Invalid DID log: signing key not in active updateKeys at entry 2 |
| pre-rotation-consume | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| pre-rotation-consume | rust | ❌ FAIL | resolve error: Invalid DID log: signing key not in active updateKeys at entry 2 |
| pre-rotation-consume | ts | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| services | java (self) | ✅ PASS |  |
| services | java-eecc | ❌ FAIL | resolve error: Invalid DID log: versionTime must be after previous entry at entry 2 |
| services | python | ❌ FAIL | LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters (Python/TS write empty witness object; library expects absent field) |
| services | rust | 🔶 DIFF | see diffs.txt |
| services | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
| witness-threshold | java (self) | ✅ PASS |  |
| witness-threshold | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-threshold | python | 🔶 DIFF | see diffs.txt |
| witness-threshold | rust | ❌ FAIL | resolve error: Invalid witness proofs: insufficient witness proofs for entry 1-QmdDTDXMshdRwAbnN7b22BKAUy1CvQsq6y6zQqSP7reDJ7: need 1, got 0 |
| witness-threshold | ts | 🔶 DIFF | see diffs.txt |
| witness-update | java (self) | ✅ PASS |  |
| witness-update | java-eecc | ❌ FAIL | resolve error: Invalid DID log: versionTime must be after previous entry at entry 2 |
| witness-update | python | 🔶 DIFF | see diffs.txt |
| witness-update | rust | ❌ FAIL | resolve error: Invalid witness proofs: missing witness proof for entry 1-QmayLd7TkamnZhA8EbQCP6aUvU7YvGW1xW2iauRFC47ziP |
| witness-update | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Java library may reject on update validation |
