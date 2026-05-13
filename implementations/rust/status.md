# rust cross-resolution status

| Test Case | Log Source | Result | Notes |
|---|---|---|---|
| basic-create | java | 🔶 DIFF | see diffs.txt |
| basic-create | java-eecc | 🔶 DIFF | see diffs.txt |
| basic-create | python | 🔶 DIFF | see diffs.txt |
| basic-create | rust (self) | ✅ PASS |  |
| basic-create | ts | 🔶 DIFF | see diffs.txt |
| basic-update | java | 🔶 DIFF | see diffs.txt |
| basic-update | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 2] Log truncated at 2-Qma6hsKB1EstAgW9MhcwKMC4RbeSozZSMdXtMun51ZexeH: ValidationE |
| basic-update | python | 🔶 DIFF | see diffs.txt |
| basic-update | rust (self) | ✅ PASS |  |
| basic-update | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
| deactivate | java | 🔶 DIFF | see diffs.txt |
| deactivate | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 2] Log truncated at 2-QmcnrouaBSCHw9tP5SDgyWiSf2KoZyEWDb6RtCyGYksePp: ValidationE |
| deactivate | python | 🔶 DIFF | see diffs.txt |
| deactivate | rust (self) | ✅ PASS |  |
| deactivate | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
| key-rotation | java | 🔶 DIFF | see diffs.txt |
| key-rotation | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 2] Log truncated at 2-QmcJ65eHXabwznDPxLAkJhcwTLYhGGuPjtonkGMSeP8fqJ: ValidationE |
| key-rotation | python | 🔶 DIFF | see diffs.txt |
| key-rotation | rust (self) | ✅ PASS |  |
| key-rotation | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
| multi-update | java | 🔶 DIFF | see diffs.txt |
| multi-update | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 3] Log truncated at 3-QmU9PTtjDo2jkXkRFT1mkMiQ5KQruiTvhQdrfQu6tFdyGw: ValidationE |
| multi-update | python | 🔶 DIFF | see diffs.txt |
| multi-update | rust (self) | ✅ PASS |  |
| multi-update | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
| multiple-update-keys | java | ⚠️ SKIP | no did.jsonl |
| multiple-update-keys | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 2] Log truncated at 2-QmaXfYp3i2rzD3cznSotTQJ7r1a3mpeyttC3rZ1BahJHA4: ValidationE |
| multiple-update-keys | python | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | rust (self) | ✅ PASS |  |
| multiple-update-keys | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
| portable | java | 🔶 DIFF | see diffs.txt |
| portable | java-eecc | 🔶 DIFF | see diffs.txt |
| portable | python | 🔶 DIFF | see diffs.txt |
| portable | rust (self) | ✅ PASS |  |
| portable | ts | 🔶 DIFF | see diffs.txt |
| portable-move | java | 🔶 DIFF | see diffs.txt |
| portable-move | java-eecc | ⚠️ SKIP | no did.jsonl |
| portable-move | python | 🔶 DIFF | see diffs.txt |
| portable-move | rust (self) | ✅ PASS |  |
| portable-move | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
| pre-rotation | java | 🔶 DIFF | see diffs.txt |
| pre-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation | python | 🔶 DIFF | see diffs.txt |
| pre-rotation | rust (self) | ✅ PASS |  |
| pre-rotation | ts | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | java | ⚠️ SKIP | no did.jsonl |
| pre-rotation-consume | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 2] Log truncated at 2-Qma2yGykHqRFCbRHiZd1axCVnXC743twuQzszaSqZYNsEn: ValidationE |
| pre-rotation-consume | python | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | rust (self) | ✅ PASS |  |
| pre-rotation-consume | ts | 🔶 DIFF | see diffs.txt |
| services | java | 🔶 DIFF | see diffs.txt |
| services | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 2] Log truncated at 2-QmaydhnnaU2gDA17xZ4Nb7G4DSNjV5MoWQSrZ8nuDEjuvG: ValidationE |
| services | python | 🔶 DIFF | see diffs.txt |
| services | rust (self) | ✅ PASS |  |
| services | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
| witness-threshold | java | 🔶 DIFF | see diffs.txt |
| witness-threshold | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-threshold | python | 🔶 DIFF | see diffs.txt |
| witness-threshold | rust (self) | ✅ PASS |  |
| witness-threshold | ts | 🔶 DIFF | see diffs.txt |
| witness-update | java | ❌ FAIL | resolve_log: WitnessProofError("LogEntry (2-QmY1XUJiEudbdEeLnJkZVgm7jiGjHtZaPh2o5DnW8bnxYH): Witness proof validation fa |
| witness-update | java-eecc | ❌ FAIL | resolve_log: ValidationError("[version 2] Log truncated at 2-QmPY4jwLJ3nr5YWarm9qxcmEcZ6Gi5tNH2xH1oXwdZda64: ValidationE |
| witness-update | python | ❌ FAIL | resolve_log: WitnessProofError("LogEntry (2-QmUjrsFsAwy2csZnbRrQv6fHKVPhsFDxBwTpYdxbWXS9sB): Witness proof validation fa |
| witness-update | rust (self) | ✅ PASS |  |
| witness-update | ts | ⚠️ XFAIL | TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects |
