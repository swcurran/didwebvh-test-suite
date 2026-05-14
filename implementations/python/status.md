# python status

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
| basic-update | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| deactivate | java | 🔶 DIFF | see diffs.txt |
| deactivate | java-eecc | 🔶 DIFF | see diffs.txt |
| deactivate | python | 🔶 DIFF | see diffs.txt |
| deactivate | rust | 🔶 DIFF | see diffs.txt |
| deactivate | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| key-rotation | java | 🔶 DIFF | see diffs.txt |
| key-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| key-rotation | python | 🔶 DIFF | see diffs.txt |
| key-rotation | rust | 🔶 DIFF | see diffs.txt |
| key-rotation | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
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
| multi-update | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| multi-update | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| multi-update | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| multiple-update-keys | java-eecc | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | python | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | rust | 🔶 DIFF | see diffs.txt |
| multiple-update-keys | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| portable | java | 🔶 DIFF | see diffs.txt |
| portable | java-eecc | 🔶 DIFF | see diffs.txt |
| portable | python | 🔶 DIFF | see diffs.txt |
| portable | rust | 🔶 DIFF | see diffs.txt |
| portable | ts | ✅ PASS |  |
| portable-move | java | 🔶 DIFF | see diffs.txt |
| portable-move | python | 🔶 DIFF | see diffs.txt |
| portable-move | rust | 🔶 DIFF | see diffs.txt |
| portable-move | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| pre-rotation | java | 🔶 DIFF | see diffs.txt |
| pre-rotation | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation | python | 🔶 DIFF | see diffs.txt |
| pre-rotation | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation | ts | ✅ PASS |  |
| pre-rotation-consume | java-eecc | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | python | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | rust | 🔶 DIFF | see diffs.txt |
| pre-rotation-consume | ts | ✅ PASS |  |
| services | java | 🔶 DIFF | see diffs.txt |
| services | java-eecc | 🔶 DIFF | see diffs.txt |
| services | python | 🔶 DIFF | see diffs.txt |
| services | rust | 🔶 DIFF | see diffs.txt |
| services | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
| witness-threshold | java | 🔶 DIFF | see diffs.txt |
| witness-threshold | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-threshold | python | 🔶 DIFF | see diffs.txt |
| witness-threshold | rust | 🔶 DIFF | see diffs.txt |
| witness-threshold | ts | ✅ PASS |  |
| witness-update | java | 🔶 DIFF | see diffs.txt |
| witness-update | java-eecc | 🔶 DIFF | see diffs.txt |
| witness-update | python | ✅ PASS |  |
| witness-update | rust | 🔶 DIFF | see diffs.txt |
| witness-update | ts | ⚠️ XFAIL | TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation entries; Python library rejects an empty list. Fix |
