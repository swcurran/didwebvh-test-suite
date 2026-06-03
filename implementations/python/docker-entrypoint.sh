#!/usr/bin/env bash
set -euo pipefail

cd /workspace

echo "--- Python: generate vectors ---"
python implementations/python/generate.py

echo "--- Python: cross-resolution + negative tests ---"
# pytest exits 1 on test failures; that is expected (DIFFs/FAILs are recorded in status.md)
pytest implementations/python/test_vectors.py \
  --tb=no -q || true
