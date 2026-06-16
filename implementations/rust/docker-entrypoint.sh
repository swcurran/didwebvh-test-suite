#!/usr/bin/env bash
set -euo pipefail

echo "--- Rust: generate vectors ---"
/app/bin/generate-vectors || true

echo "--- Rust: cross-resolution + negative tests ---"
# test-vectors may exit non-zero on failures; results are recorded in status.md
/app/bin/test-vectors || true
