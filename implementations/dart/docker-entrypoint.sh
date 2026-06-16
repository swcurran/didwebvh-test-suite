#!/usr/bin/env bash
# Run with CWD = /workspace/implementations/dart/ (mounted from host).
# The Dart harness derives all paths from the working directory:
#   IMPL_ROOT  = CWD                        → /workspace/implementations/dart/
#   VECTORS_ROOT = CWD/../../vectors/       → /workspace/vectors/
set -euo pipefail

cd /workspace/implementations/dart

echo "--- Dart: generate vectors ---"
/app/generate_vectors

echo "--- Dart: cross-resolution + negative tests ---"
# test_vectors may exit non-zero on failures; results are recorded in status.md
/app/test_vectors || true
