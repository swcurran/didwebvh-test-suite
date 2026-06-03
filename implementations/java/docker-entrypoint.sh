#!/usr/bin/env bash
# Run with CWD = /workspace/implementations/java/ (mounted from host).
# The Java harness derives all paths from user.dir (CWD):
#   IMPL_ROOT  = CWD                        → /workspace/implementations/java/
#   VECTORS_ROOT = CWD/../../vectors/       → /workspace/vectors/
set -euo pipefail

CP="/app/classes:/app/deps/*"

cd /workspace/implementations/java

echo "--- Java: generate vectors ---"
java -cp "$CP" org.didwebvh.compliance.GenerateVectors

echo "--- Java: cross-resolution + negative tests ---"
# TestVectors may exit non-zero on failures; results are recorded in status.md
java -cp "$CP" org.didwebvh.compliance.TestVectors || true
