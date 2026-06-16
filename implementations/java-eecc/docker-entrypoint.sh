#!/usr/bin/env bash
set -euo pipefail

CP="/app/classes:/app/deps/*"

cd /workspace/implementations/java-eecc

echo "--- Java-EECC: generate vectors ---"
java -cp "$CP" org.didwebvh.compliance.GenerateVectors

echo "--- Java-EECC: cross-resolution + negative tests ---"
java -cp "$CP" org.didwebvh.compliance.TestVectors || true
