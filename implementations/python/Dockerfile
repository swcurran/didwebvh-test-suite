# Build image for the Python test harness.
#
# At runtime mount:
#   /workspace/vectors                 ← <repo>/vectors/
#   /workspace/implementations/python  ← <repo>/implementations/python/
#
# The did-webvh library is installed into the system Python inside the image
# so it survives the runtime mount of implementations/python/.

FROM python:3.14-slim

ARG REPO=https://github.com/decentralized-identity/didwebvh-py
ARG BRANCH=main

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Clone and install the library at the specified branch; save the exact commit for provenance
RUN mkdir -p /app \
    && git clone --depth 1 --branch "$BRANCH" "$REPO" /deps/did-webvh-py \
    && git -C /deps/did-webvh-py rev-parse HEAD > /app/library-commit \
    && pip install --no-cache-dir /deps/did-webvh-py

# Install test runner and async support
RUN pip install --no-cache-dir pytest pytest-asyncio pyyaml

WORKDIR /workspace

# Copy harness source (overridden at runtime by the host mount)
COPY implementations/python/ ./implementations/python/

# Entrypoint lives outside the mounted directory so it is always available
COPY implementations/python/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
