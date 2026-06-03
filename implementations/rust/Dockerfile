# Build image for the Rust test harness.
#
# CARGO_MANIFEST_DIR is baked at compile time.  We compile with the harness
# source at /workspace/implementations/rust/ — the same path that is mounted
# at runtime — so the baked-in VECTORS_ROOT and IMPL_DIR constants resolve
# correctly against the mounted host directories.
#
# Binaries are placed at /app/bin/ (outside the mount) so they are not hidden
# when implementations/rust/ is mounted from the host.
#
# At runtime mount:
#   /workspace/vectors                ← <repo>/vectors/
#   /workspace/implementations/rust   ← <repo>/implementations/rust/

# ── builder ──────────────────────────────────────────────────────────────────
FROM rust:latest AS builder

ARG REPO=https://github.com/decentralized-identity/didwebvh-rs
ARG BRANCH=main

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Set up the harness source at the exact path that matches the runtime mount.
# This ensures env!("CARGO_MANIFEST_DIR") bakes in as /workspace/implementations/rust.
WORKDIR /workspace/implementations/rust
COPY implementations/rust/ .

# Rewrite the library dependency to use the specified repo + branch.
# Remove any existing Cargo.lock so cargo fetches fresh from the branch HEAD.
RUN sed -i \
      "s|didwebvh-rs = { git = \"[^\"]*\"|didwebvh-rs = { git = \"${REPO}\", branch = \"${BRANCH}\"|" \
      Cargo.toml \
    && rm -f Cargo.lock

# Build release binaries into /app/target (not inside the harness tree)
RUN CARGO_TARGET_DIR=/app/target cargo build --release

# Extract the exact commit cargo resolved for the library from Cargo.lock
RUN grep -A3 'name = "didwebvh-rs"' Cargo.lock \
    | grep 'source' \
    | grep -oE '[a-f0-9]{40}' \
    > /app/library-commit

# ── runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/generate-vectors /app/bin/generate-vectors
COPY --from=builder /app/target/release/test-vectors      /app/bin/test-vectors
COPY --from=builder /app/library-commit                   /app/library-commit

COPY implementations/rust/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

WORKDIR /workspace
ENTRYPOINT ["/app/entrypoint.sh"]
