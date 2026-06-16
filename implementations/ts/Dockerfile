# Build image for the TypeScript/Bun test harness.
#
# At runtime mount:
#   /workspace/vectors              ← <repo>/vectors/
#   /workspace/implementations/ts   ← <repo>/implementations/ts/
#
# node_modules live at /workspace/node_modules/ (not inside implementations/ts/)
# so they survive the runtime mount and serve the pinned library version.

FROM oven/bun:1

ARG REPO=https://github.com/decentralized-identity/didwebvh-ts
ARG BRANCH=main

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git jq \
    && rm -rf /var/lib/apt/lists/*

# Clone the library, build it, then save the exact commit for provenance
RUN mkdir -p /app \
    && git clone --depth 1 --branch "$BRANCH" "$REPO" /deps/didwebvh-ts \
    && git -C /deps/didwebvh-ts rev-parse HEAD > /app/library-commit \
    && cd /deps/didwebvh-ts && bun install && bun run build

WORKDIR /workspace

# Copy package.json, repoint didwebvh-ts to the cloned local copy, then install.
# Do NOT copy bun.lockb — it references the old file: path.
COPY package.json ./
RUN jq '.dependencies["didwebvh-ts"] = "file:///deps/didwebvh-ts"' package.json \
      > /tmp/package.json && mv /tmp/package.json package.json \
    && bun install

# Copy harness source (overridden at runtime by the host mount, but useful for
# standalone image use and for import resolution during build).
COPY implementations/ts/ ./implementations/ts/

CMD ["bun", "run", "implementations/ts/src/generator.ts"]
