# Build image for the TypeScript test harness (Node + pnpm + tsx — aligned
# with didwebvh-ts's own toolchain since it migrated from bun to node+pnpm in
# https://github.com/decentralized-identity/didwebvh-ts/pull/156).
#
# At runtime mount:
#   /workspace/vectors              ← <repo>/vectors/
#   /workspace/implementations/ts   ← <repo>/implementations/ts/
#
# node_modules live at /workspace/node_modules/ (not inside implementations/ts/)
# so they survive the runtime mount and serve the pinned library version.

FROM node:24-slim

ARG REPO=https://github.com/decentralized-identity/didwebvh-ts
ARG BRANCH=main

# Fixed, world-readable corepack cache: `scripts/run` execs the container as
# the host's uid:gid (no passwd entry, no $HOME), so the default per-user
# corepack cache wouldn't be found at runtime and it would try to re-download
# pnpm from the registry on every run. Pointing COREPACK_HOME at a shared path
# populated at build time keeps the container's runtime step fully offline.
ENV COREPACK_HOME=/opt/corepack

# System deps + corepack (pnpm) for both the harness and the vendored library.
# bun is also installed, purely as a build-time fallback for cloning branches
# of didwebvh-ts that predate PR#156 (still bun.lock-based) — the harness
# itself never invokes it.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git jq curl unzip \
    && corepack enable \
    && corepack prepare pnpm@11.10.0 --activate \
    && chmod -R a+rX "$COREPACK_HOME" \
    && curl -fsSL https://bun.sh/install | BUN_INSTALL=/usr/local bash \
    && rm -rf /var/lib/apt/lists/*

# Clone the library, build it, then save the exact commit for provenance.
# Build with whichever toolchain the checked-out commit actually uses: recent
# commits (pnpm-lock.yaml present, post PR#156) build with node+pnpm; older
# commits/branches (bun.lock present) still build with bun.
RUN mkdir -p /app \
    && git clone --depth 1 --branch "$BRANCH" "$REPO" /deps/didwebvh-ts \
    && git -C /deps/didwebvh-ts rev-parse HEAD > /app/library-commit \
    && cd /deps/didwebvh-ts \
    && if [ -f pnpm-lock.yaml ]; then \
         pnpm install --frozen-lockfile && pnpm run build; \
       else \
         bun install && bun run build; \
       fi

WORKDIR /workspace

# Copy manifests, repoint didwebvh-ts to the cloned local copy, then install.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN jq '.dependencies["didwebvh-ts"] = "file:///deps/didwebvh-ts"' package.json \
      > /tmp/package.json && mv /tmp/package.json package.json \
    && pnpm install --no-frozen-lockfile

# Copy harness source (overridden at runtime by the host mount, but useful for
# standalone image use and for import resolution during build).
COPY implementations/ts/ ./implementations/ts/

CMD ["pnpm", "exec", "tsx", "implementations/ts/src/generator.ts"]
