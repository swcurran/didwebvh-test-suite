# Build image for the Dart test harness (didwebvh-dart).
#
# Strategy: clone the library to /deps/didwebvh-dart, inject the harness as a
# workspace member (packages/harness/), resolve deps in the workspace root, and
# compile the two binaries to AOT executables at /app/.
#
# At runtime mount:
#   /workspace/vectors                  ← <repo>/vectors/
#   /workspace/implementations/dart     ← <repo>/implementations/dart/

FROM dart:stable

ARG REPO=https://github.com/IVIR3zaM/didwebvh-dart
ARG BRANCH=main

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git python3 \
    && rm -rf /var/lib/apt/lists/*

# Clone the library; save commit for provenance
RUN mkdir -p /app \
    && git clone --depth 1 --branch "$BRANCH" "$REPO" /deps/didwebvh-dart \
    && git -C /deps/didwebvh-dart rev-parse HEAD > /app/library-commit

# Capture the library version from the core package pubspec
RUN python3 -c "\
import re; \
content = open('/deps/didwebvh-dart/packages/didwebvh/pubspec.yaml').read(); \
m = re.search(r'^version:\s*[\"\']{0,1}([^\"\'\\n]+)[\"\']{0,1}', content, re.MULTILINE); \
print(m.group(1).strip() if m else 'unknown')" > /tmp/lib-version

# Inject the harness into the workspace:
#   1. Copy harness source to packages/harness/ inside the library workspace
#   2. Append the harness member to the workspace root pubspec.yaml

COPY implementations/dart/ /deps/didwebvh-dart/packages/harness/

RUN python3 -c "\
import re; \
content = open('/deps/didwebvh-dart/pubspec.yaml').read(); \
content = re.sub(r'(workspace:\s*(?:\n  - [^\n]+)+)', lambda m: m.group(0) + '\n  - packages/harness', content); \
open('/deps/didwebvh-dart/pubspec.yaml', 'w').write(content)"

# Resolve all workspace dependencies and compile the two executables
WORKDIR /deps/didwebvh-dart
RUN dart pub get

WORKDIR /deps/didwebvh-dart/packages/harness
RUN dart compile exe bin/generate_vectors.dart -o /app/generate_vectors \
    && dart compile exe bin/test_vectors.dart -o /app/test_vectors

COPY implementations/dart/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

WORKDIR /workspace
ENTRYPOINT ["/app/entrypoint.sh"]
