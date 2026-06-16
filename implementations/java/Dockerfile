# Build image for the Java test harness (didwebvh-java / didwebvh-core).
#
# The harness resolves all paths from System.getProperty("user.dir") (CWD),
# so the entrypoint sets CWD to /workspace/implementations/java/ which is
# mounted from the host.  Compiled classes live at /app/classes/ and deps
# at /app/deps/ — both outside the mounted directory.
#
# At runtime mount:
#   /workspace/vectors               ← <repo>/vectors/
#   /workspace/implementations/java  ← <repo>/implementations/java/

FROM eclipse-temurin:21-jdk-jammy

ARG REPO=https://github.com/decentralized-identity/didwebvh-java
ARG BRANCH=main

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git maven python3 \
    && rm -rf /var/lib/apt/lists/*

# Clone the library and install it into the local Maven repo; save commit for provenance
RUN mkdir -p /app \
    && git clone --depth 1 --branch "$BRANCH" "$REPO" /deps/didwebvh-java \
    && git -C /deps/didwebvh-java rev-parse HEAD > /app/library-commit \
    && mvn -f /deps/didwebvh-java/pom.xml install -q -DskipTests

# Capture the installed library version
RUN mvn -f /deps/didwebvh-java/pom.xml help:evaluate \
      -Dexpression=project.version -q -DforceStdout \
    | tr -d '[:space:]' > /tmp/lib-version

# Copy harness source and update its pom.xml to reference the installed version
WORKDIR /app/src
COPY implementations/java/ .
RUN python3 -c "\
import re; \
lib_version = open('/tmp/lib-version').read().strip(); \
content = open('pom.xml').read(); \
content = re.sub(r'(<artifactId>didwebvh-core</artifactId>\s*<version>)[^<]*', lambda m: m.group(1) + lib_version, content); \
open('pom.xml', 'w').write(content)"

# Compile harness, copy classes and runtime deps to /app/
RUN mvn compile -q \
    && cp -r target/classes /app/classes \
    && mvn dependency:copy-dependencies -q -DoutputDirectory=/app/deps

COPY implementations/java/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

WORKDIR /workspace
ENTRYPOINT ["/app/entrypoint.sh"]
