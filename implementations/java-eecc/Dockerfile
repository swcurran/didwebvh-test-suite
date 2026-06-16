# Build image for the Java-EECC test harness (de.eecc.did:webvh).
#
# The EECC library repo has its Maven module under didwebvh-java/ (not at the root).
# The EECC library requires Maven 3.9+; we install it directly from Apache.
# Same CWD-based path strategy as the java/ harness.
#
# At runtime mount:
#   /workspace/vectors                    ← <repo>/vectors/
#   /workspace/implementations/java-eecc  ← <repo>/implementations/java-eecc/

FROM eclipse-temurin:21-jdk-jammy

ARG REPO=https://github.com/european-epc-competence-center/didwebvh
ARG BRANCH=main
ARG MAVEN_VERSION=3.9.6

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Maven 3.9+ (the apt version 3.6.3 is too old for the EECC library)
RUN curl -fsSL "https://archive.apache.org/dist/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz" \
    | tar -xz -C /opt \
    && ln -s /opt/apache-maven-${MAVEN_VERSION}/bin/mvn /usr/local/bin/mvn

# Clone the library and install it into the local Maven repo; save commit for provenance.
# The Maven module is in the didwebvh-java/ subdirectory of the repo.
RUN mkdir -p /app \
    && git clone --depth 1 --branch "$BRANCH" "$REPO" /deps/didwebvh-eecc \
    && git -C /deps/didwebvh-eecc rev-parse HEAD > /app/library-commit \
    && mvn -f /deps/didwebvh-eecc/didwebvh-java/pom.xml install -q -DskipTests

# Capture the installed library version
RUN mvn -f /deps/didwebvh-eecc/didwebvh-java/pom.xml help:evaluate \
      -Dexpression=project.version -q -DforceStdout \
    | tr -d '[:space:]' > /tmp/lib-version

# Copy harness source and update its pom.xml to reference the installed version
WORKDIR /app/src
COPY implementations/java-eecc/ .
RUN python3 -c "\
import re; \
lib_version = open('/tmp/lib-version').read().strip(); \
content = open('pom.xml').read(); \
content = re.sub(r'(<artifactId>webvh</artifactId>\s*<version>)[^<]*', lambda m: m.group(1) + lib_version, content); \
open('pom.xml', 'w').write(content)"

# Compile harness, copy classes and runtime deps to /app/
RUN mvn compile -q \
    && cp -r target/classes /app/classes \
    && mvn dependency:copy-dependencies -q -DoutputDirectory=/app/deps

COPY implementations/java-eecc/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

WORKDIR /workspace
ENTRYPOINT ["/app/entrypoint.sh"]
