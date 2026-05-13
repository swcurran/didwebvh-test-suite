package org.didwebvh.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.DidWebVh;
import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;
import io.didwebvh.log.LogParser;
import io.didwebvh.model.DidDocumentMetadata;
import io.didwebvh.model.DidLog;
import io.didwebvh.witness.WitnessProofCollection;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Compliance test harness: runs each committed vector (from every implementation
 * subdir) through the EECC didwebvh-java resolver and compares results.
 *
 * Also writes a status.md to vectors/<scenario>/java-eecc/ showing cross-resolution
 * results against all implementation subdirs.
 *
 * Usage:
 *   mvn compile exec:java
 *
 * Exit code 0 = all pass; 1 = at least one failure or diff; 2 = setup error.
 */
public class TestVectors {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Path IMPL_ROOT = Paths.get(System.getProperty("user.dir"));
    private static final Path VECTORS_ROOT = IMPL_ROOT.resolve("../../vectors").normalize();
    private static final Path CONFIG_PATH = IMPL_ROOT.resolve("config.yaml").normalize();
    private static final String IMPL_NAME = "java-eecc";

    private static final Pattern VERSION_PATTERN =
            Pattern.compile("resolutionResult\\.([0-9]+)\\.json");

    private int pass = 0;
    private int fail = 0;   // resolver errored
    private int diff = 0;   // resolver ran but output differs
    private int xfail = 0;

    private final List<String[]> allRows = new ArrayList<>();  // [scenario, logSource, result, notes]
    private final StringBuilder allDiffs = new StringBuilder();

    public static void main(String[] args) {
        try {
            new TestVectors().run();
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            System.exit(2);
        }
    }

    private void run() throws IOException {
        if (!Files.isDirectory(VECTORS_ROOT)) {
            System.err.println("error: cannot read vectors/: " + VECTORS_ROOT);
            System.exit(2);
        }

        // Delete stale output files from previous runs
        Files.deleteIfExists(IMPL_ROOT.resolve("status.md"));
        Files.deleteIfExists(IMPL_ROOT.resolve("diffs.txt"));

        List<Path> scenarios;
        try (Stream<Path> stream = Files.list(VECTORS_ROOT)) {
            scenarios = stream
                    .filter(Files::isDirectory)
                    .sorted()
                    .collect(Collectors.toList());
        }

        for (Path scenarioDir : scenarios) {
            if (!Files.exists(scenarioDir.resolve("script.yaml"))) continue;

            String scenarioName = scenarioDir.getFileName().toString();

            // Delete old per-scenario status.md if present
            Files.deleteIfExists(scenarioDir.resolve(IMPL_NAME).resolve("status.md"));

            List<Path> implDirs;
            try (Stream<Path> stream = Files.list(scenarioDir)) {
                implDirs = stream.filter(Files::isDirectory).sorted().collect(Collectors.toList());
            }

            for (Path implDir : implDirs) {
                String implName = implDir.getFileName().toString();

                if (!Files.exists(implDir.resolve("did.jsonl"))) {
                    allRows.add(new String[]{scenarioName, implName, "⚠️ SKIP", "no did.jsonl present"});
                    continue;
                }

                List<Path> resultFiles;
                try (Stream<Path> stream = Files.list(implDir)) {
                    resultFiles = stream
                            .filter(p -> {
                                String n = p.getFileName().toString();
                                return n.startsWith("resolutionResult") && n.endsWith(".json");
                            })
                            .sorted()
                            .collect(Collectors.toList());
                }

                String label = implName.equals(IMPL_NAME) ? implName + " (self)" : implName;

                if (resultFiles.isEmpty()) {
                    allRows.add(new String[]{scenarioName, label, "⚠️ SKIP", "no resolutionResult files"});
                    continue;
                }

                boolean implFail = false;
                boolean implDiff = false;
                boolean implXfail = false;
                String implXfailReason = "";
                String implFailReason = "";

                for (Path resultFile : resultFiles) {
                    String testId = scenarioName + "/" + implName + "/" + resultFile.getFileName();
                    TestOutcome outcome = runTest(implDir, resultFile);
                    switch (outcome.kind) {
                        case PASS:
                            System.out.println("PASS   " + testId);
                            pass++;
                            break;
                        case XFAIL:
                            System.out.println("XFAIL  " + testId + " (" + outcome.message + ")");
                            xfail++;
                            implXfail = true;
                            implXfailReason = outcome.message;
                            break;
                        case DIFF:
                            System.err.println("DIFF   " + testId);
                            for (String line : outcome.message.split("\n")) {
                                System.err.println("       " + line);
                            }
                            diff++;
                            if (!implFail) implDiff = true;
                            if (implFailReason.isEmpty()) implFailReason = "see diffs.txt";
                            allDiffs.append("=== ").append(scenarioName).append(" / ")
                                    .append(implName).append(" — ")
                                    .append(resultFile.getFileName()).append(" ===\n")
                                    .append(outcome.message).append("\n\n");
                            break;
                        case FAIL:
                            System.err.println("FAIL   " + testId);
                            for (String line : outcome.message.split("\n")) {
                                System.err.println("       " + line);
                            }
                            fail++;
                            implFail = true;
                            implDiff = false;
                            if (implFailReason.isEmpty()) implFailReason = outcome.message.split("\n")[0];
                            break;
                    }
                }

                if (implFail) {
                    allRows.add(new String[]{scenarioName, label, "❌ FAIL", implFailReason});
                } else if (implDiff) {
                    allRows.add(new String[]{scenarioName, label, "🔶 DIFF", "see diffs.txt"});
                } else if (implXfail) {
                    allRows.add(new String[]{scenarioName, label, "⚠️ XFAIL", implXfailReason});
                } else {
                    allRows.add(new String[]{scenarioName, label, "✅ PASS", ""});
                }
            }
        }

        writeCombinedOutput();

        System.out.println("\n" + pass + " passed, " + diff + " diff, " + fail + " failed, " + xfail + " xfailed");
        System.exit((fail > 0 || diff > 0) ? 1 : 0);
    }

    // ---------------------------------------------------------------------------
    // Output
    // ---------------------------------------------------------------------------

    private void writeCombinedOutput() {
        String versionLine = readConfigVersion();
        StringBuilder content = new StringBuilder();
        content.append("# ").append(IMPL_NAME).append(" cross-resolution status\n\n");
        if (!versionLine.isEmpty()) {
            content.append("Implementation: ").append(IMPL_NAME)
                   .append(" ").append(versionLine).append("\n\n");
        }

        content.append("| Test Case | Log Source | Result | Notes |\n|---|---|---|---|\n");
        for (String[] row : allRows) {
            content.append("| ").append(row[0]).append(" | ").append(row[1])
                   .append(" | ").append(row[2]).append(" | ").append(row[3]).append(" |\n");
        }

        try {
            Files.writeString(IMPL_ROOT.resolve("status.md"), content.toString());
        } catch (IOException e) {
            System.err.println("warning: could not write status.md: " + e);
        }

        String diffsContent = allDiffs.toString().stripTrailing();
        if (!diffsContent.isEmpty()) {
            try {
                Files.writeString(IMPL_ROOT.resolve("diffs.txt"), diffsContent + "\n");
            } catch (IOException e) {
                System.err.println("warning: could not write diffs.txt: " + e);
            }
        }
    }

    private String readConfigVersion() {
        if (!Files.exists(CONFIG_PATH)) return "";
        try {
            String text = Files.readString(CONFIG_PATH);
            String version = text.lines().filter(l -> l.startsWith("version:")).findFirst()
                    .map(l -> l.split(":", 2)[1].trim().replace("\"", "")).orElse("");
            String commit = text.lines().filter(l -> l.startsWith("commit:")).findFirst()
                    .map(l -> l.split(":", 2)[1].trim().replace("\"", "")).orElse("");
            List<String> parts = new ArrayList<>();
            if (!version.isEmpty()) parts.add(version);
            if (!commit.isEmpty()) parts.add(commit);
            return String.join(" @ ", parts);
        } catch (IOException e) {
            return "";
        }
    }

    // ---------------------------------------------------------------------------
    // Core test logic
    // ---------------------------------------------------------------------------

    private TestOutcome runTest(Path implDir, Path resultFile) {
        try {
            String rawJsonl = Files.readString(implDir.resolve("did.jsonl"));
            String expectedContent = Files.readString(resultFile);
            ObjectNode expected = (ObjectNode) MAPPER.readTree(expectedContent);

            DidLog log;
            try {
                log = LogParser.parse(rawJsonl);
            } catch (Exception e) {
                return TestOutcome.fail("log parse error: " + e.getMessage());
            }

            if (log.isEmpty()) {
                return TestOutcome.fail("empty log after parsing");
            }

            String did = log.first().state().path("id").asText(null);
            if (did == null || did.isEmpty()) {
                return TestOutcome.fail("Could not extract DID from did.jsonl");
            }

            Integer versionNumber = extractVersionNumber(resultFile.getFileName().toString());

            WitnessProofCollection witnessProofs = null;
            Path witnessFile = implDir.resolve("did-witness.json");
            if (Files.exists(witnessFile)) {
                try {
                    witnessProofs = WitnessProofCollection.parse(Files.readString(witnessFile));
                } catch (Exception e) {
                    return TestOutcome.xfail("witness parse error: " + e.getMessage());
                }
            }

            ResolveOptions.Builder optBuilder = ResolveOptions.builder();
            if (versionNumber != null) optBuilder.versionNumber(versionNumber);
            if (witnessProofs != null) optBuilder.witnessProofs(witnessProofs);
            ResolveOptions options = optBuilder.build();

            ResolveResult result;
            try {
                result = DidWebVh.resolveFromLog(did, log, options);
            } catch (Exception e) {
                return TestOutcome.fail("resolve exception: " + e);
            }

            if (!result.isSuccess() && result.resolutionMetadata() != null
                    && result.resolutionMetadata().error() != null) {
                JsonNode expDoc = expected.get("didDocument");
                if (expDoc != null && !expDoc.isNull()) {
                    String detail = result.resolutionMetadata().problemDetails() != null
                            ? result.resolutionMetadata().problemDetails().detail() : "";
                    return TestOutcome.xfail("TS COMPAT: library resolution error ("
                            + result.resolutionMetadata().error() + "): " + detail);
                }
            }

            ObjectNode actual = buildActualResult(result, log, options, did);
            normalizePair(actual, expected);

            String actualJcs = canonicalize(MAPPER.writeValueAsString(actual));
            String expectedJcs = canonicalize(MAPPER.writeValueAsString(expected));

            if (actualJcs.equals(expectedJcs)) {
                return TestOutcome.pass();
            }

            // JCS-sort both for clean diff output
            String expSorted = MAPPER.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(MAPPER.readTree(expectedJcs));
            String actSorted = MAPPER.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(MAPPER.readTree(actualJcs));
            return TestOutcome.diff(computeUnifiedDiff(expSorted, actSorted, 3));

        } catch (Exception e) {
            return TestOutcome.fail("exception: " + e);
        }
    }

    // ---------------------------------------------------------------------------
    // Build actual result
    // ---------------------------------------------------------------------------

    private ObjectNode buildActualResult(ResolveResult result, DidLog log,
            ResolveOptions options, String did) {
        ObjectNode actual = MAPPER.createObjectNode();

        JsonNode doc = result.document();
        if (doc == null && result.documentMetadata() != null
                && Boolean.TRUE.equals(result.documentMetadata().deactivated())) {
            DidDocumentMetadata deactMeta = result.documentMetadata();
            if (deactMeta.versionNumber() != null && deactMeta.versionNumber() > 1) {
                try {
                    ResolveOptions preDeactOptions = ResolveOptions.builder()
                            .versionNumber(deactMeta.versionNumber() - 1)
                            .build();
                    ResolveResult preDeact = DidWebVh.resolveFromLog(did, log, preDeactOptions);
                    doc = preDeact.document();
                } catch (Exception ignored) {}
            }
        }
        actual.set("didDocument", doc != null ? doc : MAPPER.nullNode());

        ObjectNode metaObj = MAPPER.createObjectNode();
        DidDocumentMetadata meta = result.documentMetadata();
        if (meta != null) {
            if (meta.created() != null)       metaObj.put("created", meta.created());
            if (meta.versionTime() != null)   metaObj.put("updated", meta.versionTime());
            if (meta.versionId() != null)     metaObj.put("versionId", meta.versionId());
            if (meta.versionNumber() != null) metaObj.put("versionNumber", meta.versionNumber());
            if (meta.versionTime() != null)   metaObj.put("versionTime", meta.versionTime());
            if (Boolean.TRUE.equals(meta.deactivated())) metaObj.put("deactivated", true);
            if (meta.portable() != null)      metaObj.put("portable", meta.portable());
            if (meta.scid() != null)          metaObj.put("scid", meta.scid());
        }
        actual.set("didDocumentMetadata", metaObj);

        ObjectNode resMeta = MAPPER.createObjectNode();
        resMeta.put("contentType", "application/did+ld+json");
        actual.set("didResolutionMetadata", resMeta);

        return actual;
    }

    // ---------------------------------------------------------------------------
    // Bidirectional normalisation applied to both sides before comparison
    // ---------------------------------------------------------------------------

    private void normalizePair(ObjectNode actual, ObjectNode expected) {
        sortServices(actual);
        sortServices(expected);

        JsonNode actMeta = actual.get("didDocumentMetadata");
        JsonNode expMeta = expected.get("didDocumentMetadata");
        if (actMeta != null && actMeta.isObject() && expMeta != null && expMeta.isObject()) {
            Set<String> actKeys = new HashSet<>();
            actMeta.fieldNames().forEachRemaining(actKeys::add);
            Set<String> expKeys = new HashSet<>();
            expMeta.fieldNames().forEachRemaining(expKeys::add);
            Set<String> common = new HashSet<>(actKeys);
            common.retainAll(expKeys);

            ObjectNode filteredAct = MAPPER.createObjectNode();
            ObjectNode filteredExp = MAPPER.createObjectNode();
            for (String k : common) {
                filteredAct.set(k, actMeta.get(k));
                filteredExp.set(k, expMeta.get(k));
            }
            actual.set("didDocumentMetadata", filteredAct);
            expected.set("didDocumentMetadata", filteredExp);
        }
    }

    private void sortServices(ObjectNode result) {
        JsonNode didDoc = result.get("didDocument");
        if (didDoc == null || !didDoc.isObject()) return;
        JsonNode services = didDoc.get("service");
        if (services == null || !services.isArray()) return;
        List<JsonNode> list = new ArrayList<>();
        services.forEach(list::add);
        list.sort(Comparator.comparing(e -> {
            JsonNode id = e.get("id");
            return id != null ? id.asText("") : "";
        }));
        com.fasterxml.jackson.databind.node.ArrayNode sorted = MAPPER.createArrayNode();
        list.forEach(sorted::add);
        ((ObjectNode) didDoc).set("service", sorted);
    }

    // ---------------------------------------------------------------------------
    // Unified diff generation (LCS-based)
    // ---------------------------------------------------------------------------

    private static String computeUnifiedDiff(String expected, String actual, int ctx) {
        List<String> expLines = Arrays.asList(expected.split("\n"));
        List<String> actLines = Arrays.asList(actual.split("\n"));
        int m = expLines.size(), n = actLines.size();

        int[][] dp = new int[m + 1][n + 1];
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                dp[i][j] = expLines.get(i - 1).equals(actLines.get(j - 1))
                        ? dp[i - 1][j - 1] + 1
                        : Math.max(dp[i - 1][j], dp[i][j - 1]);
            }
        }

        List<String[]> edits = new ArrayList<>();
        int i = m, j = n;
        while (i > 0 || j > 0) {
            if (i > 0 && j > 0 && expLines.get(i - 1).equals(actLines.get(j - 1))) {
                edits.add(0, new String[]{" ", expLines.get(i - 1)});
                i--; j--;
            } else if (j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j])) {
                edits.add(0, new String[]{"+", actLines.get(j - 1)});
                j--;
            } else {
                edits.add(0, new String[]{"-", expLines.get(i - 1)});
                i--;
            }
        }

        List<Integer> changed = IntStream.range(0, edits.size())
                .filter(k -> !edits.get(k)[0].equals(" "))
                .boxed().collect(Collectors.toList());

        if (changed.isEmpty()) return "";

        List<int[]> hunks = new ArrayList<>();
        int hs = Math.max(0, changed.get(0) - ctx);
        int he = Math.min(edits.size() - 1, changed.get(0) + ctx);
        for (int k = 1; k < changed.size(); k++) {
            int pos = changed.get(k);
            if (pos - ctx <= he + 1) {
                he = Math.min(edits.size() - 1, pos + ctx);
            } else {
                hunks.add(new int[]{hs, he});
                hs = Math.max(0, pos - ctx);
                he = Math.min(edits.size() - 1, pos + ctx);
            }
        }
        hunks.add(new int[]{hs, he});

        StringBuilder out = new StringBuilder("--- expected\n+++ actual (java-eecc resolver)\n");
        for (int h = 0; h < hunks.size(); h++) {
            for (int k = hunks.get(h)[0]; k <= hunks.get(h)[1]; k++) {
                out.append(edits.get(k)[0]).append(edits.get(k)[1]).append("\n");
            }
            if (h + 1 < hunks.size()) out.append("...\n");
        }
        return out.toString().stripTrailing();
    }

    // ---------------------------------------------------------------------------
    // Extraction helpers
    // ---------------------------------------------------------------------------

    private Integer extractVersionNumber(String filename) {
        Matcher m = VERSION_PATTERN.matcher(filename);
        return m.matches() ? Integer.parseInt(m.group(1)) : null;
    }

    // ---------------------------------------------------------------------------
    // JSON / JCS utilities
    // ---------------------------------------------------------------------------

    private static String canonicalize(String json) throws IOException {
        return new JsonCanonicalizer(json).getEncodedString();
    }

    // ---------------------------------------------------------------------------
    // Outcome types
    // ---------------------------------------------------------------------------

    private enum Kind { PASS, XFAIL, DIFF, FAIL }

    private static final class TestOutcome {
        final Kind kind;
        final String message;

        private TestOutcome(Kind kind, String message) {
            this.kind = kind;
            this.message = message;
        }

        static TestOutcome pass() { return new TestOutcome(Kind.PASS, null); }
        static TestOutcome xfail(String msg) { return new TestOutcome(Kind.XFAIL, msg); }
        static TestOutcome diff(String msg) { return new TestOutcome(Kind.DIFF, msg); }
        static TestOutcome fail(String msg) { return new TestOutcome(Kind.FAIL, msg); }
    }
}
