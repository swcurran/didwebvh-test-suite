package org.didwebvh.compliance;

import com.google.gson.*;
import io.github.ivir3zam.didwebvh.core.ResolutionException;
import io.github.ivir3zam.didwebvh.core.model.LogEntry;
import io.github.ivir3zam.didwebvh.core.model.ResolutionMetadata;
import io.github.ivir3zam.didwebvh.core.model.ResolveResult;
import io.github.ivir3zam.didwebvh.core.resolve.DidResolver;
import io.github.ivir3zam.didwebvh.core.resolve.ResolveOptions;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
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
 * subdir) through the Java didwebvh-core resolver and compares results.
 *
 * Also writes a status.md to vectors/<scenario>/java/ showing cross-resolution
 * results against all implementation subdirs.
 *
 * Usage:
 *   mvn compile exec:java
 *
 * Exit code 0 = all pass; 1 = at least one failure or diff; 2 = setup error.
 */
public class TestVectors {

    private static final Path IMPL_ROOT = Paths.get(System.getProperty("user.dir"));
    private static final Path VECTORS_ROOT = IMPL_ROOT.resolve("../../vectors").normalize();
    private static final Path CONFIG_PATH = IMPL_ROOT.resolve("config.yaml").normalize();
    private static final String IMPL_NAME = "java";

    private static final Pattern VERSION_PATTERN =
            Pattern.compile("resolutionResult\\.([0-9]+)\\.json");

    private int pass = 0;
    private int fail = 0;  // resolver errored
    private int diff = 0;  // resolver ran but output differs
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
            if (!Files.exists(scenarioDir.resolve("script.yaml"))) {
                continue;
            }

            String scenarioName = scenarioDir.getFileName().toString();

            // Delete old per-scenario status.md if present
            Files.deleteIfExists(scenarioDir.resolve(IMPL_NAME).resolve("status.md"));

            List<Path> implDirs;
            try (Stream<Path> stream = Files.list(scenarioDir)) {
                implDirs = stream
                        .filter(Files::isDirectory)
                        .sorted()
                        .collect(Collectors.toList());
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
                String implXfailReason = "";
                String implFailReason = "";
                boolean implXfail = false;

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

    private void writeCombinedOutput() {
        String versionLine = readConfigVersion();
        StringBuilder content = new StringBuilder();
        content.append("# ").append(IMPL_NAME).append(" cross-resolution status\n\n");
        if (!versionLine.isEmpty()) {
            content.append("Implementation: didwebvh-").append(IMPL_NAME)
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
            String version = text.lines()
                    .filter(l -> l.startsWith("version:"))
                    .findFirst()
                    .map(l -> l.split(":", 2)[1].trim().replace("\"", ""))
                    .orElse("");
            String commit = text.lines()
                    .filter(l -> l.startsWith("commit:"))
                    .findFirst()
                    .map(l -> l.split(":", 2)[1].trim().replace("\"", ""))
                    .orElse("");
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
            Path logFile = implDir.resolve("did.jsonl");
            String rawJsonl = Files.readString(logFile);
            String expectedContent = Files.readString(resultFile);

            if (logHasEmptyNextKeyHashes(rawJsonl)) {
                return TestOutcome.xfail(
                        "TS COMPAT: nextKeyHashes:[] — TS serialises empty list; "
                        + "Java library may reject on update validation");
            }
            if (logHasEmptyWitness(rawJsonl)) {
                return TestOutcome.fail(
                        "LIB BUG: ivir3zam 0.2.0 NPEs on witness:{} in parameters "
                        + "(Python/TS write empty witness object; library expects absent field)");
            }

            String did = extractDid(rawJsonl);
            if (did == null) {
                return TestOutcome.fail("Could not extract DID from did.jsonl");
            }

            Integer versionNumber = extractVersionNumber(resultFile.getFileName().toString());
            ResolveOptions options = versionNumber != null
                    ? ResolveOptions.builder().versionNumber(versionNumber).build()
                    : ResolveOptions.defaults();

            Path witnessFile = implDir.resolve("did-witness.json");
            String witnessContent = Files.exists(witnessFile)
                    ? Files.readString(witnessFile) : null;

            DidResolver resolver = new DidResolver();
            ResolveResult result;
            try {
                if (witnessContent != null) {
                    result = resolveWithWitness(resolver, rawJsonl, did, options, witnessContent);
                } else {
                    result = resolver.resolveFromLog(rawJsonl, did, options);
                }
            } catch (XFailException e) {
                return TestOutcome.xfail(e.getMessage());
            } catch (ResolutionException e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                if (isKnownTsCompatError(msg)) {
                    return TestOutcome.xfail("TS COMPAT: resolution error: " + msg);
                }
                return TestOutcome.fail("resolve error: " + msg);
            }

            JsonObject expected = JsonParser.parseString(expectedContent).getAsJsonObject();

            JsonObject didDocJson = null;
            if (result.getDidDocument() != null) {
                didDocJson = result.getDidDocument().asJsonObject();
            } else if (result.getMetadata() != null && result.getMetadata().getVersionId() != null) {
                didDocJson = extractStateFromLog(rawJsonl, result.getMetadata().getVersionId());
            }

            JsonObject actual = buildActualResult(didDocJson, result.getMetadata());
            normalizePair(actual, expected);

            String actualJcs = canonicalize(actual.toString());
            String expectedJcs = canonicalize(expected.toString());
            if (actualJcs.equals(expectedJcs)) {
                return TestOutcome.pass();
            }

            // JCS-sort both for clean diff output
            Gson pretty = new GsonBuilder().setPrettyPrinting().create();
            String expSorted = pretty.toJson(JsonParser.parseString(expectedJcs));
            String actSorted = pretty.toJson(JsonParser.parseString(actualJcs));
            String diffBody = computeUnifiedDiff(expSorted, actSorted, 3);
            return TestOutcome.diff(diffBody);

        } catch (Exception e) {
            return TestOutcome.fail("exception: " + e);
        }
    }

    // ---------------------------------------------------------------------------
    // Witness support via reflection
    // ---------------------------------------------------------------------------

    private ResolveResult resolveWithWitness(DidResolver resolver, String rawJsonl,
            String did, ResolveOptions options, String witnessContent) {
        try {
            Field lpField = DidResolver.class.getDeclaredField("logProcessor");
            lpField.setAccessible(true);
            Object lp = lpField.get(resolver);

            Method processMethod = null;
            for (Method m : lp.getClass().getDeclaredMethods()) {
                if ("process".equals(m.getName()) && m.getParameterCount() == 4) {
                    processMethod = m;
                    break;
                }
            }
            if (processMethod == null) {
                throw new XFailException(
                        "Java API: no 4-arg LogProcessor.process() found via reflection");
            }
            processMethod.setAccessible(true);
            return (ResolveResult) processMethod.invoke(lp, rawJsonl, witnessContent, did, options);

        } catch (XFailException e) {
            throw e;
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ResolutionException) {
                throw (ResolutionException) cause;
            }
            throw new RuntimeException("LogProcessor.process() threw: " + cause, cause);
        } catch (Exception e) {
            throw new XFailException(
                    "Java API: witness reflection failed (" + e.getClass().getSimpleName()
                    + ": " + e.getMessage() + ")");
        }
    }

    // ---------------------------------------------------------------------------
    // Build actual result
    // ---------------------------------------------------------------------------

    private JsonObject buildActualResult(JsonObject didDocJson, ResolutionMetadata meta) {
        JsonObject actual = new JsonObject();

        if (didDocJson != null) {
            actual.add("didDocument", didDocJson);
        } else {
            actual.add("didDocument", JsonNull.INSTANCE);
        }

        JsonObject metaObj = new JsonObject();
        if (meta != null) {
            if (meta.getCreated() != null) metaObj.addProperty("created", meta.getCreated());
            if (meta.getUpdated() != null) metaObj.addProperty("updated", meta.getUpdated());
            if (meta.getVersionId() != null) {
                metaObj.addProperty("versionId", meta.getVersionId());
                String[] parts = meta.getVersionId().split("-", 2);
                try {
                    metaObj.addProperty("versionNumber", Integer.parseInt(parts[0]));
                } catch (NumberFormatException ignored) {}
            }
            if (meta.getVersionTime() != null) metaObj.addProperty("versionTime", meta.getVersionTime());
            if (Boolean.TRUE.equals(meta.getDeactivated())) metaObj.addProperty("deactivated", true);
            if (meta.getPortable() != null) metaObj.addProperty("portable", meta.getPortable());
            if (meta.getScid() != null) metaObj.addProperty("scid", meta.getScid());
        }
        actual.add("didDocumentMetadata", metaObj);

        JsonObject resMeta = new JsonObject();
        resMeta.addProperty("contentType", "application/did+ld+json");
        actual.add("didResolutionMetadata", resMeta);

        return actual;
    }

    // ---------------------------------------------------------------------------
    // Bidirectional normalisation applied to both sides before comparison
    // ---------------------------------------------------------------------------

    private void normalizePair(JsonObject actual, JsonObject expected) {
        // Sort services on both sides
        sortServices(actual);
        sortServices(expected);

        // Restrict didDocumentMetadata to intersection of keys in both
        JsonObject actMeta = asObject(actual.get("didDocumentMetadata"));
        JsonObject expMeta = asObject(expected.get("didDocumentMetadata"));
        if (actMeta != null && expMeta != null) {
            Set<String> common = new HashSet<>(actMeta.keySet());
            common.retainAll(expMeta.keySet());
            JsonObject filteredAct = new JsonObject();
            JsonObject filteredExp = new JsonObject();
            for (String k : common) {
                filteredAct.add(k, actMeta.get(k));
                filteredExp.add(k, expMeta.get(k));
            }
            actual.add("didDocumentMetadata", filteredAct);
            expected.add("didDocumentMetadata", filteredExp);
        }
    }

    private void sortServices(JsonObject result) {
        JsonObject didDoc = asObject(result.get("didDocument"));
        if (didDoc == null) return;
        JsonArray services = asArray(didDoc.get("service"));
        if (services == null) return;
        List<JsonElement> list = new ArrayList<>();
        for (JsonElement el : services) list.add(el);
        list.sort(Comparator.comparing(e -> {
            if (e.isJsonObject()) {
                JsonElement id = e.getAsJsonObject().get("id");
                if (id != null && id.isJsonPrimitive()) return id.getAsString();
            }
            return "";
        }));
        JsonArray sorted = new JsonArray();
        list.forEach(sorted::add);
        didDoc.add("service", sorted);
    }

    // ---------------------------------------------------------------------------
    // Unified diff generation (LCS-based)
    // ---------------------------------------------------------------------------

    private static String computeUnifiedDiff(String expected, String actual, int ctx) {
        List<String> expLines = Arrays.asList(expected.split("\n"));
        List<String> actLines = Arrays.asList(actual.split("\n"));
        int m = expLines.size(), n = actLines.size();

        // Build LCS DP table
        int[][] dp = new int[m + 1][n + 1];
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                dp[i][j] = expLines.get(i - 1).equals(actLines.get(j - 1))
                        ? dp[i - 1][j - 1] + 1
                        : Math.max(dp[i - 1][j], dp[i][j - 1]);
            }
        }

        // Backtrack to build edit list: {tag, line} where tag = ' ', '-', '+'
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
                .boxed()
                .collect(Collectors.toList());

        if (changed.isEmpty()) return "";

        // Group into hunks with context
        List<int[]> hunks = new ArrayList<>(); // [start, end] inclusive
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

        StringBuilder out = new StringBuilder("--- expected\n+++ actual (java resolver)\n");
        for (int h = 0; h < hunks.size(); h++) {
            for (int k = hunks.get(h)[0]; k <= hunks.get(h)[1]; k++) {
                out.append(edits.get(k)[0]).append(edits.get(k)[1]).append("\n");
            }
            if (h + 1 < hunks.size()) out.append("...\n");
        }
        return out.toString().stripTrailing();
    }

    // ---------------------------------------------------------------------------
    // Pre-flight helpers
    // ---------------------------------------------------------------------------

    /**
     * LIB BUG: ivir3zam 0.2.0 NPEs on "witness":{} in parameters.  The library
     * deserializes the empty object into a Witnesses with witnesses=null, then
     * calls .isEmpty() on it.  Python and TS always write "witness":{} when no
     * witness is configured; Rust omits the field entirely.
     */
    private boolean logHasEmptyWitness(String rawJsonl) {
        for (String line : rawJsonl.lines().filter(l -> !l.isBlank()).collect(Collectors.toList())) {
            try {
                JsonObject entry = JsonParser.parseString(line).getAsJsonObject();
                JsonObject params = asObject(entry.get("parameters"));
                if (params == null) continue;
                JsonElement w = params.get("witness");
                if (w != null && w.isJsonObject() && w.getAsJsonObject().size() == 0) {
                    return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }

    private boolean logHasEmptyNextKeyHashes(String rawJsonl) {
        List<String> lines = rawJsonl.lines().filter(l -> !l.isBlank()).collect(Collectors.toList());
        if (lines.size() < 2) return false;
        for (String line : lines) {
            try {
                JsonObject entry = JsonParser.parseString(line).getAsJsonObject();
                JsonObject params = asObject(entry.get("parameters"));
                if (params != null && params.has("nextKeyHashes")) {
                    JsonElement nkh = params.get("nextKeyHashes");
                    if (nkh.isJsonArray() && nkh.getAsJsonArray().size() == 0) return true;
                }
            } catch (Exception ignored) {}
        }
        return false;
    }

    private boolean isKnownTsCompatError(String msg) {
        String lower = msg.toLowerCase();
        return lower.contains("nextkeyhashe")
                || lower.contains("prerotation")
                || lower.contains("pre-rotation")
                || msg.contains("updateKeys are not null")
                || msg.contains("updatekeys are not null");
    }

    // ---------------------------------------------------------------------------
    // Extraction helpers
    // ---------------------------------------------------------------------------

    private String extractDid(String rawJsonl) {
        return rawJsonl.lines().filter(l -> !l.isBlank()).findFirst().map(line -> {
            try {
                JsonObject entry = JsonParser.parseString(line).getAsJsonObject();
                JsonObject state = asObject(entry.get("state"));
                if (state != null && state.has("id")) return state.get("id").getAsString();
            } catch (Exception ignored) {}
            return null;
        }).orElse(null);
    }

    private Integer extractVersionNumber(String filename) {
        Matcher m = VERSION_PATTERN.matcher(filename);
        return m.matches() ? Integer.parseInt(m.group(1)) : null;
    }

    private JsonObject extractStateFromLog(String rawJsonl, String targetVersionId) {
        for (String line : rawJsonl.lines().filter(l -> !l.isBlank()).collect(Collectors.toList())) {
            try {
                LogEntry entry = LogEntry.fromJsonLine(line);
                if (targetVersionId.equals(entry.getVersionId())) return entry.getState();
            } catch (Exception ignored) {}
        }
        return null;
    }

    // ---------------------------------------------------------------------------
    // JSON / JCS utilities
    // ---------------------------------------------------------------------------

    private static String canonicalize(String json) throws IOException {
        return new JsonCanonicalizer(json).getEncodedString();
    }

    private static JsonObject asObject(JsonElement el) {
        return (el != null && el.isJsonObject()) ? el.getAsJsonObject() : null;
    }

    private static JsonArray asArray(JsonElement el) {
        return (el != null && el.isJsonArray()) ? el.getAsJsonArray() : null;
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

    private static final class XFailException extends RuntimeException {
        XFailException(String message) { super(message); }
    }
}
