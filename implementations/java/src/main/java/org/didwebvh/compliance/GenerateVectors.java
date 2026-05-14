package org.didwebvh.compliance;

import com.google.gson.*;
import io.github.ivir3zam.didwebvh.core.DidWebVh;
import io.github.ivir3zam.didwebvh.core.DidWebVhState;
import io.github.ivir3zam.didwebvh.core.ResolutionException;
import io.github.ivir3zam.didwebvh.core.SigningException;
import io.github.ivir3zam.didwebvh.core.create.CreateDidConfig;
import io.github.ivir3zam.didwebvh.core.create.CreateDidResult;
import io.github.ivir3zam.didwebvh.core.crypto.MultikeyUtil;
import io.github.ivir3zam.didwebvh.core.crypto.PreRotationHashGenerator;
import io.github.ivir3zam.didwebvh.core.model.DataIntegrityProof;
import io.github.ivir3zam.didwebvh.core.model.LogEntry;
import io.github.ivir3zam.didwebvh.core.model.Parameters;
import io.github.ivir3zam.didwebvh.core.model.ResolutionMetadata;
import io.github.ivir3zam.didwebvh.core.model.ResolveResult;
import io.github.ivir3zam.didwebvh.core.resolve.DidResolver;
import io.github.ivir3zam.didwebvh.core.resolve.ResolveOptions;
import io.github.ivir3zam.didwebvh.core.signing.ProofGenerator;
import io.github.ivir3zam.didwebvh.core.signing.Signer;
import io.github.ivir3zam.didwebvh.core.update.UpdateDidResult;
import io.github.ivir3zam.didwebvh.core.witness.WitnessConfig;
import io.github.ivir3zam.didwebvh.core.witness.WitnessEntry;
import io.github.ivir3zam.didwebvh.core.witness.WitnessProofCollection;
import io.github.ivir3zam.didwebvh.core.witness.WitnessProofEntry;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.erdtman.jcs.JsonCanonicalizer;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Generates DID log artifacts for each scenario by reading vectors/<scenario>/script.yaml
 * and writing vectors/<scenario>/java/{did.jsonl, resolutionResult*.json, did-witness.json}.
 *
 * Usage:
 *   mvn compile exec:java -Dexec.mainClass=org.didwebvh.compliance.GenerateVectors
 *   mvn compile exec:java@generate-vectors
 */
public class GenerateVectors {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final Gson GSON_PRETTY = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    private static final Path IMPL_ROOT = Paths.get(System.getProperty("user.dir"));
    private static final Path VECTORS_ROOT = IMPL_ROOT.resolve("../../vectors").normalize();
    private static final String IMPL_NAME = "java";

    // ---------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        if (!Files.isDirectory(VECTORS_ROOT)) {
            System.err.println("error: cannot find vectors/: " + VECTORS_ROOT);
            System.exit(2);
        }

        List<Path> scenarios;
        if (args.length > 0) {
            scenarios = Arrays.stream(args)
                    .map(a -> VECTORS_ROOT.resolve(a))
                    .collect(Collectors.toList());
        } else {
            try (Stream<Path> stream = Files.list(VECTORS_ROOT)) {
                scenarios = stream
                        .filter(Files::isDirectory)
                        .sorted()
                        .collect(Collectors.toList());
            }
        }

        int generated = 0, skipped = 0, failed = 0;
        List<String[]> genRows = new ArrayList<>();  // [testCase, result, notes]
        for (Path scenarioDir : scenarios) {
            Path scriptPath = scenarioDir.resolve("script.yaml");
            if (!Files.exists(scriptPath)) continue;

            String scenarioName = scenarioDir.getFileName().toString();
            System.out.print("Generating " + scenarioName + "... ");
            try {
                Yaml yaml = new Yaml();
                Map<String, Object> script;
                try (InputStream is = Files.newInputStream(scriptPath)) {
                    script = yaml.load(is);
                }
                processScenario(scenarioDir, script);
                System.out.println("done");
                generated++;
                genRows.add(new String[]{scenarioName, "✅ PASS", ""});
            } catch (UnsupportedOperationException e) {
                System.out.println("SKIP (" + e.getMessage() + ")");
                skipped++;
                genRows.add(new String[]{scenarioName, "⚠️ SKIP", e.getMessage()});
            } catch (Exception e) {
                System.out.println("FAIL: " + e.getMessage());
                e.printStackTrace(System.err);
                failed++;
                genRows.add(new String[]{scenarioName, "❌ FAIL", e.getMessage()});
            }
        }
        System.out.println("\n" + generated + " generated, " + skipped + " skipped, " + failed + " failed");

        JsonArray genArr = new JsonArray();
        for (String[] row : genRows) {
            JsonObject obj = new JsonObject();
            obj.addProperty("testCase", row[0]);
            obj.addProperty("result", row[1]);
            obj.addProperty("notes", row[2]);
            genArr.add(obj);
        }
        try {
            Files.writeString(IMPL_ROOT.resolve("gen_results.json"), GSON_PRETTY.toJson(genArr));
        } catch (Exception e) {
            System.err.println("warning: could not write gen_results.json: " + e.getMessage());
        }

        System.exit(failed > 0 ? 1 : 0);
    }

    // ---------------------------------------------------------------------------
    // Per-scenario processing
    // ---------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static void processScenario(Path scenarioDir, Map<String, Object> script) throws Exception {
        List<Map<String, Object>> keyDefs = (List<Map<String, Object>>) script.get("keys");
        Map<String, Ed25519PrivateKeyParameters> privKeyMap = new LinkedHashMap<>();
        Map<String, String> multikeyMap = new LinkedHashMap<>();

        for (Map<String, Object> kd : keyDefs) {
            String id = (String) kd.get("id");
            String seed = (String) kd.get("seed");
            Ed25519PrivateKeyParameters privKey = buildPrivKey(seed);
            String mk = MultikeyUtil.encode(MultikeyUtil.ED25519_KEY_TYPE, privKey.generatePublicKey().getEncoded());
            privKeyMap.put(id, privKey);
            multikeyMap.put(id, mk);
        }

        Path outDir = scenarioDir.resolve(IMPL_NAME);
        Files.createDirectories(outDir);

        DidWebVhState currentState = null;
        String currentDid = null;
        List<String> currentUpdateKeyMks = new ArrayList<>();
        List<WitnessProofEntry> witnessEntries = new ArrayList<>();

        List<Map<String, Object>> steps = (List<Map<String, Object>>) script.get("steps");

        for (Map<String, Object> step : steps) {
            String op = (String) step.get("op");
            Map<String, Object> params = (Map<String, Object>) step.get("params");

            // ----------------------------------------------------------------
            if ("create".equals(op)) {
                String domain = (String) step.get("domain");
                if (domain == null) throw new IllegalArgumentException("create step missing domain");
                String signerKeyId = (String) step.get("signer");

                List<String> updateKeyIds = params != null && params.containsKey("updateKeys")
                        ? (List<String>) params.get("updateKeys")
                        : Collections.singletonList(signerKeyId);

                // ivir3zam only supports one updateKey (the signer's key) at create time
                // Use the first declared updateKey as the signer
                String primaryKeyId = updateKeyIds.get(0);
                currentUpdateKeyMks = updateKeyIds.stream().map(multikeyMap::get).collect(Collectors.toList());

                if (currentUpdateKeyMks.size() > 1) {
                    throw new UnsupportedOperationException(
                            "multiple-update-keys at create time not supported by ivir3zam API");
                }

                Signer signer = buildSigner(multikeyMap.get(primaryKeyId), privKeyMap.get(primaryKeyId));

                CreateDidConfig cfg = DidWebVh.create(domain, signer);

                // portable
                Boolean portable = params != null ? (Boolean) params.get("portable") : null;
                if (Boolean.TRUE.equals(portable)) cfg.portable(true);

                // alsoKnownAs
                List<String> alsoKnownAs = getAlsoKnownAs(params);
                if (alsoKnownAs != null && !alsoKnownAs.isEmpty()) cfg.alsoKnownAs(alsoKnownAs);

                // nextKeyHashes
                List<String> nextKeyHashes = buildNextKeyHashes(params, multikeyMap);
                if (nextKeyHashes != null) cfg.nextKeyHashes(nextKeyHashes);

                // witness
                WitnessConfig witnessParam = buildWitnessParam(params, multikeyMap);
                if (witnessParam != null) cfg.witness(witnessParam);

                // services (via additionalDocumentContent)
                List<Map<?, ?>> services = getServices(params);
                if (services != null && !services.isEmpty()) {
                    JsonObject extra = new JsonObject();
                    extra.add("service", servicesToJson(services));
                    cfg.additionalDocumentContent(extra);
                }

                CreateDidResult result = cfg.execute();
                currentDid = result.getDid();
                currentState = DidWebVhState.from(currentDid, result.getLogEntry());

                // Witness proofs
                if (witnessParam != null) {
                    String versionId = result.getLogEntry().getVersionId();
                    witnessEntries.add(makeWitnessEntry(versionId, params, privKeyMap, multikeyMap));
                }

            // ----------------------------------------------------------------
            } else if ("update".equals(op)) {
                String signerKeyId = (String) step.get("signer");

                // domain migration (portable-move)
                String newDomain = (String) step.get("domain");
                if (newDomain != null) {
                    Signer signer = buildSigner(multikeyMap.get(signerKeyId), privKeyMap.get(signerKeyId));
                    UpdateDidResult result = DidWebVh.migrate(currentState, signer, newDomain).execute();
                    currentState.appendEntry(result.getLogEntry());
                    currentDid = currentState.getLastEntry().getState()
                            .get("id").getAsString();
                    currentUpdateKeyMks = Collections.singletonList(multikeyMap.get(signerKeyId));
                    continue;
                }

                List<String> newUpdateKeyMks = null;
                if (params != null && params.containsKey("updateKeys")) {
                    List<String> ids = (List<String>) params.get("updateKeys");
                    newUpdateKeyMks = ids.stream().map(multikeyMap::get).collect(Collectors.toList());
                    currentUpdateKeyMks = newUpdateKeyMks;
                }

                List<String> nextKeyHashes = buildNextKeyHashes(params, multikeyMap);
                WitnessConfig witnessParam = buildWitnessParam(params, multikeyMap);
                List<Map<?, ?>> services = getServices(params);
                List<String> alsoKnownAs = getAlsoKnownAs(params);

                Signer signer = buildSigner(multikeyMap.get(signerKeyId), privKeyMap.get(signerKeyId));

                // Build updated document
                JsonObject currentDoc = currentState.getLastEntry().getState().deepCopy();
                boolean docChanged = false;

                if (newUpdateKeyMks != null) {
                    rebuildVerificationMethods(currentDoc, currentDid, newUpdateKeyMks);
                    docChanged = true;
                }
                if (alsoKnownAs != null) {
                    if (alsoKnownAs.isEmpty()) {
                        currentDoc.remove("alsoKnownAs");
                    } else {
                        JsonArray akaArr = new JsonArray();
                        alsoKnownAs.forEach(akaArr::add);
                        currentDoc.add("alsoKnownAs", akaArr);
                    }
                    docChanged = true;
                }
                if (services != null) {
                    if (services.isEmpty()) {
                        currentDoc.remove("service");
                    } else {
                        currentDoc.add("service", servicesToJson(services));
                    }
                    docChanged = true;
                }

                var updateCfg = DidWebVh.update(currentState, signer);
                if (docChanged) updateCfg.newDocument(currentDoc);

                // changedParameters: updateKeys, nextKeyHashes, witness
                Parameters changedParams = buildChangedParams(newUpdateKeyMks, nextKeyHashes, witnessParam);
                if (changedParams != null) updateCfg.changedParameters(changedParams);

                UpdateDidResult result = updateCfg.execute();
                currentState.appendEntry(result.getLogEntry());

                if (witnessParam != null) {
                    String versionId = result.getLogEntry().getVersionId();
                    witnessEntries.add(makeWitnessEntry(versionId, params, privKeyMap, multikeyMap));
                }

            // ----------------------------------------------------------------
            } else if ("deactivate".equals(op)) {
                String signerKeyId = (String) step.get("signer");
                Signer signer = buildSigner(multikeyMap.get(signerKeyId), privKeyMap.get(signerKeyId));
                UpdateDidResult result = DidWebVh.deactivate(currentState, signer).execute();
                currentState.appendEntry(result.getLogEntry());

            // ----------------------------------------------------------------
            } else if ("resolve".equals(op)) {
                String expectFile = (String) step.get("expect");
                Integer versionNumber = (Integer) step.get("versionNumber");

                String jsonl = currentState.toDidLog();

                ResolveOptions options = versionNumber != null
                        ? ResolveOptions.builder().versionNumber(versionNumber).build()
                        : ResolveOptions.defaults();

                ResolveResult resolved;
                try {
                    if (!witnessEntries.isEmpty()) {
                        String witnessJson = witnessProofToJson(witnessEntries);
                        resolved = resolveWithWitness(jsonl, currentDid, options, witnessJson);
                    } else {
                        resolved = new DidResolver().resolveFromLog(jsonl, currentDid, options);
                    }
                } catch (ResolutionException e) {
                    throw new UnsupportedOperationException(
                            "resolver rejected generated log: " + e.getMessage());
                }

                JsonObject resResult = buildResolutionResult(resolved, jsonl);
                Files.writeString(outDir.resolve(expectFile),
                        GSON_PRETTY.toJson(resResult));
            }
        }

        // Write DID log
        Files.writeString(outDir.resolve("did.jsonl"), currentState.toDidLog());

        // Write witness proofs if any
        if (!witnessEntries.isEmpty()) {
            Files.writeString(outDir.resolve("did-witness.json"),
                    GSON_PRETTY.toJson(witnessProofCollectionToJson(witnessEntries)));
        }
    }

    // ---------------------------------------------------------------------------
    // Document helpers
    // ---------------------------------------------------------------------------

    private static void rebuildVerificationMethods(JsonObject doc, String did, List<String> updateKeyMks) {
        JsonArray vmArray = new JsonArray();
        JsonArray authArray = new JsonArray();
        for (String mk : updateKeyMks) {
            String fragment = mk.substring(mk.length() - 8);
            String vmId = did + "#" + fragment;
            JsonObject vm = new JsonObject();
            vm.addProperty("id", vmId);
            vm.addProperty("type", "Multikey");
            vm.addProperty("controller", did);
            vm.addProperty("publicKeyMultibase", mk);
            vmArray.add(vm);
            authArray.add(vmId);
        }
        doc.add("verificationMethod", vmArray);
        doc.add("authentication", authArray);
    }

    private static JsonArray servicesToJson(List<Map<?, ?>> services) {
        JsonArray arr = new JsonArray();
        for (Map<?, ?> svc : services) {
            JsonObject obj = new JsonObject();
            for (Map.Entry<?, ?> e : svc.entrySet()) {
                obj.addProperty(e.getKey().toString(), e.getValue().toString());
            }
            arr.add(obj);
        }
        return arr;
    }

    // ---------------------------------------------------------------------------
    // Resolution result construction
    // ---------------------------------------------------------------------------

    private static JsonObject buildResolutionResult(ResolveResult result, String jsonl) throws Exception {
        JsonObject actual = new JsonObject();

        JsonObject didDocJson = null;
        if (result.getDidDocument() != null) {
            didDocJson = result.getDidDocument().asJsonObject();
        } else if (result.getMetadata() != null && result.getMetadata().getVersionId() != null) {
            // Deactivated — extract last state from log
            didDocJson = extractStateFromLog(jsonl, result.getMetadata().getVersionId());
        }
        actual.add("didDocument", didDocJson != null ? didDocJson : JsonNull.INSTANCE);

        JsonObject metaObj = new JsonObject();
        ResolutionMetadata meta = result.getMetadata();
        if (meta != null) {
            if (meta.getCreated() != null)    metaObj.addProperty("created", meta.getCreated());
            if (meta.getUpdated() != null)    metaObj.addProperty("updated", meta.getUpdated());
            if (meta.getVersionId() != null) {
                metaObj.addProperty("versionId", meta.getVersionId());
                String[] parts = meta.getVersionId().split("-", 2);
                try { metaObj.addProperty("versionNumber", Integer.parseInt(parts[0])); }
                catch (NumberFormatException ignored) {}
            }
            if (meta.getVersionTime() != null) metaObj.addProperty("versionTime", meta.getVersionTime());
            if (Boolean.TRUE.equals(meta.getDeactivated())) metaObj.addProperty("deactivated", true);
            if (Boolean.TRUE.equals(meta.getPortable()))    metaObj.addProperty("portable", true);
            if (meta.getScid() != null)        metaObj.addProperty("scid", meta.getScid());
        }
        actual.add("didDocumentMetadata", metaObj);

        JsonObject resMeta = new JsonObject();
        resMeta.addProperty("contentType", "application/did+ld+json");
        actual.add("didResolutionMetadata", resMeta);

        return actual;
    }

    private static JsonObject extractStateFromLog(String jsonl, String targetVersionId) {
        String[] lines = jsonl.split("\n");
        // Walk backwards to find the entry just before deactivation
        for (int i = lines.length - 1; i >= 0; i--) {
            if (lines[i].trim().isEmpty()) continue;
            JsonObject entry = JsonParser.parseString(lines[i]).getAsJsonObject();
            String vid = entry.get("versionId").getAsString();
            int vn = Integer.parseInt(vid.split("-")[0]);
            String targetVn = targetVersionId.split("-")[0];
            if (vn < Integer.parseInt(targetVn)) {
                return entry.getAsJsonObject("state");
            }
        }
        return null;
    }

    // ---------------------------------------------------------------------------
    // Witness support (reflection hack, same as TestVectors)
    // ---------------------------------------------------------------------------

    private static ResolveResult resolveWithWitness(String jsonl, String did,
            ResolveOptions options, String witnessJson) throws Exception {
        DidResolver resolver = new DidResolver();
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
            throw new IllegalStateException("no 4-arg LogProcessor.process() found");
        }
        processMethod.setAccessible(true);
        return (ResolveResult) processMethod.invoke(lp, jsonl, witnessJson, did, options);
    }

    // ---------------------------------------------------------------------------
    // Witness proof generation
    // ---------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static WitnessProofEntry makeWitnessEntry(
            String versionId, Map<String, Object> params,
            Map<String, Ed25519PrivateKeyParameters> privKeyMap,
            Map<String, String> multikeyMap) throws Exception {
        Map<String, Object> witConfig = (Map<String, Object>) params.get("witness");
        List<Map<String, Object>> witnesses =
                (List<Map<String, Object>>) witConfig.get("witnesses");

        JsonObject versionIdDoc = new JsonObject();
        versionIdDoc.addProperty("versionId", versionId);

        List<DataIntegrityProof> proofs = new ArrayList<>();
        for (Map<String, Object> w : witnesses) {
            String wKeyId = (String) w.get("id");
            String wMk = multikeyMap.get(wKeyId);
            String vmId = "did:key:" + wMk + "#" + wMk;
            Ed25519PrivateKeyParameters wPrivKey = privKeyMap.get(wKeyId);

            DataIntegrityProof proofOpts = new DataIntegrityProof()
                    .setType(DataIntegrityProof.DEFAULT_TYPE)
                    .setCryptosuite(DataIntegrityProof.DEFAULT_CRYPTOSUITE)
                    .setVerificationMethod(vmId)
                    .setCreated(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
                    .setProofPurpose(DataIntegrityProof.DEFAULT_PROOF_PURPOSE);

            byte[] dataToSign = ProofGenerator.buildHashData(proofOpts, versionIdDoc);

            org.bouncycastle.crypto.signers.Ed25519Signer bsSigner = new org.bouncycastle.crypto.signers.Ed25519Signer();
            bsSigner.init(true, wPrivKey);
            bsSigner.update(dataToSign, 0, dataToSign.length);
            byte[] sigBytes = bsSigner.generateSignature();

            // Encode as multibase base58btc (z prefix)
            String proofValue = "z" + io.github.ivir3zam.didwebvh.core.crypto.Base58Btc.encode(sigBytes);
            proofOpts.setProofValue(proofValue);
            proofs.add(proofOpts);
        }
        return new WitnessProofEntry(versionId, proofs);
    }

    private static String witnessProofToJson(List<WitnessProofEntry> entries) {
        return GSON.toJson(witnessProofCollectionToJson(entries));
    }

    private static JsonArray witnessProofCollectionToJson(List<WitnessProofEntry> entries) {
        JsonArray arr = new JsonArray();
        for (WitnessProofEntry entry : entries) {
            JsonObject obj = new JsonObject();
            obj.addProperty("versionId", entry.getVersionId());
            JsonArray proofArr = new JsonArray();
            for (DataIntegrityProof p : entry.getProof()) {
                JsonObject pObj = new JsonObject();
                pObj.addProperty("type", p.getType());
                pObj.addProperty("cryptosuite", p.getCryptosuite());
                pObj.addProperty("verificationMethod", p.getVerificationMethod());
                pObj.addProperty("created", p.getCreated());
                pObj.addProperty("proofPurpose", p.getProofPurpose());
                pObj.addProperty("proofValue", p.getProofValue());
                proofArr.add(pObj);
            }
            obj.add("proof", proofArr);
            arr.add(obj);
        }
        return arr;
    }

    // ---------------------------------------------------------------------------
    // Param extraction helpers
    // ---------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static List<String> buildNextKeyHashes(Map<String, Object> params,
            Map<String, String> multikeyMap) {
        if (params == null || !params.containsKey("nextKeyHashes")) return null;
        List<String> ids = (List<String>) params.get("nextKeyHashes");
        return ids.stream()
                .map(id -> PreRotationHashGenerator.generateHash(multikeyMap.get(id)))
                .collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private static WitnessConfig buildWitnessParam(Map<String, Object> params,
            Map<String, String> multikeyMap) {
        if (params == null || !params.containsKey("witness")) return null;
        Map<String, Object> wc = (Map<String, Object>) params.get("witness");
        int threshold = (Integer) wc.get("threshold");
        List<Map<String, Object>> witnesses = (List<Map<String, Object>>) wc.get("witnesses");
        List<WitnessEntry> entries = witnesses.stream()
                .map(w -> new WitnessEntry("did:key:" + multikeyMap.get((String) w.get("id"))))
                .collect(Collectors.toList());
        return new WitnessConfig(threshold, entries);
    }

    private static Parameters buildChangedParams(List<String> updateKeyMks,
            List<String> nextKeyHashes, WitnessConfig witness) {
        if (updateKeyMks == null && nextKeyHashes == null && witness == null) return null;
        Parameters p = new Parameters();
        if (updateKeyMks != null) p.setUpdateKeys(updateKeyMks);
        if (nextKeyHashes != null) p.setNextKeyHashes(nextKeyHashes);
        if (witness != null) p.setWitness(witness);
        return p;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<?, ?>> getServices(Map<String, Object> params) {
        if (params == null || !params.containsKey("services")) return null;
        return (List<Map<?, ?>>) params.get("services");
    }

    @SuppressWarnings("unchecked")
    private static List<String> getAlsoKnownAs(Map<String, Object> params) {
        if (params == null || !params.containsKey("alsoKnownAs")) return null;
        return (List<String>) params.get("alsoKnownAs");
    }

    // ---------------------------------------------------------------------------
    // Cryptographic helpers
    // ---------------------------------------------------------------------------

    private static Ed25519PrivateKeyParameters buildPrivKey(String seedHex) {
        byte[] seed = hexToBytes(seedHex);
        return new Ed25519PrivateKeyParameters(seed, 0);
    }

    private static Signer buildSigner(String multikey, Ed25519PrivateKeyParameters privKey) {
        String vmId = "did:key:" + multikey + "#" + multikey;
        return new Signer() {
            @Override public String keyType() { return MultikeyUtil.ED25519_KEY_TYPE; }
            @Override public String verificationMethod() { return vmId; }
            @Override
            public byte[] sign(byte[] data) throws SigningException {
                org.bouncycastle.crypto.signers.Ed25519Signer s = new org.bouncycastle.crypto.signers.Ed25519Signer();
                s.init(true, privKey);
                s.update(data, 0, data.length);
                return s.generateSignature();
            }
        };
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // ---------------------------------------------------------------------------
    // JCS utility
    // ---------------------------------------------------------------------------

    private static String canonicalize(String json) throws Exception {
        return new JsonCanonicalizer(json).getEncodedString();
    }
}
