package org.didwebvh.compliance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.*;
import io.didwebvh.crypto.DataIntegrity;
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import io.didwebvh.log.LogSerializer;
import io.didwebvh.model.*;
import io.didwebvh.model.proof.DataIntegrityProof;
import io.didwebvh.witness.WitnessProofCollection;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Generates DID log artifacts for each scenario by reading vectors/<scenario>/script.yaml
 * and writing vectors/<scenario>/java-eecc/{did.jsonl, resolutionResult*.json, did-witness.json}.
 *
 * Usage:
 *   mvn compile exec:java -Dexec.mainClass=org.didwebvh.compliance.GenerateVectors
 *   mvn compile exec:java -Dexec.mainClass=org.didwebvh.compliance.GenerateVectors -Dexec.args=basic-create
 */
public class GenerateVectors {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Path VECTORS_ROOT = Paths.get(System.getProperty("user.dir"))
            .resolve("../../vectors").normalize();
    private static final String IMPL_NAME = "java-eecc";

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
            } catch (UnsupportedOperationException e) {
                System.out.println("SKIP (" + e.getMessage() + ")");
                skipped++;
            } catch (Exception e) {
                System.out.println("FAIL: " + e.getMessage());
                e.printStackTrace(System.err);
                failed++;
            }
        }
        System.out.println("\n" + generated + " generated, " + skipped + " skipped, " + failed + " failed");
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
            String mk = buildMultikey(privKey.generatePublicKey().getEncoded());
            privKeyMap.put(id, privKey);
            multikeyMap.put(id, mk);
        }

        Path outDir = scenarioDir.resolve(IMPL_NAME);
        Files.createDirectories(outDir);

        DidLog currentLog = DidLog.empty();
        String currentDid = null;
        JsonNode currentDoc = null;
        List<String> currentUpdateKeyMks = new ArrayList<>();
        List<WitnessProofCollection.Entry> witnessEntries = new ArrayList<>();

        List<Map<String, Object>> steps = (List<Map<String, Object>>) script.get("steps");
        List<Object[]> resolveQueue = new ArrayList<>(); // [filename, versionNumber]

        for (Map<String, Object> step : steps) {
            String op = (String) step.get("op");
            Map<String, Object> params = (Map<String, Object>) step.get("params");

            // ----------------------------------------------------------------
            if ("create".equals(op)) {
                String domain = (String) step.get("domain");
                if (domain == null) throw new IllegalArgumentException("create step missing domain");
                String signerKeyId = (String) step.get("signer");

                List<String> updateKeyMks = resolveUpdateKeyMks(params, signerKeyId, multikeyMap);
                currentUpdateKeyMks = updateKeyMks;

                List<String> nextKeyHashes = buildNextKeyHashes(params, multikeyMap);
                Boolean portable = params != null ? (Boolean) params.get("portable") : null;
                WitnessParameter witnessParam = buildWitnessParam(params, multikeyMap);
                List<Map<?, ?>> services = getServices(params);

                ObjectNode initialDoc = buildDocument(
                        "did:webvh:{SCID}:" + domain, updateKeyMks, services, null, null);

                Signer signer = buildSigner(multikeyMap.get(signerKeyId), privKeyMap.get(signerKeyId));

                CreateOptions.Builder cb = CreateOptions.builder()
                        .domain(domain)
                        .initialDocument(initialDoc)
                        .updateKeys(updateKeyMks)
                        .signer(signer);
                if (portable != null && portable) cb.portable(true);
                if (nextKeyHashes != null) cb.nextKeyHashes(nextKeyHashes);
                if (witnessParam != null) cb.witness(witnessParam);

                CreateResult result = DidWebVh.create(cb.build());
                currentLog = result.log();
                currentDid = result.did();
                currentDoc = result.document();

                if (witnessParam != null) {
                    witnessEntries.add(makeWitnessEntry(
                            currentLog.latest().versionId(), params, privKeyMap, multikeyMap));
                }

            // ----------------------------------------------------------------
            } else if ("update".equals(op)) {
                if (step.containsKey("domain")) {
                    throw new UnsupportedOperationException(
                            "domain migration (portable-move) not supported by EECC UpdateOptions");
                }

                String signerKeyId = (String) step.get("signer");

                List<String> newUpdateKeyMks = null;
                if (params != null && params.containsKey("updateKeys")) {
                    List<String> ids = (List<String>) params.get("updateKeys");
                    newUpdateKeyMks = ids.stream().map(multikeyMap::get).collect(Collectors.toList());
                    currentUpdateKeyMks = newUpdateKeyMks;
                }

                List<String> nextKeyHashes = buildNextKeyHashes(params, multikeyMap);
                WitnessParameter witnessParam = buildWitnessParam(params, multikeyMap);
                List<Map<?, ?>> services = getServices(params);
                List<String> alsoKnownAs = getAlsoKnownAs(params);

                ObjectNode updatedDoc = buildDocument(
                        currentDid, currentUpdateKeyMks, services, alsoKnownAs, currentDoc);

                Signer signer = buildSigner(multikeyMap.get(signerKeyId), privKeyMap.get(signerKeyId));

                UpdateOptions.Builder ub = UpdateOptions.builder()
                        .log(currentLog)
                        .updatedDocument(updatedDoc)
                        .signer(signer);
                if (newUpdateKeyMks != null) ub.updateKeys(newUpdateKeyMks);
                if (nextKeyHashes != null) ub.nextKeyHashes(nextKeyHashes);
                if (witnessParam != null) ub.witness(witnessParam);

                UpdateResult result = DidWebVh.update(ub.build());
                currentLog = result.log();
                currentDoc = result.document();

                if (witnessParam != null) {
                    witnessEntries.add(makeWitnessEntry(
                            currentLog.latest().versionId(), params, privKeyMap, multikeyMap));
                }

            // ----------------------------------------------------------------
            } else if ("deactivate".equals(op)) {
                String signerKeyId = (String) step.get("signer");
                Signer signer = buildSigner(multikeyMap.get(signerKeyId), privKeyMap.get(signerKeyId));

                DeactivateResult result = DidWebVh.deactivate(
                        DeactivateOptions.builder().log(currentLog).signer(signer).build());
                currentLog = result.log();

            // ----------------------------------------------------------------
            } else if ("resolve".equals(op)) {
                String expectFile = (String) step.get("expect");
                Integer versionNumber = (Integer) step.get("versionNumber");

                ResolveOptions.Builder rb = ResolveOptions.builder();
                if (versionNumber != null) rb.versionNumber(versionNumber);
                if (!witnessEntries.isEmpty()) {
                    rb.witnessProofs(new WitnessProofCollection(witnessEntries));
                }

                ResolveResult resolved = DidWebVh.resolveFromLog(currentDid, currentLog, rb.build());
                ObjectNode resResult = buildResolutionResult(resolved, currentLog, currentDid);
                Files.writeString(outDir.resolve(expectFile),
                        MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(resResult));
            }
        }

        // Write DID log
        Files.writeString(outDir.resolve("did.jsonl"), LogSerializer.serialize(currentLog));

        // Write witness proofs if any
        if (!witnessEntries.isEmpty()) {
            ArrayNode wpcArray = MAPPER.createArrayNode();
            for (WitnessProofCollection.Entry entry : witnessEntries) {
                ObjectNode entryNode = MAPPER.createObjectNode();
                entryNode.put("versionId", entry.versionId());
                ArrayNode proofsArray = entryNode.putArray("proof");
                for (DataIntegrityProof p : entry.proof()) {
                    ObjectNode proofNode = MAPPER.createObjectNode();
                    proofNode.put("type", p.type());
                    proofNode.put("cryptosuite", p.cryptosuite());
                    proofNode.put("verificationMethod", p.verificationMethod());
                    proofNode.put("created", p.created());
                    proofNode.put("proofPurpose", p.proofPurpose());
                    proofNode.put("proofValue", p.proofValue());
                    proofsArray.add(proofNode);
                }
                wpcArray.add(entryNode);
            }
            Files.writeString(outDir.resolve("did-witness.json"),
                    MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(wpcArray));
        }
    }

    // ---------------------------------------------------------------------------
    // Document construction
    // ---------------------------------------------------------------------------

    /**
     * Builds a DID document. For creates, did contains "{SCID}" placeholder.
     * For updates, baseDoc is the existing document (deep-copied and modified).
     * Services/alsoKnownAs null means "keep from baseDoc"; empty list means "remove".
     */
    @SuppressWarnings("unchecked")
    private static ObjectNode buildDocument(String did, List<String> updateKeyMks,
            List<Map<?, ?>> services, List<String> alsoKnownAs, JsonNode baseDoc) throws Exception {
        ObjectNode doc;
        if (baseDoc != null) {
            doc = baseDoc.deepCopy();
            doc.put("id", did);
            doc.put("controller", did);
        } else {
            doc = MAPPER.createObjectNode();
            ArrayNode ctx = doc.putArray("@context");
            ctx.add("https://www.w3.org/ns/did/v1");
            ctx.add("https://w3id.org/security/multikey/v1");
            doc.put("id", did);
            doc.put("controller", did);
            doc.putArray("assertionMethod");
            doc.putArray("keyAgreement");
            doc.putArray("capabilityDelegation");
            doc.putArray("capabilityInvocation");
        }

        // Rebuild verificationMethod and authentication from updateKeyMks
        ArrayNode vmArray = MAPPER.createArrayNode();
        ArrayNode authArray = MAPPER.createArrayNode();
        for (String mk : updateKeyMks) {
            String fragment = mk.substring(mk.length() - 8);
            String vmId = did + "#" + fragment;
            ObjectNode vm = MAPPER.createObjectNode();
            vm.put("id", vmId);
            vm.put("type", "Multikey");
            vm.put("controller", did);
            vm.put("publicKeyMultibase", mk);
            vmArray.add(vm);
            authArray.add(vmId);
        }
        doc.set("verificationMethod", vmArray);
        doc.set("authentication", authArray);

        // alsoKnownAs
        if (alsoKnownAs != null) {
            if (alsoKnownAs.isEmpty()) {
                doc.remove("alsoKnownAs");
            } else {
                ArrayNode akaArray = doc.putArray("alsoKnownAs");
                alsoKnownAs.forEach(akaArray::add);
            }
        }

        // services
        if (services != null) {
            if (services.isEmpty()) {
                doc.remove("service");
            } else {
                ArrayNode svcArray = doc.putArray("service");
                for (Map<?, ?> svc : services) {
                    ObjectNode svcNode = MAPPER.createObjectNode();
                    for (Map.Entry<?, ?> e : svc.entrySet()) {
                        svcNode.put(e.getKey().toString(), e.getValue().toString());
                    }
                    svcArray.add(svcNode);
                }
            }
        }

        return doc;
    }

    // ---------------------------------------------------------------------------
    // Resolution result construction
    // ---------------------------------------------------------------------------

    private static ObjectNode buildResolutionResult(ResolveResult result, DidLog log, String did) {
        ObjectNode actual = MAPPER.createObjectNode();

        JsonNode doc = result.document();
        if (doc == null && result.documentMetadata() != null
                && Boolean.TRUE.equals(result.documentMetadata().deactivated())) {
            DidDocumentMetadata deactMeta = result.documentMetadata();
            if (deactMeta.versionNumber() != null && deactMeta.versionNumber() > 1) {
                try {
                    ResolveResult preDeact = DidWebVh.resolveFromLog(did, log,
                            ResolveOptions.builder().versionNumber(deactMeta.versionNumber() - 1).build());
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
            if (Boolean.TRUE.equals(meta.portable()))    metaObj.put("portable", true);
            if (meta.scid() != null)          metaObj.put("scid", meta.scid());
        }
        actual.set("didDocumentMetadata", metaObj);

        ObjectNode resMeta = MAPPER.createObjectNode();
        resMeta.put("contentType", "application/did+ld+json");
        actual.set("didResolutionMetadata", resMeta);

        return actual;
    }

    // ---------------------------------------------------------------------------
    // Witness proof generation
    // ---------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static WitnessProofCollection.Entry makeWitnessEntry(
            String versionId, Map<String, Object> params,
            Map<String, Ed25519PrivateKeyParameters> privKeyMap,
            Map<String, String> multikeyMap) throws Exception {
        Map<String, Object> witConfig = (Map<String, Object>) params.get("witness");
        List<Map<String, Object>> witnesses =
                (List<Map<String, Object>>) witConfig.get("witnesses");

        ObjectNode versionIdDoc = MAPPER.createObjectNode();
        versionIdDoc.put("versionId", versionId);

        List<DataIntegrityProof> proofs = new ArrayList<>();
        for (Map<String, Object> w : witnesses) {
            String wKeyId = (String) w.get("id");
            String wMk = multikeyMap.get(wKeyId);
            Signer wSigner = buildSigner(wMk, privKeyMap.get(wKeyId));
            proofs.add(DataIntegrity.createProof(versionIdDoc, wSigner.getVerificationMethodId(), wSigner));
        }
        return new WitnessProofCollection.Entry(versionId, proofs);
    }

    // ---------------------------------------------------------------------------
    // Param extraction helpers
    // ---------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static List<String> resolveUpdateKeyMks(
            Map<String, Object> params, String fallbackKeyId, Map<String, String> multikeyMap) {
        List<String> ids = params != null && params.containsKey("updateKeys")
                ? (List<String>) params.get("updateKeys")
                : Collections.singletonList(fallbackKeyId);
        return ids.stream().map(multikeyMap::get).collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    private static List<String> buildNextKeyHashes(
            Map<String, Object> params, Map<String, String> multikeyMap) throws Exception {
        if (params == null || !params.containsKey("nextKeyHashes")) return null;
        List<String> ids = (List<String>) params.get("nextKeyHashes");
        List<String> hashes = new ArrayList<>();
        for (String id : ids) {
            String mk = multikeyMap.get(id);
            hashes.add(Multiformats.sha256Multihash(mk.getBytes(StandardCharsets.UTF_8)));
        }
        return hashes;
    }

    @SuppressWarnings("unchecked")
    private static WitnessParameter buildWitnessParam(
            Map<String, Object> params, Map<String, String> multikeyMap) {
        if (params == null || !params.containsKey("witness")) return null;
        Map<String, Object> wc = (Map<String, Object>) params.get("witness");
        int threshold = (Integer) wc.get("threshold");
        List<Map<String, Object>> witnesses = (List<Map<String, Object>>) wc.get("witnesses");
        List<WitnessParameter.WitnessEntry> entries = witnesses.stream()
                .map(w -> new WitnessParameter.WitnessEntry(
                        "did:key:" + multikeyMap.get((String) w.get("id"))))
                .collect(Collectors.toList());
        return new WitnessParameter(threshold, entries);
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

    private static String buildMultikey(byte[] pubKeyBytes) {
        return Multiformats.encodeEd25519Multikey(pubKeyBytes);
    }

    private static Signer buildSigner(String multikey, Ed25519PrivateKeyParameters privKey) {
        String vmId = "did:key:" + multikey + "#" + multikey;
        return Signer.create(vmId, data -> {
            Ed25519Signer s = new Ed25519Signer();
            s.init(true, privKey);
            s.update(data, 0, data.length);
            return s.generateSignature();
        });
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
}
