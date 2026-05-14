//! Rust DID log generator for the did:webvh compliance test suite.
//!
//! Reads each vectors/<scenario>/script.yaml and writes:
//!   vectors/<scenario>/rust/did.jsonl
//!   vectors/<scenario>/rust/resolutionResult*.json
//!   vectors/<scenario>/rust/did-witness.json  (if witness proofs exist)
//!
//! Usage:
//!   cargo run --bin generate-vectors [scenario-name]

use std::path::Path;
use std::sync::Arc;

use ahash::HashMap;
use chrono::DateTime;
use didwebvh_rs::SCID_HOLDER;
use didwebvh_rs::create::sign_witness_proofs;
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::prelude::{
    DIDWebVHState, Multibase, Parameters, Secret, WitnessProofCollection,
};
use didwebvh_rs::witness::Witnesses;
use serde::Deserialize;
use serde_json::{Value, json};

const VECTORS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors");

// ---------------------------------------------------------------------------
// Script YAML types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Script {
    #[serde(default)]
    keys: Vec<KeyDef>,
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
struct KeyDef {
    id: String,
    #[serde(rename = "type")]
    key_type: String,
    seed: String,
}

#[derive(Debug, Deserialize)]
struct Step {
    op: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    signer: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    params: Option<StepParams>,
    #[serde(rename = "versionNumber", default)]
    version_number: Option<u32>,
    #[serde(default)]
    expect: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct StepParams {
    #[serde(rename = "updateKeys", default)]
    update_keys: Vec<String>,
    #[serde(rename = "nextKeyHashes", default)]
    next_key_hashes: Vec<String>,
    #[serde(default)]
    portable: Option<bool>,
    #[serde(default)]
    witness: Option<WitnessConfig>,
    #[serde(default)]
    services: Vec<Value>,
    #[serde(rename = "verificationMethods", default)]
    verification_methods: Vec<Value>,
    #[serde(rename = "alsoKnownAs", default)]
    also_known_as: Vec<String>,
    #[serde(default)]
    context: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WitnessConfig {
    threshold: u32,
    witnesses: Vec<WitnessEntry>,
}

#[derive(Debug, Deserialize)]
struct WitnessEntry {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    weight: u32,
}

// ---------------------------------------------------------------------------
// Key registry
// ---------------------------------------------------------------------------

struct KeyInfo {
    secret: Secret,
    pub_multibase: String,
}

fn build_key_registry(key_defs: &[KeyDef]) -> Result<HashMap<String, KeyInfo>, String> {
    let mut map = HashMap::default();
    for kd in key_defs {
        if kd.key_type != "ed25519" {
            return Err(format!("unsupported key type '{}' for '{}'", kd.key_type, kd.id));
        }
        let seed_bytes = hex::decode(&kd.seed)
            .map_err(|e| format!("bad seed hex for '{}': {e}", kd.id))?;
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| format!("seed for '{}' must be 32 bytes", kd.id))?;
        let mut secret = Secret::generate_ed25519(None, Some(&seed));
        let pub_mb = secret.get_public_keymultibase()
            .map_err(|e| format!("pubkey for '{}': {e}", kd.id))?;
        // Secret.id must be the full did:key verification method URL for signing
        let did_key = format!("did:key:{pub_mb}");
        secret.id = format!("{did_key}#{pub_mb}");
        map.insert(kd.id.clone(), KeyInfo { secret, pub_multibase: pub_mb });
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Parameter building
// ---------------------------------------------------------------------------

fn build_parameters(p: &StepParams, keys: &HashMap<String, KeyInfo>) -> Result<Parameters, String> {
    let update_keys: Vec<Multibase> = p.update_keys.iter()
        .map(|kid| keys.get(kid)
            .map(|k| Multibase::new(k.pub_multibase.clone()))
            .ok_or_else(|| format!("unknown key '{kid}'")))
        .collect::<Result<_, _>>()?;

    let next_key_hashes: Vec<Multibase> = p.next_key_hashes.iter()
        .map(|kid| {
            let info = keys.get(kid).ok_or_else(|| format!("unknown key '{kid}'"))?;
            let hash = Secret::base58_hash_string(&info.pub_multibase)
                .map_err(|e| format!("hash for '{kid}': {e}"))?;
            Ok(Multibase::new(hash))
        })
        .collect::<Result<_, String>>()?;

    let witness = if let Some(wc) = &p.witness {
        let mut builder = Witnesses::builder().threshold(wc.threshold);
        for we in &wc.witnesses {
            let mb = keys.get(&we.id)
                .map(|k| k.pub_multibase.clone())
                .unwrap_or_else(|| we.id.clone());
            builder = builder.witness(Multibase::new(mb));
        }
        Some(Arc::new(builder.build()
            .map_err(|e| format!("build witnesses: {e:?}"))?))
    } else {
        None
    };

    Ok(Parameters {
        update_keys: if update_keys.is_empty() { None } else { Some(Arc::new(update_keys)) },
        next_key_hashes: if next_key_hashes.is_empty() { None } else { Some(Arc::new(next_key_hashes)) },
        portable: p.portable,
        witness,
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Witness secret map: all keys, keyed by public multibase
// sign_witness_proofs only uses the ones that are active witnesses
// ---------------------------------------------------------------------------

fn all_witness_secrets(keys: &HashMap<String, KeyInfo>) -> HashMap<String, Secret> {
    keys.values()
        .map(|k| (k.pub_multibase.clone(), k.secret.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// Document construction
// ---------------------------------------------------------------------------

fn build_document(did_placeholder: &str, params: &StepParams, keys: &HashMap<String, KeyInfo>) -> Value {
    let vms: Vec<Value> = params.update_keys.iter()
        .filter_map(|kid| keys.get(kid))
        .map(|k| {
            let suffix = &k.pub_multibase[k.pub_multibase.len().saturating_sub(8)..];
            json!({
                "id": format!("{did_placeholder}#{suffix}"),
                "type": "Multikey",
                "controller": did_placeholder,
                "publicKeyMultibase": k.pub_multibase
            })
        })
        .chain(params.verification_methods.iter().cloned())
        .collect();

    let auth_refs: Vec<Value> = params.update_keys.iter()
        .filter_map(|kid| keys.get(kid))
        .map(|k| {
            let suffix = &k.pub_multibase[k.pub_multibase.len().saturating_sub(8)..];
            json!(format!("{did_placeholder}#{suffix}"))
        })
        .collect();

    let mut doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": did_placeholder,
        "controller": did_placeholder,
        "verificationMethod": vms,
        "authentication": auth_refs,
        "assertionMethod": [],
        "keyAgreement": [],
        "capabilityDelegation": [],
        "capabilityInvocation": []
    });

    if !params.services.is_empty() {
        doc["service"] = json!(params.services);
    }
    if !params.also_known_as.is_empty() {
        doc["alsoKnownAs"] = json!(params.also_known_as);
    }
    for c in &params.context {
        if let Some(ctx) = doc["@context"].as_array_mut() {
            ctx.push(json!(c));
        }
    }
    doc
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let filter = std::env::args().nth(1);
    let vectors_root = Path::new(VECTORS_ROOT);

    let mut scenarios: Vec<_> = match std::fs::read_dir(vectors_root) {
        Ok(rd) => rd.filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect(),
        Err(e) => { eprintln!("error: cannot read vectors/: {e}"); std::process::exit(2); }
    };
    scenarios.sort_by_key(|e| e.file_name());

    let mut ok = 0u32;
    let mut err = 0u32;
    let mut gen_rows: Vec<serde_json::Value> = Vec::new();

    for scenario in &scenarios {
        let name = scenario.file_name().to_string_lossy().to_string();
        if let Some(ref f) = filter {
            if &name != f { continue; }
        }
        if !scenario.path().join("script.yaml").exists() { continue; }
        print!("generate {name} ... ");
        match run_scenario(&scenario.path()).await {
            Ok(()) => {
                println!("ok"); ok += 1;
                gen_rows.push(json!({"testCase": name, "result": "✅ PASS", "notes": ""}));
            }
            Err(e) => {
                println!("ERROR: {e}"); err += 1;
                gen_rows.push(json!({"testCase": name, "result": "❌ FAIL", "notes": e}));
            }
        }
    }

    println!("\n{ok} generated, {err} errors");

    let gen_results_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("gen_results.json");
    if let Ok(s) = serde_json::to_string_pretty(&gen_rows) {
        let _ = std::fs::write(&gen_results_path, s + "\n");
    }

    if err > 0 { std::process::exit(1); }
}

// ---------------------------------------------------------------------------
// Per-scenario generation
// ---------------------------------------------------------------------------

async fn run_scenario(scenario_dir: &Path) -> Result<(), String> {
    let script_text = std::fs::read_to_string(scenario_dir.join("script.yaml"))
        .map_err(|e| format!("read script.yaml: {e}"))?;
    let script: Script = serde_yaml::from_str(&script_text)
        .map_err(|e| format!("parse script.yaml: {e}"))?;

    let keys = build_key_registry(&script.keys)?;
    let out_dir = scenario_dir.join("rust");
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| format!("create rust/ dir: {e}"))?;

    let mut state = DIDWebVHState::default();
    let mut log_lines: Vec<String> = Vec::new();
    let mut current_did: Option<String> = None;
    let mut witness_proofs = WitnessProofCollection::default();

    for step in &script.steps {
        match step.op.as_str() {
            "create" => {
                let domain = step.domain.as_deref().ok_or("create: missing domain")?;
                let signer_id = step.signer.as_deref().ok_or("create: missing signer")?;
                let key_info = keys.get(signer_id)
                    .ok_or_else(|| format!("unknown signer '{signer_id}'"))?;
                let params_def = step.params.as_ref().ok_or("create: missing params")?;
                let params = build_parameters(params_def, &keys)?;

                // Build doc with {SCID} placeholder; create_log_entry replaces it with the real SCID
                let did_placeholder = format!("did:webvh:{SCID_HOLDER}:{domain}");
                let doc = build_document(&did_placeholder, params_def, &keys);

                let timestamp = step.timestamp.as_deref()
                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok());

                let entry_state = state
                    .create_log_entry(timestamp, &doc, &params, &key_info.secret)
                    .await
                    .map_err(|e| format!("create_log_entry: {e:?}"))?;

                // Sign witness proofs if witnesses are configured
                if params_def.witness.is_some() {
                    let wit_secrets = all_witness_secrets(&keys);
                    let active_witnesses = entry_state.get_active_witnesses();
                    sign_witness_proofs(&mut witness_proofs, entry_state, &active_witnesses, &wit_secrets)
                        .await
                        .map_err(|e| format!("sign witness proofs: {e:?}"))?;
                }

                // Get the actual DID (with SCID) from the created entry
                let did = entry_state.log_entry.get_state()
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or("created entry has no id")?
                    .to_string();
                current_did = Some(did);

                log_lines.push(serde_json::to_string(&entry_state.log_entry)
                    .map_err(|e| format!("serialize create entry: {e}"))?);
            }

            "update" => {
                let signer_id = step.signer.as_deref().ok_or("update: missing signer")?;
                let key_info = keys.get(signer_id)
                    .ok_or_else(|| format!("unknown signer '{signer_id}'"))?;
                let params_def = step.params.as_ref().ok_or("update: missing params")?;
                let did = current_did.as_deref().ok_or("update before create")?;
                let params = build_parameters(params_def, &keys)?;
                let doc = build_document(did, params_def, &keys);

                let timestamp = step.timestamp.as_deref()
                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok());

                let entry_state = state
                    .create_log_entry(timestamp, &doc, &params, &key_info.secret)
                    .await
                    .map_err(|e| format!("update create_log_entry: {e:?}"))?;

                if params_def.witness.is_some() {
                    let wit_secrets = all_witness_secrets(&keys);
                    let active_witnesses = entry_state.get_active_witnesses();
                    sign_witness_proofs(&mut witness_proofs, entry_state, &active_witnesses, &wit_secrets)
                        .await
                        .map_err(|e| format!("sign witness proofs: {e:?}"))?;
                }

                log_lines.push(serde_json::to_string(&entry_state.log_entry)
                    .map_err(|e| format!("serialize update entry: {e}"))?);
            }

            "deactivate" => {
                let signer_id = step.signer.as_deref().ok_or("deactivate: missing signer")?;
                let key_info = keys.get(signer_id)
                    .ok_or_else(|| format!("unknown signer '{signer_id}'"))?;

                let entry_state = state.deactivate(&key_info.secret)
                    .await
                    .map_err(|e| format!("deactivate: {e:?}"))?;

                log_lines.push(serde_json::to_string(&entry_state.log_entry)
                    .map_err(|e| format!("serialize deactivate entry: {e}"))?);
            }

            "resolve" => {
                let did = current_did.as_deref().ok_or("resolve before create")?;
                let expect = step.expect.as_deref().ok_or("resolve: missing expect")?;

                let resolve_did = match step.version_number {
                    Some(n) => format!("{did}?versionNumber={n}"),
                    None => did.to_string(),
                };

                let jsonl = log_lines.join("\n");
                let witness_str = if witness_proofs.get_total_count() > 0 {
                    Some(serde_json::to_string(&witness_proofs)
                        .map_err(|e| format!("serialize witnesses: {e}"))?)
                } else {
                    None
                };

                // Use a fresh state for resolution (doesn't mutate our generation state)
                let mut resolve_state = DIDWebVHState::default();
                let (log_entry, meta) = resolve_state
                    .resolve_log_owned(&resolve_did, &jsonl, witness_str.as_deref())
                    .await
                    .map_err(|e| format!("resolve '{}': {e:?}", expect))?;

                let did_doc = log_entry.get_did_document()
                    .map_err(|e| format!("get_did_document: {e:?}"))?;

                let mut meta_val = serde_json::to_value(&meta)
                    .map_err(|e| format!("serialize meta: {e}"))?;
                if let Some(obj) = meta_val.as_object_mut() {
                    if let Some(vid) = obj.get("versionId").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                        if let Some(n) = vid.split('-').next().and_then(|s| s.parse::<u64>().ok()) {
                            obj.insert("versionNumber".to_string(), json!(n));
                        }
                    }
                }

                let result = json!({
                    "didDocument": did_doc,
                    "didDocumentMetadata": meta_val,
                    "didResolutionMetadata": {"contentType": "application/did+ld+json"}
                });
                std::fs::write(out_dir.join(expect), serde_json::to_string_pretty(&result).unwrap())
                    .map_err(|e| format!("write {expect}: {e}"))?;
            }

            other => eprintln!("  warning: unknown op '{other}', skipping"),
        }
    }

    // Write did.jsonl
    std::fs::write(out_dir.join("did.jsonl"), log_lines.join("\n") + "\n")
        .map_err(|e| format!("write did.jsonl: {e}"))?;

    // Write did-witness.json if any proofs
    if witness_proofs.get_total_count() > 0 {
        let s = serde_json::to_string_pretty(&witness_proofs)
            .map_err(|e| format!("serialize witness proofs: {e}"))?;
        std::fs::write(out_dir.join("did-witness.json"), s)
            .map_err(|e| format!("write did-witness.json: {e}"))?;
    }

    Ok(())
}
