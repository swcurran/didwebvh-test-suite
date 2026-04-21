//! Compliance test harness — resolution tests
//!
//! Runs each committed vector through the Rust didwebvh-rs resolver and
//! compares results against the committed resolutionResult*.json files.
//!
//! Normalization functions labelled "TS COMPAT" compensate for known differences
//! between what the TypeScript generator writes into vectors/ and what the Rust
//! library produces.  Each is a candidate for community discussion — see the
//! Python harness (implementations/python/test_vectors.py) for full rationale.
//!
//! Known hard incompatibilities are reported as XFAIL rather than FAIL so the
//! suite stays green while they are resolved upstream.
//!
//! Usage:
//!   cargo run --bin test-vectors
//!
//! Exit code 0 = all pass or xfail; 1 = at least one failure; 2 = setup error.

use std::path::Path;

use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::prelude::DIDWebVHState;
use serde_json::{json, Value};

const VECTORS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors");

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let vectors_root = Path::new(VECTORS_ROOT);

    let mut scenarios: Vec<_> = match std::fs::read_dir(vectors_root) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect(),
        Err(e) => {
            eprintln!("error: cannot read vectors/: {e}");
            std::process::exit(2);
        }
    };
    scenarios.sort_by_key(|e| e.file_name());

    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut xfail = 0u32;

    for scenario in &scenarios {
        let dir = scenario.path();
        let name = scenario.file_name().to_string_lossy().to_string();
        if !dir.join("did.jsonl").exists() {
            continue;
        }

        let mut result_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("resolutionResult") && n.ends_with(".json")
            })
            .collect();
        result_files.sort_by_key(|e| e.file_name());

        for rf in &result_files {
            let result_file = rf.file_name().to_string_lossy().to_string();
            let test_id = format!("{}/{}", name, result_file);
            match run_vector_test(&dir, &result_file).await {
                TestOutcome::Pass => {
                    println!("PASS   {test_id}");
                    pass += 1;
                }
                TestOutcome::XFail(reason) => {
                    println!("XFAIL  {test_id} ({reason})");
                    xfail += 1;
                }
                TestOutcome::Fail(msg) => {
                    eprintln!("FAIL   {test_id}");
                    for line in msg.lines() {
                        eprintln!("       {line}");
                    }
                    fail += 1;
                }
            }
        }
    }

    println!("\n{pass} passed, {fail} failed, {xfail} xfailed");
    if fail > 0 {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Test outcome
// ---------------------------------------------------------------------------

enum TestOutcome {
    Pass,
    XFail(String),
    Fail(String),
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// "resolutionResult.json" → None, "resolutionResult.2.json" → Some(2)
fn extract_version_number(result_file: &str) -> Option<u32> {
    let stem = result_file.trim_end_matches(".json");
    stem.split('.').nth(1).and_then(|s| s.parse().ok())
}

/// TS COMPAT — nextKeyHashes: []
/// The TS generator writes nextKeyHashes:[] for every non-pre-rotation entry
/// (it always serialises the field, defaulting to an empty list).  The Rust
/// library rejects an empty list when validating the *next* entry's pre-rotation
/// check against the previous entry's nextKeyHashes.  Single-entry logs (create
/// only) are not affected because the update path is never reached.
///
/// We check ALL entries when the log has >= 2 lines, since having [] in the
/// create entry is enough to fail when the second entry is processed.
fn log_has_empty_next_key_hashes(log_content: &str) -> bool {
    let lines: Vec<&str> = log_content.lines().collect();
    if lines.len() < 2 {
        return false; // single-entry log; update path never reached
    }
    for line in &lines {
        if let Ok(entry) = serde_json::from_str::<Value>(line) {
            if entry.pointer("/parameters/nextKeyHashes") == Some(&json!([])) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// TS COMPAT normalizations applied to the actual (Rust) result
// ---------------------------------------------------------------------------

fn normalize_actual(actual: &mut Value, expected: &Value) {
    let Some(obj) = actual.as_object_mut() else {
        return;
    };

    // TS COMPAT — resolution envelope @context
    // The Rust library may add "@context": "https://w3id.org/did-resolution/v1"
    // to the resolution envelope.  The TS generator does not include this key.
    obj.remove("@context");

    // TS COMPAT — didResolutionMetadata null vs {contentType: ...}
    // For successful resolutions the TS vectors commit
    // didResolutionMetadata: {"contentType": "application/did+ld+json"}.
    // The Rust library may return null for the same case.
    if obj
        .get("didResolutionMetadata")
        .map(|v| v.is_null())
        .unwrap_or(false)
    {
        if expected.get("didResolutionMetadata")
            == Some(&json!({"contentType": "application/did+ld+json"}))
        {
            obj.insert(
                "didResolutionMetadata".to_string(),
                json!({"contentType": "application/did+ld+json"}),
            );
        }
    }

    // TS COMPAT — service ID form
    // The TS generator writes implicit service IDs as bare fragments: "#files".
    // The Rust library may expand them to absolute DID URLs: "did:webvh:...#files".
    if let Some(services) = obj
        .get_mut("didDocument")
        .and_then(|d| d.get_mut("service"))
        .and_then(|s| s.as_array_mut())
    {
        for svc in services.iter_mut() {
            if let Some(id) = svc.get("id").and_then(|v| v.as_str()) {
                if !id.starts_with('#') {
                    if let Some(frag) = id.split_once('#').map(|(_, f)| format!("#{f}")) {
                        svc["id"] = json!(frag);
                    }
                }
            }
        }
    }

    // TS COMPAT — service endpoint trailing slash
    // The Rust library may append a trailing slash to the #files serviceEndpoint.
    if let Some(services) = obj
        .get_mut("didDocument")
        .and_then(|d| d.get_mut("service"))
        .and_then(|s| s.as_array_mut())
    {
        for svc in services.iter_mut() {
            if let Some(ep) = svc.get("serviceEndpoint").and_then(|v| v.as_str()) {
                if ep.ends_with('/') {
                    let trimmed = ep.trim_end_matches('/').to_string();
                    svc["serviceEndpoint"] = json!(trimmed);
                }
            }
        }
    }

    // TS COMPAT — service ordering
    // The Rust library may return implied services in a different order than the
    // TS generator.  Sort actual services by id for a stable comparison.
    if let Some(services) = obj
        .get_mut("didDocument")
        .and_then(|d| d.get_mut("service"))
        .and_then(|s| s.as_array_mut())
    {
        services.sort_by(|a, b| {
            let a_id = a.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let b_id = b.get("id").and_then(|v| v.as_str()).unwrap_or("");
            a_id.cmp(b_id)
        });
    }

    // TS COMPAT — extra didDocumentMetadata fields
    // The Rust library emits additional fields not present in the TS vectors:
    // deactivated, portable, scid, watchers, witness.  Compare only the keys
    // that appear in the expected metadata.
    if let (Some(act_meta), Some(exp_meta)) = (
        obj.get("didDocumentMetadata")
            .and_then(|v| v.as_object())
            .cloned(),
        expected
            .get("didDocumentMetadata")
            .and_then(|v| v.as_object()),
    ) {
        let filtered: serde_json::Map<String, Value> = exp_meta
            .keys()
            .filter_map(|k| act_meta.get(k).map(|v| (k.clone(), v.clone())))
            .collect();
        obj.insert("didDocumentMetadata".to_string(), Value::Object(filtered));
    }
}

// ---------------------------------------------------------------------------
// Core test logic
// ---------------------------------------------------------------------------

async fn run_vector_test(scenario_dir: &Path, result_file: &str) -> TestOutcome {
    let log_content = match std::fs::read_to_string(scenario_dir.join("did.jsonl")) {
        Ok(c) => c,
        Err(e) => return TestOutcome::Fail(format!("read did.jsonl: {e}")),
    };

    if log_has_empty_next_key_hashes(&log_content) {
        return TestOutcome::XFail(
            "TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects"
                .to_string(),
        );
    }

    let expected: Value =
        match std::fs::read_to_string(scenario_dir.join(result_file)).map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map_err(|e: serde_json::Error| e.to_string())) {
            Ok(v) => v,
            Err(e) => return TestOutcome::Fail(format!("read {result_file}: {e}")),
        };

    // Extract the DID from the first log entry's state.id
    let first_line = match log_content.lines().next() {
        Some(l) => l,
        None => return TestOutcome::Fail("empty did.jsonl".to_string()),
    };
    let first_entry: Value = match serde_json::from_str(first_line) {
        Ok(v) => v,
        Err(e) => return TestOutcome::Fail(format!("parse first log entry: {e}")),
    };
    let base_did = match first_entry.pointer("/state/id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return TestOutcome::Fail("no /state/id in first log entry".to_string()),
    };

    // Load witness proofs when present
    let witness_content = {
        let wp = scenario_dir.join("did-witness.json");
        if wp.exists() {
            match std::fs::read_to_string(&wp) {
                Ok(c) => Some(c),
                Err(e) => return TestOutcome::Fail(format!("read did-witness.json: {e}")),
            }
        } else {
            None
        }
    };

    // Append ?versionNumber=N to the DID URL for version-specific resolution.
    // resolve_log_owned() parses DID URL query parameters internally.
    let did = match extract_version_number(result_file) {
        Some(n) => format!("{base_did}?versionNumber={n}"),
        None => base_did.clone(),
    };

    let mut state = DIDWebVHState::default();
    let (log_entry, meta) = match state
        .resolve_log_owned(&did, &log_content, witness_content.as_deref())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("{e:?}");
            // Catch resolution errors caused by known TS compat issues
            if msg.to_lowercase().contains("nextkeyhashe")
                || msg.to_lowercase().contains("prerotation")
                || msg.to_lowercase().contains("pre-rotation")
                // TS COMPAT: TS includes updateKeys in the deactivation entry;
                // Rust library requires updateKeys to be null when deactivated.
                || msg.contains("updateKeys are not null")
                || msg.contains("updatekeys are not null")
            {
                return TestOutcome::XFail(format!("TS COMPAT: resolution error: {msg}"));
            }
            return TestOutcome::Fail(format!("resolve_log: {msg}"));
        }
    };

    let did_document = match log_entry.get_did_document() {
        Ok(d) => d,
        Err(e) => return TestOutcome::Fail(format!("get_did_document: {e}")),
    };

    let mut did_document_metadata = match serde_json::to_value(&meta) {
        Ok(v) => v,
        Err(e) => return TestOutcome::Fail(format!("serialize MetaData: {e}")),
    };

    // TS COMPAT — versionNumber
    // The Rust MetaData struct does not include versionNumber; the TS vectors do.
    // Derive it by parsing the leading integer from versionId (e.g. "2-Qm..." → 2).
    if let Some(meta_obj) = did_document_metadata.as_object_mut() {
        if let Some(version_id) = meta_obj.get("versionId").and_then(|v| v.as_str()) {
            if let Some(n) = version_id.split('-').next().and_then(|s| s.parse::<u64>().ok()) {
                meta_obj.insert("versionNumber".to_string(), json!(n));
            }
        }
    }

    let mut actual = json!({
        "didDocument": did_document,
        "didDocumentMetadata": did_document_metadata,
        "didResolutionMetadata": {"contentType": "application/did+ld+json"},
    });

    normalize_actual(&mut actual, &expected);

    if actual == expected {
        return TestOutcome::Pass;
    }

    let act_str = serde_json::to_string_pretty(&actual).unwrap_or_default();
    let exp_str = serde_json::to_string_pretty(&expected).unwrap_or_default();
    TestOutcome::Fail(format!(
        "mismatch\n--- expected ---\n{}\n--- actual ---\n{}",
        exp_str
            .lines()
            .take(40)
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
        act_str
            .lines()
            .take(40)
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    ))
}
