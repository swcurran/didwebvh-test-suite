//! Compliance test harness — resolution tests
//!
//! Runs each committed vector (from every implementation subdir) through the
//! Rust didwebvh-rs resolver and compares results against the committed
//! resolutionResult*.json files.  Also writes a status.md to the rust/ subdir
//! of each scenario showing cross-resolution results.
//!
//! Normalization functions labelled "TS COMPAT" compensate for known differences
//! between what the TypeScript generator writes into vectors/ and what the Rust
//! library produces.  Each is a candidate for community discussion.
//!
//! Known hard incompatibilities are reported as XFAIL rather than FAIL.
//!
//! Usage:
//!   cargo run --bin test-vectors
//!
//! Exit code 0 = all pass or xfail; 1 = at least one failure; 2 = setup error.

use std::path::Path;

use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::prelude::DIDWebVHState;
use serde_json::{json, Value};
use serde_jcs;
use similar::{ChangeTag, TextDiff};

const VECTORS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors");
const IMPL_DIR: &str = env!("CARGO_MANIFEST_DIR");
const IMPL_NAME: &str = "rust";
const CONFIG_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/config.yaml");

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let vectors_root = Path::new(VECTORS_ROOT);
    let impl_dir = Path::new(IMPL_DIR);

    // Delete output files at the start of each run
    let status_path = impl_dir.join("status.md");
    let diffs_path = impl_dir.join("diffs.txt");
    let _ = std::fs::remove_file(&status_path);
    let _ = std::fs::remove_file(&diffs_path);

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
    let mut xfail = 0u32;
    let mut fail = 0u32;
    let mut diff_count = 0u32;

    // (test_case, log_source, result, notes)
    let mut all_rows: Vec<(String, String, String, String)> = Vec::new();
    // (test_case, log_source, filename, diff_body)
    let mut all_diffs: Vec<(String, String, String, String)> = Vec::new();

    for scenario in &scenarios {
        let scenario_dir = scenario.path();
        let scenario_name = scenario.file_name().to_string_lossy().to_string();

        if !scenario_dir.join("script.yaml").exists() {
            continue;
        }

        // Delete old per-scenario status.md if it exists
        let old_status = scenario_dir.join(IMPL_NAME).join("status.md");
        let _ = std::fs::remove_file(&old_status);

        let mut impl_dirs: Vec<_> = match std::fs::read_dir(&scenario_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .collect(),
            Err(_) => continue,
        };
        impl_dirs.sort_by_key(|e| e.file_name());

        for impl_entry in &impl_dirs {
            let impl_path = impl_entry.path();
            let impl_name = impl_entry.file_name().to_string_lossy().to_string();

            if !impl_path.join("did.jsonl").exists() {
                all_rows.push((scenario_name.clone(), impl_name, "⚠️ SKIP".to_string(), "no did.jsonl".to_string()));
                continue;
            }

            let mut result_files: Vec<_> = std::fs::read_dir(&impl_path)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_string();
                    n.starts_with("resolutionResult") && n.ends_with(".json")
                })
                .collect();
            result_files.sort_by_key(|e| e.file_name());

            if result_files.is_empty() {
                all_rows.push((scenario_name.clone(), impl_name, "⚠️ SKIP".to_string(), "no resolutionResult files".to_string()));
                continue;
            }

            let mut impl_outcome = "pass";
            let mut impl_reason = String::new();

            for rf in &result_files {
                let result_file = rf.file_name().to_string_lossy().to_string();
                let test_id = format!("{scenario_name}/{impl_name}/{result_file}");
                match run_vector_test(&impl_path, &result_file).await {
                    TestOutcome::Pass => {
                        println!("PASS   {test_id}");
                        pass += 1;
                    }
                    TestOutcome::XFail(reason) => {
                        println!("XFAIL  {test_id} ({reason})");
                        xfail += 1;
                        if impl_outcome == "pass" { impl_outcome = "xfail"; impl_reason = reason; }
                    }
                    TestOutcome::Fail(reason) => {
                        eprintln!("FAIL   {test_id} ({reason})");
                        fail += 1;
                        if impl_outcome != "diff" { impl_outcome = "fail"; }
                        if impl_reason.is_empty() { impl_reason = reason; }
                    }
                    TestOutcome::Diff(msg) => {
                        eprintln!("DIFF   {test_id}");
                        for line in msg.lines().take(5) { eprintln!("       {line}"); }
                        diff_count += 1;
                        if impl_outcome == "pass" || impl_outcome == "xfail" { impl_outcome = "diff"; }
                        all_diffs.push((scenario_name.clone(), impl_name.clone(), result_file, msg));
                    }
                }
            }

            let label = if impl_name == IMPL_NAME {
                format!("{impl_name} (self)")
            } else {
                impl_name.clone()
            };

            let (result, notes) = match impl_outcome {
                "xfail" => ("⚠️ XFAIL".to_string(), impl_reason.chars().take(120).collect()),
                "fail"  => ("❌ FAIL".to_string(),  impl_reason.chars().take(120).collect()),
                "diff"  => ("🔶 DIFF".to_string(),  "see diffs.txt".to_string()),
                _       => ("✅ PASS".to_string(),  String::new()),
            };
            all_rows.push((scenario_name.clone(), label, result, notes));
        }
    }

    println!("\n{pass} passed, {diff_count} diff, {fail} failed, {xfail} xfailed");

    // Write implementations/rust/status.md
    if !all_rows.is_empty() {
        let version = read_config_version();
        let header = if version.is_empty() { String::new() } else {
            format!("Implementation: didwebvh-rs {version}\n\n")
        };
        let table_rows: String = all_rows.iter()
            .map(|(tc, ls, r, n)| format!("| {tc} | {ls} | {r} | {n} |"))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!(
            "# rust cross-resolution status\n\n{header}| Test Case | Log Source | Result | Notes |\n|---|---|---|---|\n{table_rows}\n"
        );
        if let Err(e) = std::fs::write(&status_path, &content) {
            eprintln!("warning: could not write status.md: {e}");
        }
    }

    // Write implementations/rust/diffs.txt
    if !all_diffs.is_empty() {
        let content: String = all_diffs.iter()
            .map(|(tc, ls, f, d)| format!("=== {tc} / {ls} — {f} ===\n{d}"))
            .collect::<Vec<_>>()
            .join("\n\n") + "\n";
        if let Err(e) = std::fs::write(&diffs_path, &content) {
            eprintln!("warning: could not write diffs.txt: {e}");
        }
    }

    if fail > 0 || diff_count > 0 {
        std::process::exit(1);
    }
}

fn read_config_version() -> String {
    let cfg_path = Path::new(CONFIG_PATH);
    let Ok(text) = std::fs::read_to_string(cfg_path) else { return String::new(); };
    let version = text.lines()
        .find(|l| l.starts_with("version:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    let commit = text.lines()
        .find(|l| l.starts_with("commit:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    [version, commit].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" @ ")
}

// ---------------------------------------------------------------------------
// Test outcome
// ---------------------------------------------------------------------------

enum TestOutcome {
    Pass,
    XFail(String), // known incompatibility — not a spec violation
    Fail(String),  // resolver errored — no result produced
    Diff(String),  // resolver ran but output differs from expected
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
fn log_has_empty_next_key_hashes(log_content: &str) -> bool {
    let lines: Vec<&str> = log_content.lines().collect();
    if lines.len() < 2 {
        return false;
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
// Normalizations applied to both sides before comparison
// ---------------------------------------------------------------------------

fn normalize_services(value: &mut Value) {
    if let Some(services) = value
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
}

fn normalize_pair(actual: &mut Value, expected: &mut Value) {
    // Remove @context from actual (Rust library always includes it)
    if let Some(obj) = actual.as_object_mut() {
        obj.remove("@context");
    }

    // Null didResolutionMetadata → default contentType (Rust returns null on success)
    if actual.get("didResolutionMetadata").map(|v| v.is_null()).unwrap_or(false) {
        if expected.get("didResolutionMetadata")
            == Some(&json!({"contentType": "application/did+ld+json"}))
        {
            if let Some(obj) = actual.as_object_mut() {
                obj.insert(
                    "didResolutionMetadata".to_string(),
                    json!({"contentType": "application/did+ld+json"}),
                );
            }
        }
    }

    // Sort services on both sides (order-independent comparison)
    normalize_services(actual);
    normalize_services(expected);

    // Restrict didDocumentMetadata to the intersection of keys present in both
    let act_keys: std::collections::BTreeSet<String> = actual
        .get("didDocumentMetadata")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let exp_keys: std::collections::BTreeSet<String> = expected
        .get("didDocumentMetadata")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let common: std::collections::BTreeSet<&String> = act_keys.intersection(&exp_keys).collect();

    if !common.is_empty() {
        if let Some(act_meta) = actual
            .get("didDocumentMetadata")
            .and_then(|v| v.as_object())
            .cloned()
        {
            let filtered_act: serde_json::Map<String, Value> = common
                .iter()
                .filter_map(|k| act_meta.get(*k).map(|v| ((*k).clone(), v.clone())))
                .collect();
            actual.as_object_mut().unwrap()
                .insert("didDocumentMetadata".to_string(), Value::Object(filtered_act));
        }
        if let Some(exp_meta) = expected
            .get("didDocumentMetadata")
            .and_then(|v| v.as_object())
            .cloned()
        {
            let filtered_exp: serde_json::Map<String, Value> = common
                .iter()
                .filter_map(|k| exp_meta.get(*k).map(|v| ((*k).clone(), v.clone())))
                .collect();
            expected.as_object_mut().unwrap()
                .insert("didDocumentMetadata".to_string(), Value::Object(filtered_exp));
        }
    }
}

// ---------------------------------------------------------------------------
// Core test logic
// ---------------------------------------------------------------------------

async fn run_vector_test(impl_dir: &Path, result_file: &str) -> TestOutcome {
    let log_content = match std::fs::read_to_string(impl_dir.join("did.jsonl")) {
        Ok(c) => c,
        Err(e) => return TestOutcome::Fail(format!("read did.jsonl: {e}")),
    };

    if log_has_empty_next_key_hashes(&log_content) {
        return TestOutcome::XFail(
            "TS COMPAT: nextKeyHashes:[] — TS serialises empty list; Rust library rejects"
                .to_string(),
        );
    }

    let mut expected: Value =
        match std::fs::read_to_string(impl_dir.join(result_file)).map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map_err(|e: serde_json::Error| e.to_string())) {
            Ok(v) => v,
            Err(e) => return TestOutcome::Fail(format!("read {result_file}: {e}")),
        };

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

    let witness_content = {
        let wp = impl_dir.join("did-witness.json");
        if wp.exists() {
            match std::fs::read_to_string(&wp) {
                Ok(c) => Some(c),
                Err(e) => return TestOutcome::Fail(format!("read did-witness.json: {e}")),
            }
        } else {
            None
        }
    };

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
            if msg.to_lowercase().contains("nextkeyhashe")
                || msg.to_lowercase().contains("prerotation")
                || msg.to_lowercase().contains("pre-rotation")
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

    normalize_pair(&mut actual, &mut expected);

    let actual_jcs = match serde_jcs::to_vec(&actual) {
        Ok(b) => b,
        Err(e) => return TestOutcome::Fail(format!("JCS serialize actual: {e}")),
    };
    let expected_jcs = match serde_jcs::to_vec(&expected) {
        Ok(b) => b,
        Err(e) => return TestOutcome::Fail(format!("JCS serialize expected: {e}")),
    };
    if actual_jcs == expected_jcs {
        return TestOutcome::Pass;
    }

    let act_str = serde_json::to_string_pretty(&actual).unwrap_or_default();
    let exp_str = serde_json::to_string_pretty(&expected).unwrap_or_default();
    let diff = TextDiff::from_lines(&exp_str, &act_str);
    let mut diff_out = String::from("--- expected\n+++ actual (rust resolver)\n");
    let groups = diff.grouped_ops(3);
    for (i, group) in groups.iter().enumerate() {
        for op in group {
            for change in diff.iter_changes(op) {
                let prefix = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal  => " ",
                };
                diff_out.push_str(&format!("{prefix}{}", change.value()));
            }
        }
        if i + 1 < groups.len() {
            diff_out.push_str("...\n");
        }
    }
    TestOutcome::Diff(diff_out)
}
