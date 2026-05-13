"""
Python generator: reads each scenario's script.yaml, generates DID log artifacts
using the Python did_webvh library, writes them to vectors/<scenario>/python/,
and produces a status.md showing cross-resolution results against all other
implementation subdirs.

Usage:
    python generate.py                  # process all scenarios
    python generate.py basic-create     # process specific scenario(s)
"""

import asyncio
import difflib
import json
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path

import jsoncanon
from did_webvh.resolver import resolve_did

# Reuse all helpers from test_generate.py
from test_generate import _run_script, _key_from_seed

VECTORS_ROOT = Path(__file__).parent.parent.parent / "vectors"
IMPL_DIR = Path(__file__).parent
IMPL_NAME = "python"


def _read_config() -> dict:
    cfg_path = IMPL_DIR / "config.yaml"
    if cfg_path.exists():
        return yaml.safe_load(cfg_path.read_text()) or {}
    return {}


def _version_line(cfg: dict) -> str:
    parts = [p for p in [cfg.get("version", ""), cfg.get("commit", "")] if p]
    return " @ ".join(parts) if parts else ""


def _log_has_empty_next_key_hashes(log_path: Path) -> bool:
    lines = log_path.read_text().splitlines()
    if len(lines) < 2:
        return False
    for line in lines:
        params = json.loads(line).get("parameters", {})
        if params.get("nextKeyHashes") == []:
            return True
    return False


def _normalize_services_order(result: dict) -> None:
    services = result.get("didDocument", {}).get("service", [])
    if isinstance(services, list):
        services.sort(key=lambda s: s.get("id", ""))


def _normalize_pair(actual: dict, expected: dict) -> None:
    _normalize_services_order(actual)
    _normalize_services_order(expected)
    act_meta = actual.get("didDocumentMetadata") or {}
    exp_meta = expected.get("didDocumentMetadata") or {}
    if act_meta and exp_meta:
        common = set(act_meta.keys()) & set(exp_meta.keys())
        actual["didDocumentMetadata"] = {k: act_meta[k] for k in common}
        expected["didDocumentMetadata"] = {k: exp_meta[k] for k in common}


def _compute_diff(expected: dict, actual: dict) -> str:
    # Use JCS-sorted pretty-print so diff shows content differences, not key-order noise
    exp_lines = json.dumps(json.loads(jsoncanon.canonicalize(expected)), indent=2).splitlines()
    act_lines = json.dumps(json.loads(jsoncanon.canonicalize(actual)), indent=2).splitlines()
    diff = list(difflib.unified_diff(
        exp_lines, act_lines,
        fromfile="expected",
        tofile="actual (python resolver)",
        n=3,
        lineterm="",
    ))
    return "\n".join(diff)


async def _cross_resolve_status(scenario_name: str, scenario_dir: Path) -> str:
    cfg = _read_config()
    ver = _version_line(cfg)
    now = datetime.now(timezone.utc).isoformat()

    rows = []
    diffs = []  # list of (title, diff_body)

    for impl_dir in sorted(scenario_dir.iterdir()):
        if not impl_dir.is_dir():
            continue
        log_path = impl_dir / "did.jsonl"
        if not log_path.exists():
            rows.append(f"| {impl_dir.name} | ⚠️ SKIP | no did.jsonl present |")
            continue

        lines = log_path.read_text().splitlines()
        if not lines:
            rows.append(f"| {impl_dir.name} | ❌ FAIL | empty did.jsonl |")
            continue

        did = json.loads(lines[0]).get("state", {}).get("id")
        if not did:
            rows.append(f"| {impl_dir.name} | ❌ FAIL | cannot extract DID |")
            continue

        label = f"{impl_dir.name} (self)" if impl_dir.name == IMPL_NAME else impl_dir.name

        if _log_has_empty_next_key_hashes(log_path):
            rows.append(f"| {label} | ❌ FAIL | TS COMPAT: nextKeyHashes:[] not accepted |")
            continue

        result_files = sorted(f.name for f in impl_dir.glob("resolutionResult*.json"))

        if not result_files:
            try:
                await resolve_did(did, local_history=log_path)
                rows.append(f"| {label} | ⚠️ SKIP | no resolutionResult files |")
            except Exception as e:
                rows.append(f"| {label} | ❌ FAIL | {str(e).splitlines()[0]} |")
            continue

        impl_outcome = "pass"
        impl_reason = ""

        for result_file in result_files:
            expected = json.loads((impl_dir / result_file).read_text())

            stem = result_file.removesuffix(".json")
            parts = stem.split(".")
            version_number = None
            if len(parts) > 1:
                try:
                    version_number = int(parts[1])
                except ValueError:
                    pass

            kwargs = {"version_number": version_number} if version_number is not None else {}
            try:
                result = await resolve_did(did, local_history=log_path, **kwargs)
                actual = result.serialize()
                actual.pop("@context", None)
                _normalize_pair(actual, expected)
                if jsoncanon.canonicalize(actual) != jsoncanon.canonicalize(expected):
                    if impl_outcome == "pass":
                        impl_outcome = "diff"
                        impl_reason = "output differs"
                    diffs.append((
                        f"Output diff: {IMPL_NAME} resolver vs. {impl_dir.name} — {result_file}",
                        _compute_diff(expected, actual),
                    ))
            except Exception as e:
                if impl_outcome != "diff":
                    impl_outcome = "fail"
                if not impl_reason:
                    impl_reason = str(e).splitlines()[0]

        icon = "❌ FAIL" if impl_outcome == "fail" else "🔶 DIFF" if impl_outcome == "diff" else "✅ PASS"
        rows.append(f"| {label} | {icon} | {impl_reason} |")

    header = f"Implementation: did-webvh-py {ver}\nRun: {now}\n\n" if ver else f"Run: {now}\n\n"
    table = "| Log source | Result | Notes |\n|---|---|---|\n" + "\n".join(rows)
    content = f"# python — {scenario_name}\n\n{header}## Cross-resolution results\n\n{table}\n"

    if diffs:
        content += "\n## Failure details\n"
        for title, diff_body in diffs:
            content += f"\n### {title}\n\n```\n{diff_body}\n```\n"

    return content


def _process_scenario(scenario_name: str) -> tuple[bool, str]:
    scenario_dir = VECTORS_ROOT / scenario_name
    script_path = scenario_dir / "script.yaml"
    if not script_path.exists():
        return False, f"no script.yaml found"

    script = yaml.safe_load(script_path.read_text())
    out_dir = scenario_dir / IMPL_NAME

    try:
        log_entries, witness_proofs, resolve_steps = _run_script(script, omit_empty_nkh=True)
    except Exception as e:
        return False, f"script execution failed: {e}"

    out_dir.mkdir(parents=True, exist_ok=True)

    log_text = "\n".join(json.dumps(e) for e in log_entries) + "\n"
    (out_dir / "did.jsonl").write_text(log_text)

    if witness_proofs:
        (out_dir / "did-witness.json").write_text(json.dumps(witness_proofs, indent=2) + "\n")

    # Resolve each resolve step using the generated log and write resolutionResult files
    if resolve_steps:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "did.jsonl").write_text(log_text)
            if witness_proofs:
                (tmp_path / "did-witness.json").write_text(json.dumps(witness_proofs, indent=2))

            did = log_entries[0]["state"]["id"]
            for rs in resolve_steps:
                kwargs = {"version_number": rs["versionNumber"]} if rs.get("versionNumber") is not None else {}
                result = asyncio.run(resolve_did(did, local_history=tmp_path / "did.jsonl", **kwargs))
                actual = result.serialize()
                actual.pop("@context", None)
                (out_dir / rs["filename"]).write_text(json.dumps(actual, indent=2) + "\n")

    status = asyncio.run(_cross_resolve_status(scenario_name, scenario_dir))
    (out_dir / "status.md").write_text(status)

    return True, "done"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if args:
        scenario_names = [Path(a).name for a in args]
    else:
        scenario_names = sorted(
            d.name for d in VECTORS_ROOT.iterdir()
            if d.is_dir() and (d / "script.yaml").exists()
        )

    has_error = False
    for name in scenario_names:
        print(f"Generating {name}... ", end="", flush=True)
        ok, msg = _process_scenario(name)
        print(msg)
        if not ok:
            has_error = True

    if has_error:
        sys.exit(1)


if __name__ == "__main__":
    main()
