"""
Python generator: reads each scenario's script.yaml, generates DID log artifacts
using the Python did_webvh library, writes them to vectors/<scenario>/python/.

Usage:
    python generate.py                  # process all scenarios
    python generate.py basic-create     # process specific scenario(s)
"""

import asyncio
import json
import sys
import yaml
from pathlib import Path

from did_webvh.resolver import resolve_did

# Reuse all helpers from test_generate.py
from test_generate import _run_script

VECTORS_ROOT = Path(__file__).parent.parent.parent / "vectors"
IMPL_DIR = Path(__file__).parent
IMPL_NAME = "python"



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

    # Remove any stale per-scenario status.md from old generator versions
    stale = out_dir / "status.md"
    if stale.exists():
        stale.unlink()

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

    gen_rows = []
    has_error = False
    for name in scenario_names:
        print(f"Generating {name}... ", end="", flush=True)
        ok, msg = _process_scenario(name)
        print(msg)
        gen_rows.append({
            "testCase": name,
            "result": "✅ PASS" if ok else "❌ FAIL",
            "notes": "" if ok else msg,
        })
        if not ok:
            has_error = True

    (IMPL_DIR / "gen_results.json").write_text(json.dumps(gen_rows, indent=2) + "\n")

    if has_error:
        sys.exit(1)


if __name__ == "__main__":
    main()
