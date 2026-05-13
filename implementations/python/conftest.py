"""
pytest plugin: collect cross-resolution results and write
implementations/python/status.md + implementations/python/diffs.txt
at the end of the test session.
"""
from __future__ import annotations

import json
from difflib import unified_diff
from pathlib import Path

import pytest

IMPL_DIR = Path(__file__).parent
STATUS_PATH = IMPL_DIR / "status.md"
DIFFS_PATH = IMPL_DIR / "diffs.txt"

_rows: list[dict] = []
_diffs: list[dict] = []


# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------

def pytest_sessionstart(session):
    _rows.clear()
    _diffs.clear()
    if STATUS_PATH.exists():
        STATUS_PATH.unlink()
    if DIFFS_PATH.exists():
        DIFFS_PATH.unlink()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.when != "call" or not hasattr(item, "callspec"):
        return

    scenario = item.callspec.params.get("scenario")
    impl = item.callspec.params.get("impl")
    result_file = item.callspec.params.get("result_file")
    if not (scenario and impl and result_file):
        return

    store = getattr(item, "_status_data", {})

    if report.passed:
        _rows.append({"testCase": scenario, "logSource": impl,
                      "result": "✅ PASS", "notes": ""})

    elif report.skipped and hasattr(report, "wasxfail"):
        notes = report.wasxfail.split("\n")[0][:120]
        _rows.append({"testCase": scenario, "logSource": impl,
                      "result": "⚠️ XFAIL", "notes": notes})

    elif report.failed:
        if store.get("actual") is not None and store.get("expected") is not None:
            diff = _compute_diff(store["expected"], store["actual"])
            if diff:
                _rows.append({"testCase": scenario, "logSource": impl,
                              "result": "🔶 DIFF", "notes": "see diffs.txt"})
                _diffs.append({"testCase": scenario, "logSource": impl,
                               "filename": result_file, "diff": diff})
            else:
                _rows.append({"testCase": scenario, "logSource": impl,
                              "result": "❌ FAIL", "notes": "assertion failed (no diff)"})
        else:
            _rows.append({"testCase": scenario, "logSource": impl,
                          "result": "❌ FAIL", "notes": _extract_reason(report)})


def pytest_sessionfinish(session, exitstatus):
    if not _rows:
        return

    version = _read_version()
    header = f"Implementation: did-webvh python {version}\n\n" if version else ""
    table_rows = "\n".join(
        f"| {r['testCase']} | {r['logSource']} | {r['result']} | {r['notes']} |"
        for r in _rows
    )
    STATUS_PATH.write_text(
        f"# python cross-resolution status\n\n{header}"
        f"| Test Case | Log Source | Result | Notes |\n|---|---|---|---|\n{table_rows}\n"
    )

    if _diffs:
        diff_content = "\n\n".join(
            f"=== {d['testCase']} / {d['logSource']} — {d['filename']} ===\n{d['diff']}"
            for d in _diffs
        ) + "\n"
        DIFFS_PATH.write_text(diff_content)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_diff(expected: dict, actual: dict) -> str:
    exp_lines = json.dumps(expected, indent=2, ensure_ascii=False).splitlines(keepends=True)
    act_lines = json.dumps(actual, indent=2, ensure_ascii=False).splitlines(keepends=True)
    return "".join(unified_diff(
        exp_lines, act_lines,
        fromfile="expected", tofile="actual (python resolver)",
        n=3,
    )).rstrip()


def _extract_reason(report) -> str:
    if report.longrepr:
        lines = str(report.longrepr).splitlines()
        for line in reversed(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith("E   assert"):
                return stripped[:120]
        for line in reversed(lines):
            stripped = line.strip()
            if stripped:
                return stripped[:120]
    return "unknown error"


def _read_version() -> str:
    try:
        import yaml
        cfg = yaml.safe_load((IMPL_DIR / "config.yaml").read_text())
        return str(cfg.get("version", "")) if cfg else ""
    except Exception:
        return ""
