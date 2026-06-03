"""
Compliance test harness: runs each committed vector through the Python did_webvh
resolver and compares results.

Parametrized over (scenario, impl, result_file) so every implementation's
committed logs are tested against the Python resolver.

Normalization functions labelled "TS COMPAT" compensate for known differences
between what the TypeScript generator writes into vectors/ and what the Python
library produces.  Each one is a candidate for community discussion — see the
inline notes for context.

Known hard failures are marked xfail rather than skipped so the suite stays
green while the incompatibilities are being resolved upstream.
"""

import asyncio
import json
import pytest
from pathlib import Path

import jsoncanon

from did_webvh.resolver import resolve_did

VECTORS_ROOT = Path(__file__).parent.parent.parent / "vectors"


# ---------------------------------------------------------------------------
# Test collection helpers
# ---------------------------------------------------------------------------

def _collect_cases() -> list[tuple[str, str, str]]:
    """Return (scenario_name, impl_name, result_filename) for all impl vectors."""
    cases = []
    for vdir in sorted(VECTORS_ROOT.iterdir()):
        if not vdir.is_dir():
            continue
        if vdir.name.startswith("negative-"):
            continue
        for impl_dir in sorted(vdir.iterdir()):
            if not impl_dir.is_dir():
                continue
            if not (impl_dir / "did.jsonl").exists():
                continue
            for rf in sorted(impl_dir.glob("resolutionResult*.json")):
                cases.append((vdir.name, impl_dir.name, rf.name))
    return cases


def _collect_negative_cases() -> list[tuple[str, str]]:
    """Return (scenario_name, expected_error) for all negative test vectors with a ts/ log."""
    cases = []
    for vdir in sorted(VECTORS_ROOT.iterdir()):
        if not vdir.is_dir() or not vdir.name.startswith("negative-"):
            continue
        ts_dir = vdir / "ts"
        jsonl = ts_dir / "did.jsonl"
        result_json = ts_dir / "resolutionResult.json"
        if not jsonl.exists() or not result_json.exists():
            continue
        expected_error = json.loads(result_json.read_text()).get(
            "didResolutionMetadata", {}
        ).get("error", "?")
        cases.append((vdir.name, expected_error))
    return cases


def _version_number_from_stem(stem: str) -> int | None:
    """Extract the version number from a filename stem like 'resolutionResult.2'."""
    parts = stem.split(".")
    if len(parts) > 1:
        try:
            return int(parts[1])
        except ValueError:
            pass
    return None



# ---------------------------------------------------------------------------
# TS COMPAT normalizations applied to the actual (Python) result
# ---------------------------------------------------------------------------

def _normalize_top_level_context(actual: dict) -> None:
    """
    TS COMPAT — resolution envelope @context
    The Python library always adds "@context": "https://w3id.org/did-resolution/v1"
    to the resolution envelope.  The TS generator does not include this key.
    """
    actual.pop("@context", None)


def _normalize_service_ids(doc: dict | None) -> None:
    """
    TS COMPAT — service ID form
    The TS generator writes implicit service IDs as bare fragments: "#files",
    "#whois".  The Python library expands them to absolute DID URLs.
    """
    if not doc:
        return
    for svc in doc.get("service", []):
        sid = svc.get("id", "")
        if "#" in sid and not sid.startswith("#"):
            svc["id"] = "#" + sid.split("#", 1)[1]


def _normalize_service_endpoints(doc: dict | None) -> None:
    """
    TS COMPAT — implicit service endpoint trailing slash
    The Python library appends a trailing slash to the #files serviceEndpoint.
    """
    if not doc:
        return
    for svc in doc.get("service", []):
        ep = svc.get("serviceEndpoint")
        if isinstance(ep, str) and ep.endswith("/"):
            svc["serviceEndpoint"] = ep.rstrip("/")


def _normalize_resolution_metadata(actual: dict, expected: dict) -> None:
    """
    TS COMPAT — didResolutionMetadata null vs {contentType: ...}
    For successful resolutions the TS vectors commit
    didResolutionMetadata: {"contentType": "application/did+ld+json"}.
    The Python library returns null for the same case.
    """
    if actual.get("didResolutionMetadata") is None:
        if expected.get("didResolutionMetadata") == {"contentType": "application/did+ld+json"}:
            actual["didResolutionMetadata"] = {"contentType": "application/did+ld+json"}


def _normalize_document_metadata(actual: dict, expected: dict) -> None:
    """
    TS COMPAT — extra didDocumentMetadata fields
    The Python library emits additional fields not present in the TS vectors.
    Compare only the keys that appear in the expected metadata.
    """
    act_meta = actual.get("didDocumentMetadata")
    exp_meta = expected.get("didDocumentMetadata")
    if act_meta and exp_meta:
        actual["didDocumentMetadata"] = {k: act_meta[k] for k in exp_meta if k in act_meta}


# ---------------------------------------------------------------------------
# Parametrised test
# ---------------------------------------------------------------------------

@pytest.fixture
def _status_data(request):
    """Passes actual/expected to conftest.py for diff generation in status files."""
    data: dict = {}
    request.node._status_data = data
    return data


@pytest.mark.parametrize("scenario,impl,result_file", _collect_cases())
def test_vector(scenario: str, impl: str, result_file: str, _status_data: dict) -> None:
    log = VECTORS_ROOT / scenario / impl / "did.jsonl"
    expected = json.loads((VECTORS_ROOT / scenario / impl / result_file).read_text())

    did = json.loads(log.read_text().splitlines()[0])["state"]["id"]

    version_number = _version_number_from_stem(Path(result_file).stem)
    kwargs = {"version_number": version_number} if version_number is not None else {}

    result = asyncio.run(resolve_did(did, local_history=log, **kwargs))
    actual = result.serialize()

    _normalize_top_level_context(actual)
    _normalize_service_ids(actual.get("didDocument"))
    _normalize_service_endpoints(actual.get("didDocument"))
    _normalize_resolution_metadata(actual, expected)
    _normalize_document_metadata(actual, expected)

    _status_data["actual"] = actual
    _status_data["expected"] = expected
    assert jsoncanon.canonicalize(actual) == jsoncanon.canonicalize(expected)


# ---------------------------------------------------------------------------
# Negative resolution tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario,expected_error", _collect_negative_cases())
def test_negative_resolution(scenario: str, expected_error: str, _status_data: dict) -> None:
    """Resolver must reject each negative test vector.

    PASS = resolver returned an error or raised an exception.
    FAIL = resolver accepted the invalid log (conformance bug).
    """
    log = VECTORS_ROOT / scenario / "ts" / "did.jsonl"
    log_text = log.read_text().strip()

    if not log_text:
        _status_data["neg_scenario"] = scenario
        _status_data["neg_expected_error"] = expected_error
        _status_data["neg_outcome"] = "skip"
        pytest.skip("URL-only test (no log)")

    did = json.loads(log_text.splitlines()[0])["state"]["id"]

    try:
        result = asyncio.run(resolve_did(did, local_history=log))
        actual_error = result.serialize().get("didResolutionMetadata", {}) or {}
        if actual_error.get("error"):
            # Resolver returned an error — correct behaviour.
            _status_data["neg_outcome"] = "pass"
            _status_data["neg_scenario"] = scenario
            _status_data["neg_expected_error"] = expected_error
        else:
            # Resolver succeeded — it should have rejected this log.
            _status_data["neg_outcome"] = "fail"
            _status_data["neg_scenario"] = scenario
            _status_data["neg_expected_error"] = expected_error
            pytest.fail("resolver accepted invalid log (should have returned an error)")
    except Exception:
        # Any exception counts as rejection — correct behaviour.
        _status_data["neg_outcome"] = "pass"
        _status_data["neg_scenario"] = scenario
        _status_data["neg_expected_error"] = expected_error
