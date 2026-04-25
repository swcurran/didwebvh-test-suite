"""
Compliance test harness: runs each committed vector through the Python did_webvh
resolver and compares results.

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

def _collect_cases() -> list[tuple[str, str]]:
    """Return (scenario_name, result_filename) pairs for all vectors."""
    cases = []
    for vdir in sorted(VECTORS_ROOT.iterdir()):
        if not vdir.is_dir():
            continue
        if not (vdir / "did.jsonl").exists():
            continue
        for rf in sorted(vdir.glob("resolutionResult*.json")):
            cases.append((vdir.name, rf.name))
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
# Pre-flight checks for known hard failures
# ---------------------------------------------------------------------------

def _log_has_empty_next_key_hashes(log_path: Path) -> bool:
    """
    TS COMPAT ISSUE — nextKeyHashes: []
    The TS generator writes nextKeyHashes: [] for every non-pre-rotation entry
    (it always serialises the field, defaulting to an empty list).
    The Python library rejects an empty list during update validation: its
    validator for the *previous* entry's nextKeyHashes requires the field to be
    either absent or a non-empty list of strings (state.py: `not next_keys`
    rejects []).  Single-entry logs (create only) are not affected because the
    update path is never reached.
    Resolution needed: either the TS generator should omit the field when empty,
    or the Python library should treat [] as equivalent to absent.
    """
    lines = log_path.read_text().splitlines()
    if len(lines) < 2:
        return False  # single-entry log; update path never reached
    for line in lines:
        params = json.loads(line).get("parameters", {})
        if params.get("nextKeyHashes") == []:
            return True
    return False


# ---------------------------------------------------------------------------
# TS COMPAT normalizations applied to the actual (Python) result
# ---------------------------------------------------------------------------

def _normalize_top_level_context(actual: dict) -> None:
    """
    TS COMPAT — resolution envelope @context
    The Python library always adds "@context": "https://w3id.org/did-resolution/v1"
    to the resolution envelope.  The TS generator does not include this key in
    the committed vectors.  Removed here pending community decision on whether
    vectors should include it.
    """
    actual.pop("@context", None)


def _normalize_service_ids(doc: dict | None) -> None:
    """
    TS COMPAT — service ID form
    The TS generator writes implicit service IDs as bare fragments: "#files",
    "#whois".  The Python library expands them to absolute DID URLs:
    "did:webvh:...#files".  Both are valid per the DID spec; normalise to the
    bare-fragment form used by the TS vectors.
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
    The Python library appends a trailing slash to the #files serviceEndpoint
    (e.g. "https://example.com/").  The TS generator omits it.  Strip for
    comparison.
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
    The Python library returns null for the same case.  Treat null as
    equivalent to the minimal contentType-only object.
    """
    if actual.get("didResolutionMetadata") is None:
        if expected.get("didResolutionMetadata") == {"contentType": "application/did+ld+json"}:
            actual["didResolutionMetadata"] = {"contentType": "application/did+ld+json"}


def _normalize_document_metadata(actual: dict, expected: dict) -> None:
    """
    TS COMPAT — extra didDocumentMetadata fields
    The Python library emits additional fields not present in the TS vectors:
    deactivated (bool), portable (bool), scid (str), watchers (list),
    witness (dict).  The TS vectors include only the fields they explicitly
    assert.  Compare only the keys that appear in the expected metadata so
    that extra Python fields do not cause spurious failures.
    Note: when the TS vector does include a field (e.g. deactivated: true on a
    deactivated DID) it will still be checked because it is present in expected.
    """
    act_meta = actual.get("didDocumentMetadata")
    exp_meta = expected.get("didDocumentMetadata")
    if act_meta and exp_meta:
        actual["didDocumentMetadata"] = {k: act_meta[k] for k in exp_meta if k in act_meta}


# ---------------------------------------------------------------------------
# Parametrised test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario,result_file", _collect_cases())
def test_vector(scenario: str, result_file: str) -> None:
    log = VECTORS_ROOT / scenario / "did.jsonl"
    expected = json.loads((VECTORS_ROOT / scenario / result_file).read_text())

    if _log_has_empty_next_key_hashes(log):
        pytest.xfail(
            "TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation "
            "entries; Python library rejects an empty list. Fix: TS should omit the "
            "field when empty, OR Python should accept []."
        )

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

    assert jsoncanon.canonicalize(actual) == jsoncanon.canonicalize(expected)
