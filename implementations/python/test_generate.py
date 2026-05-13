"""
Generation compliance test: exercises the Python did_webvh library's DID
creation, update, and deactivation.

For each scenario this harness re-executes the committed script.yaml using the
Python library and checks that:
  1. Every generated log entry matches the committed did.jsonl line-for-line.
  2. Generated witness proofs (when present) match the committed did-witness.json.
  3. Each `resolve` step produces a result matching the committed
     resolutionResult*.json (same TS COMPAT normalizations as test_vectors.py).

Normalization functions labelled "TS COMPAT" compensate for known differences
between TS and Python outputs. Hard incompatibilities are marked xfail.
"""

import asyncio
import json
import tempfile
import pytest
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import yaml
from multiformats import multibase

from did_webvh.askar import AskarSigningKey
from did_webvh.core.proof import di_jcs_sign
from did_webvh.core.state import DocumentState
from did_webvh.resolver import resolve_did

VECTORS_ROOT = Path(__file__).parent.parent.parent / "vectors"
TS_IMPL = "ts"

DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MULTIKEY_CONTEXT = "https://w3id.org/security/multikey/v1"
SCID_PLACEHOLDER = "{SCID}"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _key_from_seed(seed_hex: str) -> AskarSigningKey:
    """Derive a deterministic Ed25519 signing key from a 32-byte hex seed."""
    return AskarSigningKey.from_secret_bytes("ed25519", bytes.fromhex(seed_hex))


def _next_key_hash(signing_key: AskarSigningKey) -> str:
    """
    Compute the pre-rotation commitment hash for a key.
    SHA-256 the multikey string (UTF-8), wrap in sha2-256 multihash, base58btc encode.
    Compatible with the TS deriveNextKeyHash helper.
    """
    mk = str(signing_key.multikey)
    h = sha256(mk.encode()).digest()
    mh = bytes([0x12, 0x20]) + h
    return multibase.encode(mh, "base58btc")[1:]  # strip 'z' prefix


def _vm_fragment(multikey: str) -> str:
    """
    TS COMPAT — VM ID fragment convention.
    TS uses the last 8 chars of the multikey (without leading 'z') as the
    DID fragment for the verification method ID.
    """
    return multikey.lstrip("z")[-8:]


# ---------------------------------------------------------------------------
# Document builders (replicate TS didwebvh-ts createDID document structure)
# ---------------------------------------------------------------------------

def _genesis_doc(
    domain: str,
    update_keys: list[AskarSigningKey],
    *,
    context: list[str] | None = None,
    also_known_as: list[str] | None = None,
    services: list[dict] | None = None,
) -> dict:
    """
    Build a genesis DID document with the {SCID} placeholder.

    TS COMPAT — document structure: the TS didwebvh-ts library adds a 'purpose'
    field inside each verification method, uses the last-8-chars fragment
    convention for VM IDs, and always emits empty relationship arrays.  These
    details affect the SCID hash, so we must replicate them exactly.
    """
    placeholder_did = f"did:webvh:{SCID_PLACEHOLDER}:{domain}"
    ctx = [DID_CONTEXT, MULTIKEY_CONTEXT]
    if context:
        ctx.extend(context)

    vms, auth_refs = [], []
    for sk in update_keys:
        mk = str(sk.multikey)
        frag = _vm_fragment(mk)
        vm_id = f"{placeholder_did}#{frag}"
        vms.append({
            "type": "Multikey",
            "publicKeyMultibase": mk,
            "purpose": "authentication",
            "id": vm_id,
        })
        auth_refs.append(vm_id)

    doc = {
        "@context": ctx,
        "id": placeholder_did,
        "controller": placeholder_did,
        "verificationMethod": vms,
        "authentication": auth_refs,
        "assertionMethod": [],
        "keyAgreement": [],
        "capabilityDelegation": [],
        "capabilityInvocation": [],
    }
    if also_known_as:
        doc["alsoKnownAs"] = also_known_as
    if services:
        doc["service"] = services
    return doc


def _update_doc(
    prev_doc: dict,
    did: str,
    update_keys: list[AskarSigningKey],
    *,
    also_known_as: list[str] | None = None,
    services: list[dict] | None = None,
    domain: str | None = None,
) -> dict:
    """Build an updated document from the previous one."""
    doc = deepcopy(prev_doc)
    if domain:
        # portable move: update the DID ID
        doc["id"] = did
        doc["controller"] = did

    vms, auth_refs = [], []
    for sk in update_keys:
        mk = str(sk.multikey)
        frag = _vm_fragment(mk)
        vm_id = f"{did}#{frag}"
        vms.append({
            "type": "Multikey",
            "publicKeyMultibase": mk,
            "purpose": "authentication",
            "id": vm_id,
        })
        auth_refs.append(vm_id)
    doc["verificationMethod"] = vms
    doc["authentication"] = auth_refs

    if also_known_as is not None:
        doc["alsoKnownAs"] = also_known_as
    elif "alsoKnownAs" in doc:
        del doc["alsoKnownAs"]

    if services is not None:
        doc["service"] = services
    elif "service" in doc:
        del doc["service"]

    return doc


# ---------------------------------------------------------------------------
# Params builders (replicate TS default field set)
# ---------------------------------------------------------------------------

def _create_params(
    update_keys: list[AskarSigningKey],
    *,
    portable: bool = False,
    next_key_hashes: list[str] | None = None,
    witness: dict | None = None,
    omit_empty_nkh: bool = False,
) -> dict:
    """
    TS COMPAT — create params defaults.
    TS always serialises portable/nextKeyHashes/watchers/witness/deactivated
    even when they are default-valued (false / [] / {} ).
    Set omit_empty_nkh=True when generating Python-native artifacts to avoid
    passing nextKeyHashes:[] which the Python library rejects.
    """
    nkh = next_key_hashes if next_key_hashes is not None else []
    params = {
        "updateKeys": [str(sk.multikey) for sk in update_keys],
        "portable": portable,
        "watchers": [],
        "witness": witness if witness is not None else {},
        "deactivated": False,
    }
    if nkh or not omit_empty_nkh:
        params["nextKeyHashes"] = nkh
    return params


def _update_params_delta(
    update_keys: list[AskarSigningKey],
    *,
    next_key_hashes: list[str] | None = None,
    witness: dict | None = None,
    omit_empty_nkh: bool = False,
) -> dict:
    """
    TS COMPAT — update params delta.
    TS always includes updateKeys/nextKeyHashes/witness/watchers in every
    non-deactivation update delta.
    Set omit_empty_nkh=True when generating Python-native artifacts.
    """
    nkh = next_key_hashes if next_key_hashes is not None else []
    params = {
        "updateKeys": [str(sk.multikey) for sk in update_keys],
        "witness": witness if witness is not None else {},
        "watchers": [],
    }
    if nkh or not omit_empty_nkh:
        params["nextKeyHashes"] = nkh
    return params


def _deactivate_params_delta(update_keys: list[AskarSigningKey]) -> dict:
    """Deactivation delta only carries updateKeys and deactivated: true."""
    return {
        "updateKeys": [str(sk.multikey) for sk in update_keys],
        "deactivated": True,
    }


# ---------------------------------------------------------------------------
# Witness proof generation
# ---------------------------------------------------------------------------

def _witness_proof(version_id: str, witness_key: AskarSigningKey, timestamp: str) -> dict:
    """Generate a witness proof for a given versionId using a seeded key."""
    mk = str(witness_key.multikey)
    kid = f"did:key:{mk}#{mk}"
    return di_jcs_sign(
        {"versionId": version_id},
        witness_key,
        purpose="assertionMethod",
        timestamp=timestamp,
        kid=kid,
    )


# ---------------------------------------------------------------------------
# TS COMPAT normalizations (shared with test_vectors.py)
# ---------------------------------------------------------------------------

def _normalize_top_level_context(actual: dict) -> None:
    """TS COMPAT: Python adds @context at envelope level; TS vectors omit it."""
    actual.pop("@context", None)


def _normalize_service_ids(doc: dict | None) -> None:
    """TS COMPAT: Python expands service IDs to full DID URLs; TS uses #fragment."""
    if not doc:
        return
    for svc in doc.get("service", []):
        sid = svc.get("id", "")
        if "#" in sid and not sid.startswith("#"):
            svc["id"] = "#" + sid.split("#", 1)[1]


def _normalize_service_endpoints(doc: dict | None) -> None:
    """TS COMPAT: Python appends trailing slash to #files serviceEndpoint."""
    if not doc:
        return
    for svc in doc.get("service", []):
        ep = svc.get("serviceEndpoint")
        if isinstance(ep, str) and ep.endswith("/"):
            svc["serviceEndpoint"] = ep.rstrip("/")


def _normalize_resolution_metadata(actual: dict, expected: dict) -> None:
    """TS COMPAT: Python returns null didResolutionMetadata on success."""
    if actual.get("didResolutionMetadata") is None:
        if expected.get("didResolutionMetadata") == {"contentType": "application/did+ld+json"}:
            actual["didResolutionMetadata"] = {"contentType": "application/did+ld+json"}


def _normalize_document_metadata(actual: dict, expected: dict) -> None:
    """TS COMPAT: Python emits extra metadata fields not in TS vectors."""
    act_meta = actual.get("didDocumentMetadata")
    exp_meta = expected.get("didDocumentMetadata")
    if act_meta and exp_meta:
        actual["didDocumentMetadata"] = {k: act_meta[k] for k in exp_meta if k in act_meta}


# ---------------------------------------------------------------------------
# Script executor
# ---------------------------------------------------------------------------

def _build_witness_param(config: dict, key_map: dict) -> dict:
    return {
        "threshold": config["threshold"],
        "witnesses": [
            {"id": f"did:key:{str(key_map[w['id']].multikey)}"}
            for w in config["witnesses"]
        ],
    }


def _run_script(script: dict, omit_empty_nkh: bool = False) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Execute a script and return (log_entries, witness_proofs, resolve_results).

    log_entries      — list of history_line() dicts in order
    witness_proofs   — list of {versionId, proof:[...]} dicts (did-witness.json format)
    resolve_results  — list of {filename, result} for each resolve step

    Set omit_empty_nkh=True when generating Python-native artifacts so that
    nextKeyHashes is omitted when empty (Python library rejects []).
    """
    key_map = {k["id"]: _key_from_seed(k["seed"]) for k in script["keys"]}

    log_entries: list[dict] = []
    witness_proofs: list[dict] = []
    resolve_results: list[dict] = []

    state: DocumentState | None = None
    current_update_keys: list[AskarSigningKey] = []
    witness_key_map: dict[str, AskarSigningKey] = {}

    for step in script["steps"]:
        op = step["op"]

        if op == "create":
            params_spec = step.get("params", {})
            uk_ids = params_spec.get("updateKeys", [step["signer"]])
            current_update_keys = [key_map[kid] for kid in uk_ids]
            signer = key_map[step["signer"]]

            # Pre-rotation: resolve nextKeyHashes from key IDs to hashes
            nkh_ids = params_spec.get("nextKeyHashes", [])
            next_key_hashes = [_next_key_hash(key_map[kid]) for kid in nkh_ids] if nkh_ids else None

            # Witness config
            witness_param = None
            if params_spec.get("witness"):
                witness_param = _build_witness_param(params_spec["witness"], key_map)
                witness_key_map = {
                    w["id"]: key_map[w["id"]]
                    for w in params_spec["witness"]["witnesses"]
                }

            doc = _genesis_doc(
                step["domain"],
                current_update_keys,
                context=params_spec.get("context"),
                also_known_as=params_spec.get("alsoKnownAs"),
                services=params_spec.get("services"),
            )
            params = _create_params(
                current_update_keys,
                portable=bool(params_spec.get("portable")),
                next_key_hashes=next_key_hashes,
                witness=witness_param,
                omit_empty_nkh=omit_empty_nkh,
            )
            ts = step.get("timestamp")
            state = DocumentState.initial(params=params, document=doc, timestamp=ts)
            state.sign(signer, timestamp=ts)
            log_entries.append(state.history_line())

            if witness_key_map:
                proofs = [
                    _witness_proof(state.version_id, wk, step.get("timestamp"))
                    for wk in witness_key_map.values()
                ]
                witness_proofs.append({"versionId": state.version_id, "proof": proofs})

        elif op == "update":
            assert state is not None
            params_spec = step.get("params", {})
            uk_ids = params_spec.get("updateKeys", [step["signer"]])
            new_update_keys = [key_map[kid] for kid in uk_ids]
            signer = key_map[step["signer"]]

            nkh_ids = params_spec.get("nextKeyHashes", [])
            next_key_hashes = [_next_key_hash(key_map[kid]) for kid in nkh_ids] if nkh_ids else None

            witness_param = None
            if "witness" in params_spec:
                witness_param = _build_witness_param(params_spec["witness"], key_map)
                witness_key_map = {
                    w["id"]: key_map[w["id"]]
                    for w in params_spec["witness"]["witnesses"]
                }

            current_did = state.document["id"]
            new_doc = _update_doc(
                state.document,
                current_did,
                new_update_keys,
                also_known_as=params_spec.get("alsoKnownAs"),
                services=params_spec.get("services"),
                domain=step.get("domain"),
            )
            delta = _update_params_delta(
                new_update_keys,
                next_key_hashes=next_key_hashes,
                witness=witness_param,
                omit_empty_nkh=omit_empty_nkh,
            )
            ts = step.get("timestamp")
            state = state.create_next(new_doc, params_update=delta, timestamp=ts)
            state.sign(signer, timestamp=ts)
            current_update_keys = new_update_keys
            log_entries.append(state.history_line())

            if witness_key_map:
                proofs = [
                    _witness_proof(state.version_id, wk, step.get("timestamp"))
                    for wk in witness_key_map.values()
                ]
                witness_proofs.append({"versionId": state.version_id, "proof": proofs})

        elif op == "deactivate":
            assert state is not None
            signer = key_map[step["signer"]]
            delta = _deactivate_params_delta(current_update_keys)
            ts = step.get("timestamp")
            state = state.create_next(None, params_update=delta, timestamp=ts)
            state.sign(signer, timestamp=ts)
            log_entries.append(state.history_line())

        elif op == "resolve":
            assert state is not None
            resolve_results.append({"filename": step["expect"], "versionNumber": step.get("versionNumber")})

    return log_entries, witness_proofs, resolve_results


# ---------------------------------------------------------------------------
# Test collection
# ---------------------------------------------------------------------------

def _collect_scenarios() -> list[str]:
    return sorted(
        vdir.name
        for vdir in VECTORS_ROOT.iterdir()
        if vdir.is_dir() and (vdir / "script.yaml").exists()
    )


def _log_has_empty_next_key_hashes(log_path: Path) -> bool:
    """Same check as test_vectors.py — see that file for full rationale."""
    lines = log_path.read_text().splitlines()
    if len(lines) < 2:
        return False
    for line in lines:
        if json.loads(line).get("parameters", {}).get("nextKeyHashes") == []:
            return True
    return False


# ---------------------------------------------------------------------------
# Parametrised test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", _collect_scenarios())
def test_generate(scenario: str) -> None:
    vector_dir = VECTORS_ROOT / scenario
    script = yaml.safe_load((vector_dir / "script.yaml").read_text())

    committed_log_path = vector_dir / TS_IMPL / "did.jsonl"

    if _log_has_empty_next_key_hashes(committed_log_path):
        pytest.xfail(
            "TS COMPAT: TS generator writes nextKeyHashes: [] for non-pre-rotation "
            "entries; Python DocumentState.create_next() calls self.next_key_hashes "
            "on the previous state and raises on []. Same root cause as test_vectors.py."
        )

    # --- Execute script ---
    try:
        log_entries, witness_proofs, resolve_steps = _run_script(script)
    except Exception as exc:
        pytest.fail(f"Script execution failed: {exc}")

    committed_lines = committed_log_path.read_text().splitlines()

    # --- 1. Compare log entries line-by-line ---
    assert len(log_entries) == len(committed_lines), (
        f"Log length mismatch: generated {len(log_entries)}, committed {len(committed_lines)}"
    )
    for i, (generated, committed_raw) in enumerate(zip(log_entries, committed_lines)):
        committed = json.loads(committed_raw)
        assert generated == committed, f"Log entry {i + 1} mismatch"

    # --- 2. Compare witness proofs ---
    committed_witness_path = vector_dir / TS_IMPL / "did-witness.json"
    if committed_witness_path.exists():
        committed_witness = json.loads(committed_witness_path.read_text())
        assert witness_proofs == committed_witness, "did-witness.json mismatch"
    else:
        assert witness_proofs == [], "Unexpected witness proofs generated"

    # --- 3. Resolve steps: write to temp dir, resolve, compare ---
    if not resolve_steps:
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        log_text = "\n".join(json.dumps(e) for e in log_entries) + "\n"
        (tmp_path / "did.jsonl").write_text(log_text)
        if witness_proofs:
            (tmp_path / "did-witness.json").write_text(json.dumps(witness_proofs, indent=2))

        did = log_entries[0]["state"]["id"]

        for rs in resolve_steps:
            expected_path = vector_dir / TS_IMPL / rs["filename"]
            expected = json.loads(expected_path.read_text())

            kwargs = {"version_number": rs["versionNumber"]} if rs["versionNumber"] is not None else {}
            result = asyncio.run(resolve_did(did, local_history=tmp_path / "did.jsonl", **kwargs))
            actual = result.serialize()

            _normalize_top_level_context(actual)
            _normalize_service_ids(actual.get("didDocument"))
            _normalize_service_endpoints(actual.get("didDocument"))
            _normalize_resolution_metadata(actual, expected)
            _normalize_document_metadata(actual, expected)

            assert actual == expected, f"Resolution mismatch for {rs['filename']}"
