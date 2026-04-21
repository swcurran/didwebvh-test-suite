# flake8: noqa

import json
from datetime import datetime
from pathlib import Path
from unittest import mock

import base58

from did_webvh.askar import AskarSigningKey
from did_webvh.const import (
    HISTORY_FILENAME,
    METHOD_NAME,
    SCID_PLACEHOLDER,
    WITNESS_FILENAME,
)
from did_webvh.core.date_utils import iso_format_datetime
from did_webvh.core.proof import di_jcs_sign
from did_webvh.core.state import DocumentState
from did_webvh.provision import METHOD_NAME, genesis_document

EXAMPLE_IDENT = "domain.example"

KEYS = [
    {
        "alg": "ed25519",
        "sk": "DDtEn8PX1CXK3rETTkNt4KmdcdwDPZkEFMFmSyDTyJ7S",
        "pk": "CbqtQaXMJXkqLjAkzrL1ffFcG9sUB8dYfXz2vMxfSgDh",
    },
    {
        "alg": "ed25519",
        "sk": "ERuzbBZUJ7gnrJxVA6DSRiHt9e8YLKpmPcsKrVD6eT9W",
        "pk": "EmwaDJK5XZGHCv6iuyDgZ9CEfGzRQ7f2gppkuZFCFaH1",
    },
    {
        "alg": "ed25519",
        "sk": "AN3KbF5NxtoVB8gtNvjQzCEhz56RQJ9vbciCwQYLniWo",
        "pk": "4XCzteuPQJNw9YcfyfhNwQydwbBtndV9ndRbQeVnC2Xc",
    },
    {
        "alg": "ed25519",
        "sk": "91HjGTqyeBmyUNh9GdRWysjdwrDygSuNKTVCEih8yygw",
        "pk": "FNDV7FdYMhJn87SybTnmorK2kkAq2rBWCrkyxV24D5jP",
    },
    {
        "alg": "ed25519",
        "sk": "AjBmGtPnfy3oqvytWZzkdz8pXzAKrKa1e7XvgcDJqYG",
        "pk": "AkFQo4nWShNGQeBW6v7KD5CxNeEpFmYQrejWuqGZ3L54",
    },
    {
        "alg": "ed25519",
        "sk": "9F2kQNDLBda4hVgYfbDhh6HvCvWjkq6rzNGMDm25mNHj",
        "pk": "3LN2v9WSqXWqKSVqtvxxZEVtVDWPMvaKYMA24uEN5dAm",
    },
    {
        "alg": "ed25519",
        "sk": "HXvUzTBTEKMpTC2PsoLgJ5qg6Rdm7U1hvh2t4zphHgv5",
        "pk": "49rSxjiVpT3unzcHW5dVTvfe5pe6Xc8xvZvLT5Z7UrbS",
    },
    {
        "alg": "ed25519",
        "sk": "DxoRwzzur2TcUqE56Dsrmc6tdavQ4LAntUxy6CK2JN3r",
        "pk": "3fZGjDQa8LLnNXW1G6kDkR3Df9jrxAydz3apo3cqyAXY",
    },
    {
        "alg": "ed25519",
        "sk": "9XagU3PJpfSEHqVYookADqjZsgYDgs4T7u3gTSXPECc6",
        "pk": "FCJgKswfpVfZqopZeVkbK2EdiETup5YepeJF6nygDDhr",
    },
    {
        "alg": "ed25519",
        "sk": "DRRreq9ynWQKUg8cHUoBayQQBPwTiT6pSDbbLSieqMZg",
        "pk": "C22BEBns8F7DNHPJobBD4tKd85tweYyTE7GfgLZCqfxu",
    },
]

START_TIME = datetime.fromisoformat("2000-01-01T12:01:00")


def _load_key(index: int) -> AskarSigningKey:
    return AskarSigningKey.from_secret_bytes(
        KEYS[index]["alg"], base58.b58decode(KEYS[index]["sk"])
    )


def _json_pretty(val) -> str:
    return json.dumps(val, indent=2)


def _witness_proof(version_id: str, sk) -> dict:
    res = {"versionId": version_id}
    res["proof"] = [di_jcs_sign(res, sk)]
    return res


def _write_log(ident: str, log: list[str], witness: str | None = None):
    dir = Path("./test-suite/logs").joinpath(ident)
    dir.mkdir(parents=True, exist_ok=True)
    path = dir.joinpath(HISTORY_FILENAME)
    with path.open("w") as out:
        for line in log:
            out.write(line + "\n")
    if witness:
        wpath = dir.joinpath(WITNESS_FILENAME)
        with wpath.open("w") as out:
            out.write(witness)


def write_short_log(log_id: str) -> tuple[str, list[str]]:
    """Generate a valid log file with 2 transactions, including witnesses."""
    sk = _load_key(0)
    wit_key = _load_key(1)
    placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{EXAMPLE_IDENT}"
    gen_doc = genesis_document(placeholder_id)
    state1 = DocumentState.initial(
        params={
            "updateKeys": [str(sk.multikey)],
            "witness": {
                "threshold": 1,
                "witnesses": [{"id": "did:key:" + str(wit_key.multikey)}],
            },
        },
        document=gen_doc,
        timestamp=START_TIME,
    )
    doc_id = state1.document_id
    state1.sign(sk)
    doc = state1.document_copy()
    doc["alsoKnownAs"] = [f"did:web:{EXAMPLE_IDENT}"]
    state2 = state1.create_next(document=doc, timestamp=START_TIME.replace(minute=2))
    state2.sign(sk)
    witness = _json_pretty(
        [
            _witness_proof(state1.version_id, wit_key),
            _witness_proof(state2.version_id, wit_key),
        ]
    )
    _write_log(log_id, [state1.history_json(), state2.history_json()], witness)
    return doc_id, [state1.version_id, state2.version_id]


def write_missing_proof_log(log_id: str) -> tuple[str, list[str]]:
    """Generate an invalid log file with 3 transactions.

    The proof for the 3rd transaction is skipped.
    """
    sk = _load_key(0)
    placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{EXAMPLE_IDENT}"
    gen_doc = genesis_document(placeholder_id)
    state1 = DocumentState.initial(
        params={"updateKeys": [str(sk.multikey)]},
        document=gen_doc,
        timestamp=START_TIME,
    )
    doc_id = state1.document_id
    state1.sign(sk)
    doc = state1.document_copy()
    doc["alsoKnownAs"] = [f"did:web:{EXAMPLE_IDENT}"]
    state2 = state1.create_next(document=doc, timestamp=START_TIME.replace(minute=2))
    state2.sign(sk)
    del doc["alsoKnownAs"]
    state3 = state2.create_next(document=doc, timestamp=START_TIME.replace(minute=3))
    # state 3 is not signed
    _write_log(
        log_id, [state1.history_json(), state2.history_json(), state3.history_json()]
    )
    return doc_id, [state1.version_id, state2.version_id, state3.version_id]


def write_invalid_method_log(log_id: str) -> tuple[str, list[str]]:
    """Generate an invalid log with 1 transaction having an invalid `method` parameter."""
    sk = _load_key(0)
    placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{EXAMPLE_IDENT}"
    gen_doc = genesis_document(placeholder_id)
    state = DocumentState.initial(
        params={"method": "invalid-method", "updateKeys": [str(sk.multikey)]},
        document=gen_doc,
        timestamp=START_TIME,
    )
    doc_id = state.document_id
    state.sign(sk)
    _write_log(log_id, [state.history_json()])
    return doc_id, [state.version_id]


def write_invalid_scid_log(log_id: str) -> tuple[str, list[str]]:
    """Generate an invalid log with 1 transaction having an invalid `scid` parameter."""
    sk = _load_key(0)
    placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{EXAMPLE_IDENT}"
    gen_doc = genesis_document(placeholder_id)
    with mock.patch.object(DocumentState, "_check_scid_derivation"):
        state = DocumentState.initial(
            params={"scid": "invalid-scid", "updateKeys": [str(sk.multikey)]},
            document=gen_doc,
            timestamp=START_TIME,
        )
    doc_id = state.document_id
    state.sign(sk)
    _write_log(log_id, [state.history_json()])
    return doc_id, [state.version_id]


def write_invalid_json_log(log_id: str) -> tuple[str, list[str]]:
    """Generate an invalid log with 3 valid transactions followed by invalid JSON."""
    sk = _load_key(0)
    placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{EXAMPLE_IDENT}"
    gen_doc = genesis_document(placeholder_id)
    state1 = DocumentState.initial(
        params={"updateKeys": [str(sk.multikey)]},
        document=gen_doc,
        timestamp=START_TIME,
    )
    doc_id = state1.document_id
    state1.sign(sk)
    doc = state1.document_copy()
    doc["alsoKnownAs"] = [f"did:web:{EXAMPLE_IDENT}"]
    state2 = state1.create_next(document=doc, timestamp=START_TIME.replace(minute=2))
    state2.sign(sk)
    _write_log(
        log_id, [state1.history_json(), state2.history_json(), '{"versionId:":"3-"']
    )
    return doc_id, [state1.version_id, state2.version_id]


def write_missing_witness_log(log_id: str) -> tuple[str, list[str]]:
    """Generate an invalid log, missing witness proofs for the 3rd transction."""
    sk = _load_key(0)
    wit_key = _load_key(1)
    placeholder_id = f"did:{METHOD_NAME}:{SCID_PLACEHOLDER}:{EXAMPLE_IDENT}"
    gen_doc = genesis_document(placeholder_id)
    state1 = DocumentState.initial(
        params={
            "updateKeys": [str(sk.multikey)],
            "witness": {
                "threshold": 1,
                "witnesses": [{"id": "did:key:" + str(wit_key.multikey)}],
            },
        },
        document=gen_doc,
        timestamp=START_TIME,
    )
    doc_id = state1.document_id
    state1.sign(sk)
    doc = state1.document_copy()
    doc["alsoKnownAs"] = [f"did:web:{EXAMPLE_IDENT}"]
    state2 = state1.create_next(document=doc, timestamp=START_TIME.replace(minute=2))
    state2.sign(sk)
    del doc["alsoKnownAs"]
    state3 = state2.create_next(document=doc, timestamp=START_TIME.replace(minute=3))
    state3.sign(sk)
    witness = _json_pretty([_witness_proof(state2.version_id, wit_key)])
    _write_log(
        log_id,
        [state1.history_json(), state2.history_json(), state3.history_json()],
        witness,
    )
    return doc_id, [state1.version_id, state2.version_id, state3.version_id]


# def generate_keys():
#     keys = []
#     for _ in range(10):
#         k = AskarSigningKey.generate("ed25519")
#         sk = base58.b58encode(k.key.get_secret_bytes()).decode("ascii")
#         pk = base58.b58encode(k.key.get_public_bytes()).decode("ascii")
#         keys.append({"alg": k.algorithm, "sk": sk, "pk": pk})

#     print(keys)


def write_tests():
    tests = []
    short_did, short_vids = write_short_log("short")

    tests.extend(
        [
            {
                "log": "short",
                "did_url": short_did,
                "status": "ok",
                "didDocumentMetadata": {
                    "created": iso_format_datetime(START_TIME),
                    "updated": iso_format_datetime(START_TIME.replace(minute=2)),
                    "versionId": short_vids[1],
                    "versionNumber": 2,
                    "versionTime": iso_format_datetime(START_TIME.replace(minute=2)),
                },
            },
            {
                "log": "short",
                "did_url": short_did + "?versionId=" + short_vids[0],
                "status": "ok",
                "didDocumentMetadata": {
                    "created": iso_format_datetime(START_TIME),
                    "updated": iso_format_datetime(START_TIME.replace(minute=2)),
                    "versionId": short_vids[0],
                    "versionNumber": 1,
                    "versionTime": iso_format_datetime(START_TIME),
                },
            },
            {
                "log": "short",
                "did_url": short_did + "?versionNumber=1",
                "status": "ok",
                "didDocumentMetadata": {
                    "created": iso_format_datetime(START_TIME),
                    "updated": iso_format_datetime(START_TIME.replace(minute=2)),
                    "versionId": short_vids[0],
                    "versionNumber": 1,
                    "versionTime": iso_format_datetime(START_TIME),
                },
            },
            {
                "log": "short",
                "did_url": short_did + "?versionNumber=0",
                "status": "error",
                "didResolutionMetadata": {"error": "notFound"},
            },
            {
                "log": "short",
                "did_url": short_did + "?versionId=1-invalid",
                "status": "error",
                "didResolutionMetadata": {"error": "notFound"},
            },
            {
                "log": "short",
                "did_url": short_did + "?versionNumber=1&versionId=" + short_vids[1],
                "status": "error",
                "didResolutionMetadata": {"error": "notFound"},
            },
        ]
    )

    missing_proof_did, missing_proof_vids = write_missing_proof_log("missing-proof")

    tests.extend(
        [
            {
                "log": "missing-proof",
                "did_url": missing_proof_did,
                "status": "error",
                "didResolutionMetadata": {"error": "invalidDid"},
            },
            {
                "log": "missing-proof",
                "did_url": missing_proof_did + "?versionId=" + missing_proof_vids[0],
                "status": "ok",
                "didDocumentMetadata": {
                    "versionId": missing_proof_vids[0],
                    "versionNumber": 1,
                    "versionTime": iso_format_datetime(START_TIME),
                },
                # FIXME check metadata indicates failure in resolving latest version
            },
            {
                "log": "missing-proof",
                "did_url": missing_proof_did + "?versionId=" + missing_proof_vids[1],
                "status": "ok",
                "didDocumentMetadata": {
                    "versionId": missing_proof_vids[1],
                    "versionNumber": 2,
                },
            },
            {
                "log": "missing-proof",
                "did_url": missing_proof_did + "?versionId=" + missing_proof_vids[2],
                "status": "error",
                "didResolutionMetadata": {"error": "invalidDid"},
            },
        ]
    )

    invalid_method_did, _invalid_method_vids = write_invalid_scid_log("invalid-method")

    tests.extend(
        [
            {
                "log": "invalid-method",
                "did_url": invalid_method_did,
                "status": "error",
                "didResolutionMetadata": {"error": "invalidDid"},
            },
            {
                "log": "invalid-method",
                "did_url": invalid_method_did + "?versionNumber=1",
                "status": "error",
                "didResolutionMetadata": {"error": "invalidDid"},
            },
        ]
    )

    invalid_scid_did, _invalid_scid_vids = write_invalid_scid_log("invalid-scid")

    tests.extend(
        [
            {
                "log": "invalid-scid",
                "did_url": invalid_scid_did,
                "status": "error",
                "didResolutionMetadata": {"error": "invalidDid"},
            },
            {
                "log": "invalid-scid",
                "did_url": invalid_scid_did + "?versionNumber=1",
                "status": "error",
                "didResolutionMetadata": {"error": "invalidDid"},
            },
        ]
    )

    invalid_json_did, invalid_json_vids = write_invalid_json_log("invalid-json")

    tests.extend(
        [
            {
                "log": "invalid-json",
                "did_url": invalid_json_did,
                "status": "error",
                "didResolutionMetadata": {
                    "error": "invalidDid",
                },
            },
            {
                "log": "invalid-json",
                "did_url": invalid_json_did + "?versionId=" + invalid_json_vids[0],
                "status": "ok",
                "didDocumentMetadata": {
                    "created": iso_format_datetime(START_TIME),
                    "updated": iso_format_datetime(START_TIME.replace(minute=2)),
                    "versionId": invalid_json_vids[0],
                    "versionNumber": 1,
                    "versionTime": iso_format_datetime(START_TIME),
                },
            },
            {
                "log": "invalid-json",
                "did_url": invalid_json_did + "?versionNumber=2",
                "status": "ok",
                "didDocumentMetadata": {
                    "created": iso_format_datetime(START_TIME),
                    "updated": iso_format_datetime(START_TIME.replace(minute=2)),
                    "versionId": invalid_json_vids[1],
                    "versionNumber": 2,
                    "versionTime": iso_format_datetime(START_TIME.replace(minute=2)),
                },
            },
            {
                "log": "invalid-json",
                "did_url": invalid_json_did + "?versionNumber=3",
                "status": "error",
                "didResolutionMetadata": {
                    "error": "invalidDid",
                },
            },
        ]
    )

    missing_witness_did, missing_witness_vids = write_missing_witness_log(
        "missing-witness"
    )

    tests.extend(
        [
            {
                "log": "missing-witness",
                "did_url": missing_witness_did,
                "status": "error",
                "didResolutionMetadata": {
                    "error": "invalidDid",
                },
            },
            {
                "log": "missing-witness",
                "did_url": missing_witness_did
                + "?versionId="
                + missing_witness_vids[0],
                "status": "ok",
                "didDocumentMetadata": {
                    "created": iso_format_datetime(START_TIME),
                    "updated": iso_format_datetime(START_TIME.replace(minute=3)),
                    "versionId": missing_witness_vids[0],
                    "versionNumber": 1,
                    "versionTime": iso_format_datetime(START_TIME),
                },
            },
            {
                "log": "missing-witness",
                "did_url": missing_witness_did + "?versionNumber=2",
                "status": "ok",
                "didDocumentMetadata": {
                    "created": iso_format_datetime(START_TIME),
                    "updated": iso_format_datetime(START_TIME.replace(minute=3)),
                    "versionId": missing_witness_vids[1],
                    "versionNumber": 2,
                    "versionTime": iso_format_datetime(START_TIME.replace(minute=2)),
                },
            },
            {
                "log": "missing-witness",
                "did_url": missing_witness_did + "?versionNumber=3",
                "status": "error",
                "didResolutionMetadata": {
                    "error": "invalidDid",
                },
            },
        ]
    )

    with open("test-suite/resolver-suite.json", "w") as out:
        out.write(_json_pretty(tests))


if __name__ == "__main__":
    write_tests()
