# flake8: noqa

import json
from pathlib import Path

import pytest

from did_webvh.resolver import resolve

with open(Path(__file__).parent.joinpath("test-suite/resolver-suite.json")) as testfile:
    TESTS = json.load(testfile)


@pytest.mark.parametrize("run", TESTS)
async def test_resolver_suite(run: dict):
    result = await resolve(
        run["did_url"],
        local_history=Path(__file__).parent.joinpath("test-suite/logs", run["log"]),
    )
    if run["status"] == "ok":
        assert result["didDocument"], "Resolution failed unexpectedly: " + str(result)
    elif run["status"] == "error":
        assert not result["didDocument"], "Resolution succeeded unexpectedly"

    if "didDocumentMetadata" in run:
        metadata = result.get("didDocumentMetadata") or {}
        if not all(
            metadata.get(e) == run["didDocumentMetadata"][e]
            for e in run["didDocumentMetadata"]
        ):
            raise AssertionError(
                "Document metadata mismatch", metadata, run["didDocumentMetadata"]
            )

    if "didResolverMetadata" in run:
        metadata = result.get("didResolverMetadata") or {}
        if not all(
            metadata.get(e) == run["didResolverMetadata"][e]
            for e in run["didResolverMetadata"]
        ):
            raise AssertionError(
                "Resolver metadata mismatch", metadata, run["didResolverMetadata"]
            )
