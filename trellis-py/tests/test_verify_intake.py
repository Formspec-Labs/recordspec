"""Unit tests for WOS intake-handoff verification helpers."""

from __future__ import annotations

import hashlib

import cbor2
import pytest

from trellis_py.verify import VerifyError, _response_hash_matches
from trellis_py.verify_wos import (
    WOS_INTAKE_ACCEPTED_EVENT_TYPE,
    _parse_intake_accepted_record,
)


def test_parse_intake_accepted_rejects_empty_outputs() -> None:
    payload = {
        "event": "wos.kernel.intake_accepted",
        "data": {
            "intakeId": "handoff-1",
            "caseIntent": "requestGovernedCaseCreation",
            "caseDisposition": "createGovernedCase",
            "caseRef": "case-1",
        },
        "outputs": [],
    }
    with pytest.raises(VerifyError, match="outputs array is missing or empty"):
        _parse_intake_accepted_record(
            cbor2.dumps(payload), WOS_INTAKE_ACCEPTED_EVENT_TYPE
        )


def test_response_hash_matches_ok() -> None:
    body = b"hello-response"
    digest = hashlib.sha256(body).digest()
    text = "sha256:" + digest.hex()
    ok, err = _response_hash_matches(text, body)
    assert ok is True
    assert err is None


def test_response_hash_matches_wrong_bytes() -> None:
    ok, err = _response_hash_matches("sha256:" + "00" * 32, b"wrong-bytes")
    assert ok is False
    assert err is None


def test_response_hash_matches_bad_prefix() -> None:
    ok, err = _response_hash_matches("md5:abc", b"x")
    assert ok is False
    assert err is not None
    assert "sha256" in err.lower()
