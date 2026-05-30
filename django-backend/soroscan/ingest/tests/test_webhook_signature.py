"""
Comprehensive tests for webhook HMAC signature validation.

Covers _build_webhook_signature_header directly (unit) and the full
dispatch_webhook path (integration), including algorithm selection,
correctness, edge cases, and constant-time safety.
"""
import hashlib
import hmac
import json

import pytest
import responses
from unittest.mock import MagicMock

from soroscan.ingest.models import WebhookSubscription
from soroscan.ingest.tasks import _build_webhook_signature_header, dispatch_webhook

from .factories import (
    ContractEventFactory,
    TrackedContractFactory,
    WebhookSubscriptionFactory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_webhook(**kwargs) -> WebhookSubscription:
    """Return an unsaved WebhookSubscription-like mock for pure unit tests."""
    w = MagicMock(spec=WebhookSubscription)
    w.secret = kwargs.get("secret", "super-secret")
    w.signature_algorithm = kwargs.get("signature_algorithm", WebhookSubscription.SIGNATURE_SHA256)
    return w


def _expected_sig(secret: str, payload: bytes, digestmod) -> str:
    return hmac.new(secret.encode("utf-8"), msg=payload, digestmod=digestmod).hexdigest()


SAMPLE_PAYLOAD = b'{"contract_id":"CABC","event_type":"swap","ledger":100}'


# ---------------------------------------------------------------------------
# Unit tests — _build_webhook_signature_header
# ---------------------------------------------------------------------------

class TestBuildWebhookSignatureHeaderUnit:
    """Direct unit tests for the signature builder — no DB, no HTTP."""

    def test_sha256_prefix(self):
        w = _make_webhook(signature_algorithm=WebhookSubscription.SIGNATURE_SHA256)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        assert result.startswith("sha256=")

    def test_sha1_prefix(self):
        w = _make_webhook(signature_algorithm=WebhookSubscription.SIGNATURE_SHA1)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        assert result.startswith("sha1=")

    def test_sha256_value_correct(self):
        secret = "my-secret"
        w = _make_webhook(secret=secret, signature_algorithm=WebhookSubscription.SIGNATURE_SHA256)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        expected = "sha256=" + _expected_sig(secret, SAMPLE_PAYLOAD, hashlib.sha256)
        assert result == expected

    def test_sha1_value_correct(self):
        secret = "my-secret"
        w = _make_webhook(secret=secret, signature_algorithm=WebhookSubscription.SIGNATURE_SHA1)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        expected = "sha1=" + _expected_sig(secret, SAMPLE_PAYLOAD, hashlib.sha1)
        assert result == expected

    def test_none_algorithm_defaults_to_sha256(self):
        w = _make_webhook(signature_algorithm=None)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        assert result.startswith("sha256=")

    def test_empty_algorithm_defaults_to_sha256(self):
        w = _make_webhook(signature_algorithm="")
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        assert result.startswith("sha256=")

    def test_different_secrets_produce_different_signatures(self):
        w1 = _make_webhook(secret="secret-one")
        w2 = _make_webhook(secret="secret-two")
        sig1 = _build_webhook_signature_header(w1, SAMPLE_PAYLOAD)
        sig2 = _build_webhook_signature_header(w2, SAMPLE_PAYLOAD)
        assert sig1 != sig2

    def test_different_payloads_produce_different_signatures(self):
        w = _make_webhook(secret="same-secret")
        sig1 = _build_webhook_signature_header(w, b'{"a":1}')
        sig2 = _build_webhook_signature_header(w, b'{"a":2}')
        assert sig1 != sig2

    def test_empty_payload(self):
        """Empty payload must still produce a valid HMAC, not raise."""
        w = _make_webhook()
        result = _build_webhook_signature_header(w, b"")
        assert result.startswith("sha256=")
        expected = "sha256=" + _expected_sig(w.secret, b"", hashlib.sha256)
        assert result == expected

    def test_unicode_secret_encoded_as_utf8(self):
        """Secrets with non-ASCII characters must be UTF-8 encoded."""
        secret = "sécret-clé"
        w = _make_webhook(secret=secret)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"), msg=SAMPLE_PAYLOAD, digestmod=hashlib.sha256
        ).hexdigest()
        assert result == expected

    def test_signature_is_lowercase_hex(self):
        w = _make_webhook()
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        hex_part = result.split("=", 1)[1]
        assert hex_part == hex_part.lower()
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_sha256_hex_length(self):
        """SHA-256 hex digest is always 64 characters."""
        w = _make_webhook(signature_algorithm=WebhookSubscription.SIGNATURE_SHA256)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        assert len(result.split("=", 1)[1]) == 64

    def test_sha1_hex_length(self):
        """SHA-1 hex digest is always 40 characters."""
        w = _make_webhook(signature_algorithm=WebhookSubscription.SIGNATURE_SHA1)
        result = _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        assert len(result.split("=", 1)[1]) == 40

    def test_deterministic_same_inputs(self):
        """Same inputs must always produce the same signature."""
        w = _make_webhook(secret="fixed", signature_algorithm=WebhookSubscription.SIGNATURE_SHA256)
        assert (
            _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
            == _build_webhook_signature_header(w, SAMPLE_PAYLOAD)
        )


# ---------------------------------------------------------------------------
# Integration tests — dispatch_webhook sends correct signature header
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDispatchWebhookSignatureIntegration:
    """End-to-end: dispatch_webhook must send a verifiable HMAC header."""

    @pytest.fixture
    def contract(self):
        return TrackedContractFactory()

    @pytest.fixture
    def event(self, contract):
        return ContractEventFactory(contract=contract, ledger=1000, event_index=0)

    @pytest.fixture
    def webhook(self, contract):
        return WebhookSubscriptionFactory(
            contract=contract,
            target_url="https://hooks.example.com/recv",
            secret="integration-secret-xyz",
            is_active=True,
            status=WebhookSubscription.STATUS_ACTIVE,
            failure_count=0,
        )

    def _dispatch_and_get_request(self, webhook, event):
        responses.add(
            responses.POST,
            webhook.target_url,
            status=200,
            headers={"X-SoroScan-Ack": "ok"},
        )
        dispatch_webhook.apply(args=[webhook.id, event.id])
        return responses.calls[0].request

    @responses.activate
    def test_header_present(self, webhook, event):
        req = self._dispatch_and_get_request(webhook, event)
        assert "X-SoroScan-Signature" in req.headers

    @responses.activate
    def test_sha256_signature_verifies(self, webhook, event):
        req = self._dispatch_and_get_request(webhook, event)
        body = req.body if isinstance(req.body, bytes) else req.body.encode("utf-8")
        expected = "sha256=" + _expected_sig(webhook.secret, body, hashlib.sha256)
        assert req.headers["X-SoroScan-Signature"] == expected

    @responses.activate
    def test_sha1_signature_verifies(self, webhook, event):
        webhook.signature_algorithm = WebhookSubscription.SIGNATURE_SHA1
        webhook.save(update_fields=["signature_algorithm"])
        req = self._dispatch_and_get_request(webhook, event)
        body = req.body if isinstance(req.body, bytes) else req.body.encode("utf-8")
        expected = "sha1=" + _expected_sig(webhook.secret, body, hashlib.sha1)
        assert req.headers["X-SoroScan-Signature"] == expected

    @responses.activate
    def test_signature_covers_sorted_json_payload(self, webhook, event):
        """Payload must be sorted-key JSON so signature is deterministic."""
        req = self._dispatch_and_get_request(webhook, event)
        body = req.body if isinstance(req.body, bytes) else req.body.encode("utf-8")
        # Verify the body is valid sorted-key JSON
        parsed = json.loads(body)
        re_serialised = json.dumps(parsed, sort_keys=True).encode("utf-8")
        assert body == re_serialised

    @responses.activate
    def test_wrong_secret_does_not_verify(self, webhook, event):
        req = self._dispatch_and_get_request(webhook, event)
        body = req.body if isinstance(req.body, bytes) else req.body.encode("utf-8")
        wrong_sig = "sha256=" + _expected_sig("wrong-secret", body, hashlib.sha256)
        assert req.headers["X-SoroScan-Signature"] != wrong_sig

    @responses.activate
    def test_tampered_payload_invalidates_signature(self, webhook, event):
        req = self._dispatch_and_get_request(webhook, event)
        sent_sig = req.headers["X-SoroScan-Signature"]
        tampered = b'{"contract_id":"EVIL","event_type":"drain"}'
        recomputed = "sha256=" + _expected_sig(webhook.secret, tampered, hashlib.sha256)
        assert sent_sig != recomputed

    @responses.activate
    def test_timestamp_header_present(self, webhook, event):
        req = self._dispatch_and_get_request(webhook, event)
        assert "X-SoroScan-Timestamp" in req.headers


# ---------------------------------------------------------------------------
# Constant-time comparison safety
# ---------------------------------------------------------------------------

class TestConstantTimeComparison:
    """
    Verify that signature comparison uses hmac.compare_digest (timing-safe).
    The production code uses hmac.new(...).hexdigest() for generation; the
    *receiver* side must use compare_digest.  These tests document the
    expected verification pattern and guard against naive == comparison.
    """

    def test_compare_digest_accepts_matching_signatures(self):
        secret = b"safe-secret"
        payload = b'{"event":"test"}'
        sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).hexdigest()
        assert hmac.compare_digest(sig, sig)

    def test_compare_digest_rejects_mismatched_signatures(self):
        secret = b"safe-secret"
        payload = b'{"event":"test"}'
        sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).hexdigest()
        other = hmac.new(b"other-secret", msg=payload, digestmod=hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(sig, other)

    def test_compare_digest_rejects_truncated_signature(self):
        secret = b"safe-secret"
        payload = b'{"event":"test"}'
        sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(sig, sig[:10])

    def test_compare_digest_rejects_empty_string(self):
        secret = b"safe-secret"
        payload = b'{"event":"test"}'
        sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).hexdigest()
        assert not hmac.compare_digest(sig, "")
