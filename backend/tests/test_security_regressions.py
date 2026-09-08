import hashlib
import hmac
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient
from passlib.hash import bcrypt
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.security import hash_password, verify_password
from app.models import ProcessedEvent, Tenant
from tests.conftest import auth_header, register


def test_unconfigured_webhook_cannot_be_forged_with_empty_secret(
    client: TestClient, db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    register(client, "owner@acme.example", "Acme")
    tenant = db_session.query(Tenant).one()
    monkeypatch.setattr(get_settings(), "stripe_webhook_secret", "")
    payload = json.dumps({
        "id": "evt_forged",
        "object": "event",
        "type": "checkout.session.completed",
        "data": {"object": {"metadata": {"tenant_id": str(tenant.id)}}},
    }).encode()
    timestamp = int(time.time())
    signature = hmac.new(b"", f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()
    response = client.post(
        "/billing/webhook", content=payload,
        headers={"stripe-signature": f"t={timestamp},v1={signature}"},
    )
    assert response.status_code == 400
    db_session.refresh(tenant)
    assert tenant.subscription_status == "inactive"
    assert db_session.query(ProcessedEvent).count() == 0


@pytest.mark.parametrize("prefix", ["a" * 72, "\u00e9" * 36])
def test_password_suffix_after_72_bytes_changes_authentication(prefix: str) -> None:
    hashed = hash_password(prefix + "correct")
    assert verify_password(prefix + "correct", hashed)
    assert not verify_password(prefix + "wrong", hashed)


def test_existing_bcrypt_password_still_authenticates() -> None:
    hashed = bcrypt.hash("existing-password")
    assert verify_password("existing-password", hashed)
    assert not verify_password("wrong-password", hashed)


def test_legacy_bcrypt_rejects_ambiguous_truncated_password() -> None:
    hashed = bcrypt.hash("a" * 72)
    assert not verify_password("a" * 72 + "unknown-suffix", hashed)


def test_missing_signing_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize("secret", ["", "change-me-in-production", "dev-secret-change-me"])
def test_insecure_signing_key_is_rejected(secret: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret=secret)


@pytest.mark.parametrize("subject", ["not-an-id", "1.5", "9" * 100])
def test_malformed_signed_subject_returns_unauthorized(
    subject: str, client: TestClient
) -> None:
    settings = get_settings()
    token = jwt.encode(
        {"sub": subject, "tenant_id": 1, "iat": int(time.time()), "exp": int(time.time()) + 60},
        settings.jwt_secret, algorithm=settings.jwt_algorithm,
    )
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401


def test_token_without_expiration_is_rejected(client: TestClient) -> None:
    valid = register(client, "owner@acme.example", "Acme")
    settings = get_settings()
    payload = jwt.decode(valid, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    del payload["exp"]
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401


@pytest.mark.parametrize(
    ("claim", "value"),
    [("exp", []), ("exp", {}), ("exp", float("inf")), ("iat", []), ("iat", {})],
)
def test_malformed_time_claim_returns_unauthorized(
    claim: str, value: object, client: TestClient
) -> None:
    settings = get_settings()
    payload = {"sub": "1", "tenant_id": 1, "iat": int(time.time()), "exp": int(time.time()) + 60}
    payload[claim] = value
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    assert client.get("/auth/me", headers=auth_header(token)).status_code == 401
