from fastapi.testclient import TestClient
import main

client = TestClient(main.app)


def test_standard_login_policy():
    response = client.get("/api/policy/STANDARD_LOGIN")

    assert response.status_code == 200
    assert response.json() == {
        "tier": "low",
        "requires_totp_step_up": False,
    }


def test_vault_transfer_requires_totp():
    response = client.get("/api/policy/VAULT_TRANSFER")

    assert response.status_code == 200
    assert response.json() == {
        "tier": "critical",
        "requires_totp_step_up": True,
    }


def test_unknown_action_is_rejected():
    response = client.get("/api/policy/FAKE_ACTION")

    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown or unauthorized action type."


def test_vault_transfer_without_totp_is_rejected(monkeypatch):
    from types import SimpleNamespace
    import time

    username = "test-user"
    meta = {}
    user = {
        "public_key": b"test-public-key",
        "sign_count": 0,
        "totp_secret": "TESTSECRET",
    }

    challenge = {
        "challenge": "test-challenge",
        "issued_at": time.time(),
        "action_hash": main.context_hash("VAULT_TRANSFER", meta),
        "rp_id": "testserver",
    }

    monkeypatch.setitem(main.DB_USERS, username, user)
    monkeypatch.setitem(main.DB_AUTH_CHALLENGES, username, challenge)

    monkeypatch.setattr(
        main.webauthn,
        "verify_authentication_response",
        lambda **kwargs: SimpleNamespace(new_sign_count=1),
    )

    receipts_before = len(main.DB_RECEIPTS)

    response = client.post(
        f"/api/passkey/action-verify/{username}",
        json={
            "id": "test-credential",
            "type": "public-key",
            "rawId": "dGVzdA",
            "response": {"signature": "test-signature"},
            "action_context": {
                "action_type": "VAULT_TRANSFER",
                "meta": meta,
            },
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "This action requires a TOTP step-up code."
    )
    assert len(main.DB_RECEIPTS) == receipts_before


import pytest


def test_missing_challenge_is_rejected():
    store = {}

    with pytest.raises(main.HTTPException) as error:
        main.pop_valid_challenge(store, "missing-user")

    assert error.value.status_code == 400


def test_expired_challenge_is_rejected_and_removed():
    store = {
        "test-user": {
            "challenge": "expired-challenge",
            "issued_at": main.time.time() - main.CHALLENGE_TTL_SECONDS - 1,
        }
    }

    with pytest.raises(main.HTTPException) as error:
        main.pop_valid_challenge(store, "test-user")

    assert error.value.status_code == 400
    assert "test-user" not in store


def test_vault_transfer_with_invalid_totp_is_rejected(monkeypatch):
    from types import SimpleNamespace
    import time

    username = "invalid-totp-user"
    meta = {}
    user = {
        "public_key": b"test-public-key",
        "sign_count": 0,
        "totp_secret": "JBSWY3DPEHPK3PXP",
    }

    challenge = {
        "challenge": "test-challenge",
        "issued_at": time.time(),
        "action_hash": main.context_hash("VAULT_TRANSFER", meta),
        "rp_id": "testserver",
    }

    monkeypatch.setitem(main.DB_USERS, username, user)
    monkeypatch.setitem(main.DB_AUTH_CHALLENGES, username, challenge)

    monkeypatch.setattr(
        main.webauthn,
        "verify_authentication_response",
        lambda **kwargs: SimpleNamespace(new_sign_count=1),
    )

    receipts_before = len(main.DB_RECEIPTS)

    response = client.post(
        f"/api/passkey/action-verify/{username}",
        json={
            "id": "test-credential",
            "type": "public-key",
            "rawId": "dGVzdA",
            "response": {"signature": "test-signature"},
            "action_context": {
                "action_type": "VAULT_TRANSFER",
                "meta": meta,
            },
            "totp_code": "000000",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid TOTP step-up code."
    assert len(main.DB_RECEIPTS) == receipts_before
