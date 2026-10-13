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


def test_fifth_ip_failure_triggers_temporary_ban(monkeypatch):
    import time

    ip = "test-threshold-ip"
    monkeypatch.setitem(
        main.DB_IP_ACTIVITY,
        ip,
        {"failures": 0, "window_start": time.time(), "banned_until": 0},
    )

    for _ in range(main.IP_FAILURE_THRESHOLD):
        main.record_ip_failure(ip)

    entry = main.DB_IP_ACTIVITY[ip]
    assert entry["failures"] == main.IP_FAILURE_THRESHOLD
    assert entry["banned_until"] > time.time()


def test_success_resets_ip_failure_counter(monkeypatch):
    import time

    ip = "test-success-ip"
    monkeypatch.setitem(
        main.DB_IP_ACTIVITY,
        ip,
        {"failures": 3, "window_start": time.time(), "banned_until": 0},
    )

    main.record_ip_success(ip)

    assert main.DB_IP_ACTIVITY[ip]["failures"] == 0


def test_failure_outside_window_starts_new_count(monkeypatch):
    import time

    ip = "test-window-ip"
    old_start = time.time() - main.IP_FAILURE_WINDOW_SECONDS - 1
    monkeypatch.setitem(
        main.DB_IP_ACTIVITY,
        ip,
        {"failures": 4, "window_start": old_start, "banned_until": 0},
    )

    main.record_ip_failure(ip)

    entry = main.DB_IP_ACTIVITY[ip]
    assert entry["failures"] == 1
    assert entry["window_start"] > old_start


def test_banned_ip_is_rejected(monkeypatch):
    import time
    from starlette.requests import Request

    ip = "test-banned-ip"
    monkeypatch.setitem(
        main.DB_IP_ACTIVITY,
        ip,
        {
            "failures": main.IP_FAILURE_THRESHOLD,
            "window_start": time.time(),
            "banned_until": time.time() + 60,
        },
    )

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(b"x-demo-ip", ip.encode())],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    request = Request(scope)

    with pytest.raises(main.HTTPException) as error:
        main.ensure_ip_allowed(request)

    assert error.value.status_code == 403


def test_banned_ip_cannot_request_login_options(monkeypatch):
    import time

    ip = "test-login-banned-ip"
    monkeypatch.setitem(
        main.DB_IP_ACTIVITY,
        ip,
        {
            "failures": main.IP_FAILURE_THRESHOLD,
            "window_start": time.time(),
            "banned_until": time.time() + 60,
        },
    )

    response = client.post(
        "/api/passkey/login-options",
        json={"username": "nonexistent-test-user"},
        headers={"x-demo-ip": ip},
    )

    assert response.status_code == 403
    assert "temporarily banned" in response.json()["detail"]

def test_failed_passkey_verification_increments_ip_failures(monkeypatch):
    import time

    username = "test-failed-passkey-user"
    ip = "test-failed-passkey-ip"

    monkeypatch.setitem(
        main.DB_USERS,
        username,
        {
            "public_key": b"test-public-key",
            "sign_count": 0,
        },
    )

    monkeypatch.setitem(
        main.DB_AUTH_CHALLENGES,
        username,
        {
            "challenge": "test-challenge",
            "issued_at": time.time(),
            "rp_id": "testserver",
        },
    )

    monkeypatch.setitem(
        main.DB_IP_ACTIVITY,
        ip,
        {
            "failures": 0,
            "window_start": time.time(),
            "banned_until": 0,
        },
    )

    def reject_verification(**kwargs):
        raise ValueError("Simulated invalid passkey signature")

    monkeypatch.setattr(
        main.webauthn,
        "verify_authentication_response",
        reject_verification,
    )

    response = client.post(
        f"/api/passkey/login-verify/{username}",
        headers={"x-demo-ip": ip},
        json={"id": "test-credential", "response": {}},
    )

    assert response.status_code == 401
    assert "Signature verification failed" in response.json()["detail"]
    assert main.DB_IP_ACTIVITY[ip]["failures"] == 1

