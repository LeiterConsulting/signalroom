from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from splunk_security_agent import app as app_module
from splunk_security_agent.audit import AuditStore
from splunk_security_agent.auth import AuthService, AuthStore
from splunk_security_agent.auth.service import CSRF_COOKIE, SESSION_COOKIE
from splunk_security_agent.schemas import AuthUserCreate, AuthUserUpdate


def auth_service(tmp_path) -> AuthService:
    return AuthService(
        AuthStore(tmp_path / "auth.db"),
        AuditStore(tmp_path / "audit.db"),
    )


def bootstrap(service: AuthService) -> dict:
    return service.bootstrap(
        username="security-admin",
        display_name="Security Admin",
        password="correct horse battery staple",
        source="127.0.0.1",
    )


def test_rbac_is_optional_and_bootstrap_is_session_safe(tmp_path) -> None:
    service = auth_service(tmp_path)

    local = service.status()
    assert local["enabled"] is False
    assert local["mode"] == "local-single-user"
    assert local["authenticated"] is True
    assert local["principal"]["role"] == "admin"
    assert local["permissions"]["can_use_primary_connection"] is True

    session = bootstrap(service)
    authenticated = service.authenticate(session["token"])
    assert authenticated is not None
    assert authenticated["user"]["role"] == "admin"
    assert service.verify_csrf(authenticated, session["csrf_token"]) is True
    assert service.verify_csrf(authenticated, "wrong-token") is False

    status = service.status(session["token"])
    assert status["enabled"] is True
    assert status["authenticated"] is True
    assert status["session"] == {"expires_at": session["expires_at"]}
    assert "csrf_token" not in status["session"]

    with service.store.connect() as database:
        stored = database.execute("SELECT token_sha256,csrf_sha256 FROM auth_sessions").fetchone()
    assert stored["token_sha256"] == hashlib.sha256(session["token"].encode()).hexdigest()
    assert stored["csrf_sha256"] == hashlib.sha256(session["csrf_token"].encode()).hexdigest()
    assert session["token"] not in tuple(stored)
    assert session["csrf_token"] not in tuple(stored)


def test_roles_and_connection_assignment_are_independent(tmp_path) -> None:
    service = auth_service(tmp_path)
    admin_session = bootstrap(service)
    admin = admin_session["user"]
    viewer = service.create_user(
        AuthUserCreate(
            username="soc-viewer",
            display_name="SOC Viewer",
            role="viewer",
            password="viewer password is long",
            connection_ids=["primary"],
        ),
        actor=admin,
    )
    analyst = service.create_user(
        AuthUserCreate(
            username="offline-analyst",
            display_name="Offline Analyst",
            role="analyst",
            password="analyst password is long",
            connection_ids=[],
        ),
        actor=admin,
    )

    assert service.authorize(viewer, "GET", "/api/cases") == (True, "")
    assert service.authorize(viewer, "POST", "/api/cases")[0] is False
    assert service.authorize(viewer, "POST", "/api/auth/logout") == (True, "")
    assert service.authorize(analyst, "POST", "/api/cases") == (True, "")
    assert service.authorize(analyst, "PUT", "/api/settings")[0] is False
    allowed, reason = service.authorize(analyst, "POST", "/api/discovery/stream")
    assert allowed is False
    assert "Primary Splunk" in reason
    assert service.authorize(analyst, "POST", "/api/discovery/jobs")[0] is False
    assert service.authorize(analyst, "PUT", "/api/model-trust/policy")[0] is False
    assert service.authorize(admin, "PUT", "/api/model-trust/policy") == (
        True,
        "",
    )
    assert (
        service.authorize(
            analyst,
            "POST",
            "/api/model-capabilities/time-series/runtime/start/stream",
        )[0]
        is False
    )
    assert service.authorize(
        admin,
        "POST",
        "/api/model-capabilities/time-series/runtime/start/stream",
    ) == (True, "")
    allowed, reason = service.authorize(
        analyst,
        "POST",
        "/api/model-capabilities/time-series/forecast/stream",
    )
    assert allowed is False
    assert "Primary Splunk" in reason
    assert service.authorize(
        analyst,
        "POST",
        "/api/model-capabilities/time-series/experiments/run-1/baseline",
    ) == (True, "")
    assert service.authorize(
        analyst,
        "POST",
        "/api/model-capabilities/time-series/experiments/run-1/alert-candidates",
    ) == (True, "")
    assert service.authorize(analyst, "PUT", "/api/audit-export/policy")[0] is False
    assert service.authorize(admin, "PUT", "/api/audit-export/policy") == (True, "")
    assert service.authorize(analyst, "POST", "/api/audit-export/run")[0] is False
    assert service.authorize(analyst, "POST", "/api/audit-operations/export")[0] is False
    assert service.authorize(admin, "POST", "/api/audit-operations/export") == (True, "")
    assert service.authorize(admin, "PUT", "/api/settings") == (True, "")


def test_user_changes_revoke_sessions_and_preserve_last_admin(tmp_path) -> None:
    service = auth_service(tmp_path)
    admin_session = bootstrap(service)
    admin = admin_session["user"]
    analyst = service.create_user(
        AuthUserCreate(
            username="tier-two",
            display_name="Tier Two",
            role="analyst",
            password="tier two password long",
            connection_ids=["primary"],
        ),
        actor=admin,
    )
    analyst_session = service.login("tier-two", "tier two password long", "127.0.0.1")

    service.update_user(
        analyst["id"],
        AuthUserUpdate(connection_ids=[]),
        actor=admin,
    )
    assert service.authenticate(analyst_session["token"]) is None

    with pytest.raises(ValueError, match="at least one active admin"):
        service.update_user(
            admin["id"],
            AuthUserUpdate(role="analyst"),
            actor=admin,
        )


def test_disable_preserves_identities_for_authenticated_reenable(tmp_path) -> None:
    service = auth_service(tmp_path)
    session = bootstrap(service)

    service.disable(session["user"]["id"], "correct horse battery staple")
    status = service.status()
    assert status["enabled"] is False
    assert status["reenable_required"] is True
    assert status["identity_count"] == 1
    assert service.authenticate(session["token"]) is None

    reenabled = service.bootstrap(
        username="security-admin",
        display_name="Ignored on re-enable",
        password="correct horse battery staple",
        source="127.0.0.1",
    )
    assert service.status(reenabled["token"])["authenticated"] is True


def test_login_throttles_repeated_failures(tmp_path) -> None:
    service = auth_service(tmp_path)
    bootstrap(service)

    for _ in range(5):
        with pytest.raises(PermissionError):
            service.login("security-admin", "incorrect password", "10.0.0.5")
    with pytest.raises(RuntimeError, match="Too many failed"):
        service.login(
            "security-admin",
            "correct horse battery staple",
            "10.0.0.5",
        )


def test_http_gate_sets_cookies_enforces_csrf_and_admin_reads(tmp_path, monkeypatch) -> None:
    store = AuthStore(tmp_path / "http-auth.db")
    service = AuthService(store, AuditStore(tmp_path / "http-audit.db"))
    monkeypatch.setattr(app_module.services, "auth_store", store)
    monkeypatch.setattr(app_module.services, "auth", service)
    monkeypatch.setattr(app_module.services, "audit", service.audit)
    client = TestClient(app_module.app)

    assert client.get("/api/auth/status").json()["mode"] == "local-single-user"
    enabled = client.post(
        "/api/auth/bootstrap",
        json={
            "username": "http-admin",
            "display_name": "HTTP Admin",
            "password": "http admin password long",
        },
    )
    assert enabled.status_code == 200
    assert enabled.json()["authenticated"] is True
    assert client.cookies.get(SESSION_COOKIE)
    csrf = client.cookies.get(CSRF_COOKIE)
    assert csrf
    assert "HttpOnly" in enabled.headers.get("set-cookie", "")

    rejected = client.post(
        "/api/auth/users",
        json={
            "username": "http-viewer",
            "display_name": "HTTP Viewer",
            "role": "viewer",
            "password": "http viewer password long",
            "connection_ids": ["primary"],
        },
    )
    assert rejected.status_code == 403
    assert "CSRF" in rejected.json()["detail"]

    created = client.post(
        "/api/auth/users",
        headers={"X-SignalRoom-CSRF": csrf},
        json={
            "username": "http-viewer",
            "display_name": "HTTP Viewer",
            "role": "viewer",
            "password": "http viewer password long",
            "connection_ids": ["primary"],
        },
    )
    assert created.status_code == 201
    assert created.json()["role"] == "viewer"
    assert "password_hash" not in created.json()

    viewer_client = TestClient(app_module.app)
    viewer_login = viewer_client.post(
        "/api/auth/login",
        json={
            "username": "http-viewer",
            "password": "http viewer password long",
        },
    )
    assert viewer_login.status_code == 200
    assert viewer_client.get("/api/settings").status_code == 200
    assert viewer_client.get("/api/auth/users").status_code == 403
    viewer_csrf = viewer_client.cookies.get(CSRF_COOKIE)
    assert (
        viewer_client.post(
            "/api/auth/logout",
            headers={"X-SignalRoom-CSRF": viewer_csrf},
            json={},
        ).status_code
        == 200
    )
