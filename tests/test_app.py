"""Boundary tests: real API/classifier, with only external I/O replaced."""

import errno
import importlib
import socket

import pytest
from fastapi.testclient import TestClient
import psycopg


def module():
    return importlib.import_module("app.main")


def client_for(monkeypatch, run=None):
    main = module()
    app = main.create_app(main.Settings("app1", "app2", "172.30.83.10"))
    if run:
        monkeypatch.setattr(app.state.runner, "perform", run)
    return TestClient(app, base_url="http://localhost"), app


def identity(role="app1"):
    return {
        "identity": {"current_user": role, "session_user": role, "backend_pid": 42,
                     "database": "productdb", "server_address": "172.30.83.10"},
        "tls": {"ssl": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "bits": 256, "client_dn": "CN=pgbouncer-gateway"},
    }


def test_health_is_liveness_and_config_has_fixed_actions(monkeypatch):
    client, _ = client_for(monkeypatch)
    assert client.get("/healthz").json() == {"status": "ok", "app": "app1"}
    config = client.get("/api/config").json()
    assert config["app"] == "app1"
    assert {item["id"] for item in config["actions"]} == {
        "identity", "read", "write", "impersonate", "cross_read", "set_role",
        "direct_db", "direct_pooler_plain", "direct_pooler_tls",
    }


@pytest.mark.parametrize("payload", [
    {"pooler": "outside", "action": "identity"},
    {"pooler": "pgdog", "action": "select * from secrets"},
    {"pooler": "pgdog", "action": "identity", "host": "attacker"},
    {"pooler": "pgdog", "action": "identity", "user": "app2"},
])
def test_api_rejects_arbitrary_inputs(monkeypatch, payload):
    client, _ = client_for(monkeypatch)
    assert client.post("/api/run", json=payload).status_code == 422


@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Origin": "http://localhost.evil.example"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_api_rejects_cross_origin_posts(monkeypatch, headers):
    client, _ = client_for(monkeypatch)
    assert client.post("/api/run", json={"pooler": "pgdog", "action": "write"},
                       headers=headers).status_code == 403


def test_json_content_type_and_host_are_guarded(monkeypatch):
    client, _ = client_for(monkeypatch)
    assert client.post("/api/run", content='{"pooler":"pgdog","action":"write"}',
                       headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.get("/api/config", headers={"Host": "evil.example"}).status_code == 400


def test_api_records_attempt_metadata_and_bounded_per_app_feed(monkeypatch):
    client, app = client_for(monkeypatch, lambda action, pooler: ("allowed", identity()))
    for _ in range(105):
        response = client.post("/api/run", json={"pooler": "pgbouncer", "action": "identity"},
                               headers={"Origin": "http://localhost"})
        assert response.status_code == 200
    result = response.json()
    assert result["outcome"] == result["expected"] == "allowed"
    assert result["passed"] is True
    assert result["app"] == "app1" and result["pooler"] == "pgbouncer"
    assert result["action"] == "identity" and result["request_id"]
    assert result["duration_ms"] >= 0 and result["timestamp"]
    events = client.get("/api/events").json()["events"]
    assert len(events) == 100 and events[-1]["request_id"] == result["request_id"]
    second = module().create_app(module().Settings("app2", "app1", "172.30.83.10"))
    assert TestClient(second, base_url="http://localhost").get("/api/events").json()["events"] == []


@pytest.mark.parametrize("action,error,expected", [
    ("cross_read", psycopg.errors.InsufficientPrivilege("permission denied for schema app2"), True),
    ("set_role", psycopg.errors.InsufficientPrivilege("permission denied to set role app2"), True),
    ("cross_read", psycopg.errors.UndefinedTable("table is missing"), False),
    ("cross_read", psycopg.OperationalError("connection refused"), False),
    ("impersonate", psycopg.errors.InvalidAuthorizationSpecification("certificate authentication failed"), True),
    ("impersonate", psycopg.OperationalError("connection refused"), False),
    ("impersonate", psycopg.OperationalError("server closed the connection unexpectedly"), False),
    ("direct_pooler_tls", psycopg.OperationalError("SSL error: tlsv13 alert certificate required"), True),
    ("direct_pooler_tls", psycopg.OperationalError("SSL SYSCALL error: EOF detected"), False),
    ("direct_pooler_plain", psycopg.OperationalError("FATAL: SSL required"), True),
    ("direct_pooler_plain", psycopg.OperationalError("FATAL: only TLS connections are allowed"), True),
    ("direct_pooler_plain", psycopg.OperationalError("connection timed out"), False),
])
def test_only_expected_authorization_failures_count_as_denials(action, error, expected):
    assert module().is_expected_denial(action, error) is expected


def test_denial_with_unavailable_control_is_error(monkeypatch):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    def broken(action, pooler, **kwargs):
        if action == "identity":
            raise psycopg.OperationalError("connection refused")
        raise psycopg.errors.InsufficientPrivilege("permission denied for schema app2")
    monkeypatch.setattr(runner, "database_action", broken)
    result = runner.run("cross_read", "pgbouncer")
    assert result["outcome"] == "error" and result["passed"] is False
    assert result["evidence"]["control"]["available"] is False


def test_denial_keeps_error_and_successful_control_evidence(monkeypatch):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    def denied(action, pooler, **kwargs):
        if action == "identity":
            return identity()
        raise psycopg.errors.InsufficientPrivilege("permission denied for schema app2")
    monkeypatch.setattr(runner, "database_action", denied)
    result = runner.run("cross_read", "pgbouncer")
    assert result["outcome"] == "blocked" and result["passed"] is True
    assert result["evidence"]["denial"]["sqlstate"] == "42501"
    assert result["evidence"]["control"]["available"] is True


@pytest.mark.parametrize("failure", [socket.timeout("timed out"),
    OSError(errno.ENETUNREACH, "network unreachable"),
    ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")])
def test_direct_db_requires_numeric_probe_and_healthy_pooler(monkeypatch, failure):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    monkeypatch.setattr(runner, "database_action", lambda *args, **kwargs: identity())
    def unreachable(address, timeout):
        if address[0] == "postgres":
            raise socket.gaierror(socket.EAI_NONAME, "name not known")
        raise failure
    monkeypatch.setattr(main.socket, "create_connection", unreachable)
    result = runner.run("direct_db", "pgbouncer")
    assert result["outcome"] == "blocked" and result["passed"] is True
    probes = result["evidence"]["probes"]
    assert [probe["target"] for probe in probes] == ["postgres:5432", "172.30.83.10:5432"]
    assert probes[0]["status"] == "dns_error" and probes[1]["status"] == "isolated"


def test_dns_failure_alone_does_not_prove_isolation(monkeypatch):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    monkeypatch.setattr(runner, "database_action", lambda *args, **kwargs: identity())
    def resolution_failed(address, timeout):
        raise socket.gaierror(socket.EAI_NONAME, "name not known")
    monkeypatch.setattr(main.socket, "create_connection", resolution_failed)
    result = runner.run("direct_db", "pgdog")
    assert result["outcome"] == "error" and result["passed"] is False


def test_reachable_database_is_unexpected_even_without_dns(monkeypatch):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    monkeypatch.setattr(runner, "database_action", lambda *args, **kwargs: identity())
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    def reachable(address, timeout):
        if address[0] == "postgres":
            raise socket.gaierror(socket.EAI_NONAME, "name not known")
        return Socket()
    monkeypatch.setattr(main.socket, "create_connection", reachable)
    assert runner.run("direct_db", "pgdog")["outcome"] == "unexpected"


@pytest.mark.parametrize("current,session,tls", [("app2", "app1", True),
    ("app1", "app2", True), ("app1", "app1", False)])
def test_wrong_identity_or_plaintext_backend_is_unexpected(monkeypatch, current, session, tls):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    evidence = identity()
    evidence["identity"].update(current_user=current, session_user=session)
    evidence["tls"]["ssl"] = tls
    monkeypatch.setattr(runner, "database_action", lambda *args, **kwargs: evidence)
    result = runner.run("identity", "pgbouncer")
    assert result["outcome"] == "unexpected" and result["passed"] is False


def test_no_certificate_or_password_is_supplied_in_connection_parameters():
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    local = runner.connection_parameters("pgbouncer")
    assert (local["host"], local["port"], local["sslmode"], local["user"], local["dbname"]) == (
        "127.0.0.1", 15432, "disable", "app1", "productdb")
    direct = runner.connection_parameters("pgdog", direct=True, tls=True)
    assert (direct["host"], direct["port"], direct["sslmode"]) == ("pgdog", 6432, "require")
    assert not set(local) & {"password", "sslcert", "sslkey"}
    assert not set(direct) & {"password", "sslcert", "sslkey"}


def test_invalid_environment_identity_and_non_numeric_target_rejected():
    main = module()
    for args in [("admin", "app2", "172.30.83.10"), ("app1", "app1", "172.30.83.10"),
                 ("app1", "app2", "outside.example")]:
        with pytest.raises(ValueError):
            main.Settings(*args)


def test_wrong_numeric_ip_cannot_prove_database_isolation(monkeypatch):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.99"))
    monkeypatch.setattr(runner, "database_action", lambda *args, **kwargs: identity())
    def refused(address, timeout):
        raise ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")
    monkeypatch.setattr(main.socket, "create_connection", refused)
    result = runner.run("direct_db", "pgbouncer")
    assert result["outcome"] == "error" and result["passed"] is False
    assert "configured" in result["evidence"]["error"]["message"].lower()


@pytest.mark.parametrize("action", ["impersonate", "direct_pooler_tls"])
def test_pgdog_known_generic_auth_response_is_a_denial_only_for_pgdog(action):
    error = psycopg.OperationalError('connection failed: FATAL:  password for user "app2" and database "productdb" is wrong, or the database does not exist')
    assert module().is_expected_denial(action, error, "pgdog") is True
    assert module().is_expected_denial(action, error, "pgbouncer") is False


def test_inexact_generic_auth_failure_is_not_accepted_as_denial():
    error = psycopg.OperationalError('password for user "admin" and database "other" is wrong, or the database does not exist')
    assert module().is_expected_denial("impersonate", error, "pgdog") is False


@pytest.mark.parametrize("address,expected", [("172.30.83.10", "blocked"),
    ("172.30.83.10/32", "blocked"), ("172.30.83.99/32", "error"),
    (None, "error"), ("malformed", "error")])
def test_database_control_address_is_normalized_and_validated(monkeypatch, address, expected):
    main = module()
    runner = main.Runner(main.Settings("app1", "app2", "172.30.83.10"))
    control = identity()
    control["identity"]["server_address"] = address
    monkeypatch.setattr(runner, "database_action", lambda *args, **kwargs: control)
    def refused(target, timeout):
        raise ConnectionRefusedError(errno.ECONNREFUSED, "connection refused")
    monkeypatch.setattr(main.socket, "create_connection", refused)
    result = runner.run("direct_db", "pgbouncer")
    assert result["outcome"] == expected
    if expected == "error":
        assert result["evidence"]["error"]["message"]


def test_other_app_navigation_uses_configured_port(monkeypatch):
    main = module()
    monkeypatch.setenv("APP_ID", "app1")
    monkeypatch.setenv("OTHER_APP_ID", "app2")
    monkeypatch.setenv("OTHER_APP_PORT", "18082")
    client = TestClient(main.create_app(main.Settings.from_env()), base_url="http://localhost")
    assert client.get("/api/config").json()["other_app_port"] == 18082


@pytest.mark.parametrize("port", ["0", "65536", "not-a-port"])
def test_invalid_other_app_port_rejected(monkeypatch, port):
    monkeypatch.setenv("OTHER_APP_PORT", port)
    with pytest.raises(ValueError):
        module().Settings.from_env()
