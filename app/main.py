"""Fixed-purpose, passwordless probes. No SQL or network targets come from HTTP input."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import errno
import ipaddress
import logging
import os
from pathlib import Path
import re
import socket
from threading import Lock
from time import perf_counter
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from starlette.middleware.trustedhost import TrustedHostMiddleware


LOGGER = logging.getLogger("pooler_demo")
STATIC = Path(__file__).parent / "static"
POOLERS = {"pgbouncer": {"name": "PgBouncer", "local_port": 15432},
           "pgdog": {"name": "PgDog", "local_port": 15433}}
ACTIONS = [
    {"id": "identity", "label": "Check identity", "description": "See the role and TLS session PostgreSQL sees.", "expected": "allowed"},
    {"id": "read", "label": "Read own notes", "description": "Read the latest rows from your app’s schema.", "expected": "allowed"},
    {"id": "write", "label": "Write a note", "description": "Insert a timestamped note into your app’s schema.", "expected": "allowed"},
    {"id": "impersonate", "label": "Request the other identity", "description": "Keep this workload certificate; request the other role.", "expected": "blocked"},
    {"id": "cross_read", "label": "Read the other schema", "description": "Try to read notes owned by the other app.", "expected": "blocked"},
    {"id": "set_role", "label": "Switch to the other role", "description": "Try SET ROLE after an authorized connection.", "expected": "blocked"},
    {"id": "direct_db", "label": "Reach PostgreSQL directly", "description": "Probe the database by both DNS name and numeric IP.", "expected": "blocked"},
    {"id": "direct_pooler_plain", "label": "Bypass Envoy without TLS", "description": "Connect to the pooler over plaintext TCP.", "expected": "blocked"},
    {"id": "direct_pooler_tls", "label": "Use TLS without a certificate", "description": "Connect to the pooler with TLS but no client certificate.", "expected": "blocked"},
]
ACTION_MAP = {action["id"]: action for action in ACTIONS}


@dataclass(frozen=True)
class Settings:
    app_id: str
    other_app_id: str
    direct_db_ip: str
    other_app_port: int | None = None

    def __post_init__(self):
        if {self.app_id, self.other_app_id} != {"app1", "app2"}:
            raise ValueError("APP_ID and OTHER_APP_ID must be different members of app1, app2")
        ipaddress.ip_address(self.direct_db_ip)
        if self.other_app_port is not None and not 1 <= self.other_app_port <= 65535:
            raise ValueError("OTHER_APP_PORT must be between 1 and 65535")

    @classmethod
    def from_env(cls):
        app_id = os.environ.get("APP_ID", "app1")
        other_app_id = os.environ.get("OTHER_APP_ID", "app2" if app_id == "app1" else "app1")
        return cls(app_id, other_app_id, os.environ.get("DIRECT_DB_IP", "172.30.83.10"),
                   int(os.environ.get("OTHER_APP_PORT", "8081" if other_app_id == "app1" else "8082")))


class Pooler(str, Enum):
    pgbouncer = "pgbouncer"
    pgdog = "pgdog"


class Action(str, Enum):
    identity = "identity"
    read = "read"
    write = "write"
    impersonate = "impersonate"
    cross_read = "cross_read"
    set_role = "set_role"
    direct_db = "direct_db"
    direct_pooler_plain = "direct_pooler_plain"
    direct_pooler_tls = "direct_pooler_tls"


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pooler: Pooler
    action: Action


def error_evidence(error):
    return {"type": type(error).__name__, "sqlstate": getattr(error, "sqlstate", None),
            "message": str(error)[:4000]}


PGDOG_AUTH_REFUSAL = re.compile(
    r'FATAL:\s+password for user "app[12]" and database "productdb" is wrong, or the database does not exist(?:\n|$)',
    re.IGNORECASE,
)


def is_expected_denial(action, error, pooler=None):
    """An outage, EOF, reset, missing relation or arbitrary exception is never a denial."""
    if not isinstance(error, psycopg.Error):
        return False
    state = getattr(error, "sqlstate", None)
    message = str(error).lower()
    # PgDog 0.1.59 maps certificate identity failure to this generic auth
    # response. A successful own-identity control is also required by perform().
    if pooler == "pgdog" and action in {"impersonate", "direct_pooler_tls"} and PGDOG_AUTH_REFUSAL.search(str(error)):
        return True
    if action in {"cross_read", "set_role"}:
        return state == "42501"
    if action == "impersonate":
        return state in {"28000", "28P01"} or bool(re.search(
            r"certificate (?:authentication failed|does not match|not authorized)|"
            r"(?:invalid|bad) client certificate|certificate.*user.*mismatch", message))
    if action == "direct_pooler_plain":
        return bool(re.search(r"(?:ssl|tls)(?: connection)? (?:is )?required|must use (?:ssl|tls)|only tls connections are allowed", message))
    if action == "direct_pooler_tls":
        return bool(re.search(r"alert certificate required|client certificate (?:is )?required|"
                              r"requires a valid client certificate|peer did not return a certificate|"
                              r"no (?:valid )?client certificate", message))
    return False


IDENTITY_SQL = """SELECT current_user::text, session_user::text,
    pg_backend_pid() AS backend_pid, current_database() AS database,
    inet_server_addr()::text AS server_address,
    s.ssl, s.version, s.cipher, s.bits, s.client_dn
FROM pg_stat_ssl AS s WHERE s.pid = pg_backend_pid()"""


class Runner:
    def __init__(self, settings):
        self.settings = settings
        self._events = deque(maxlen=100)
        self._event_lock = Lock()

    def events(self):
        with self._event_lock:
            return list(self._events)

    def connection_parameters(self, pooler, *, user=None, direct=False, tls=False):
        return {"host": pooler if direct else "127.0.0.1",
                "port": 6432 if direct else POOLERS[pooler]["local_port"],
                "dbname": "productdb", "user": user or self.settings.app_id,
                "sslmode": "require" if tls else "disable", "connect_timeout": 3,
                "application_name": f"passwordless-demo-{self.settings.app_id}",
                "passfile": "/dev/null", "row_factory": dict_row}

    def database_action(self, action, pooler):
        direct = action in {"direct_pooler_plain", "direct_pooler_tls"}
        user = self.settings.other_app_id if action == "impersonate" else self.settings.app_id
        parameters = self.connection_parameters(pooler, user=user, direct=direct,
                                                tls=action == "direct_pooler_tls")
        evidence = {"connection": {key: parameters[key] for key in ("host", "port", "user", "dbname", "sslmode")},
                    "identity_sql": IDENTITY_SQL}
        try:
            with psycopg.connect(**parameters) as connection:
                # A transaction pool pins this backend until COMMIT/ROLLBACK. Identity,
                # TLS evidence and the actual action therefore belong to one backend.
                with connection.transaction():
                    connection.execute("SET LOCAL statement_timeout = '4s'")
                    row = connection.execute(IDENTITY_SQL).fetchone()
                    if row is None:
                        raise RuntimeError("No pg_stat_ssl row was visible for this backend")
                    evidence["identity"] = {key: row[key] for key in (
                        "current_user", "session_user", "backend_pid", "database", "server_address")}
                    evidence["tls"] = {key: row[key] for key in ("ssl", "version", "cipher", "bits", "client_dn")}
                    if action in {"read", "cross_read"}:
                        schema = self.settings.other_app_id if action == "cross_read" else self.settings.app_id
                        query = sql.SQL("SELECT id, body, created_at FROM {}.notes ORDER BY id DESC LIMIT 20").format(sql.Identifier(schema))
                        evidence["sql"] = query.as_string(connection)
                        evidence["rows"] = connection.execute(query).fetchall()
                    elif action == "write":
                        query = sql.SQL("INSERT INTO {}.notes (body) VALUES (%s) RETURNING id, body, created_at").format(sql.Identifier(self.settings.app_id))
                        note = f"Hello from {self.settings.app_id} via {POOLERS[pooler]['name']} at {datetime.now(timezone.utc).isoformat()}"
                        evidence["sql"] = query.as_string(connection)
                        evidence["parameters"] = [note]
                        evidence["rows"] = connection.execute(query, (note,)).fetchall()
                    elif action == "set_role":
                        query = sql.SQL("SET ROLE {}").format(sql.Identifier(self.settings.other_app_id))
                        evidence["sql"] = query.as_string(connection)
                        connection.execute(query)
                        evidence["role_after"] = connection.execute("SELECT current_user::text, session_user::text").fetchone()
                    else:
                        evidence["sql"] = IDENTITY_SQL
            return jsonable_encoder(evidence)
        except Exception as error:
            # Preserve identity evidence captured before a statement was denied.
            error.probe_evidence = jsonable_encoder(evidence)
            raise

    def identity_valid(self, evidence, pooler):
        identity = evidence.get("identity", {})
        tls = evidence.get("tls", {})
        dn = tls.get("client_dn") or ""
        expected_cn = f"{pooler}-gateway"
        return (identity.get("current_user") == self.settings.app_id
                and identity.get("session_user") == self.settings.app_id
                and identity.get("database") == "productdb"
                and tls.get("ssl") is True
                and bool(re.search(r"(?:^|[,/])\s*CN=" + re.escape(expected_cn) + r"(?:$|[,/])", dn)))

    def availability_control(self, pooler):
        try:
            evidence = self.database_action("identity", pooler)
            available = self.identity_valid(evidence, pooler)
            return {"available": available, **evidence}
        except Exception as error:
            return {"available": False, "error": error_evidence(error)}

    def direct_database(self, pooler):
        probes = []
        for host in ("postgres", self.settings.direct_db_ip):
            probe = {"target": f"{host}:5432", "kind": "dns" if host == "postgres" else "numeric_ip"}
            try:
                with socket.create_connection((host, 5432), timeout=2):
                    probe["status"] = "reachable"
            except socket.gaierror as error:
                probe.update(status="dns_error", error=error_evidence(error))
            except OSError as error:
                isolated = isinstance(error, TimeoutError) or error.errno in {
                    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT, errno.ECONNREFUSED}
                probe.update(status="isolated" if isolated else "error", error=error_evidence(error))
            probes.append(probe)
        control = self.availability_control(pooler)
        evidence = {"probes": probes, "control": control,
                    "explanation": "TCP reachability probes test network access. DNS failure alone does not prove isolation; the pooler control must reach the same live database."}
        if any(probe["status"] == "reachable" for probe in probes):
            return "unexpected", evidence
        actual_address = control.get("identity", {}).get("server_address")
        if control["available"]:
            try:
                matches_target = ipaddress.ip_interface(actual_address).ip == ipaddress.ip_address(self.settings.direct_db_ip)
            except (ValueError, TypeError):
                evidence["error"] = {"message": f"The live backend address {actual_address!r} is missing or malformed. The configured numeric target cannot be verified."}
                return "error", evidence
            if not matches_target:
                evidence["error"] = {"message": f"The configured numeric target {self.settings.direct_db_ip} does not match the live backend address {actual_address}. Isolation is unverified."}
                return "error", evidence
        if (control["available"] and probes[1]["status"] == "isolated"
                and probes[0]["status"] in {"isolated", "dns_error"}):
            return "blocked", evidence
        return "error", evidence

    def perform(self, action, pooler):
        if action == "direct_db":
            return self.direct_database(pooler)
        expected = ACTION_MAP[action]["expected"]
        try:
            evidence = self.database_action(action, pooler)
        except Exception as error:
            evidence = getattr(error, "probe_evidence", {})
            denied = is_expected_denial(action, error, pooler)
            evidence["denial" if denied else "error"] = error_evidence(error)
            if denied and pooler == "pgdog" and PGDOG_AUTH_REFUSAL.search(str(error)):
                evidence["denial"]["explanation"] = "PgDog 0.1.59 uses generic password wording for certificate identity refusal. No frontend password is configured or supplied. The successful own-identity control distinguishes this refusal from an unavailable database."
            if expected == "blocked":
                evidence["control"] = self.availability_control(pooler)
                if denied and evidence["control"]["available"]:
                    return "blocked", evidence
            return "error", evidence
        if expected == "blocked":
            return "unexpected", evidence
        if not self.identity_valid(evidence, pooler):
            evidence["error"] = {"message": "Role, database or backend gateway TLS identity did not match the selected path."}
            return "unexpected", evidence
        return "allowed", evidence

    def run(self, action, pooler):
        start = perf_counter()
        try:
            outcome, evidence = self.perform(action, pooler)
        except Exception as error:
            LOGGER.exception("Probe execution failed")
            outcome, evidence = "error", {"error": error_evidence(error)}
        expected = ACTION_MAP[action]["expected"]
        event = {"request_id": str(uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
                 "app": self.settings.app_id, "pooler": pooler, "action": action,
                 "outcome": outcome, "expected": expected, "passed": outcome == expected,
                 "duration_ms": round((perf_counter() - start) * 1000, 1), "evidence": evidence}
        with self._event_lock:
            self._events.append(event)
        LOGGER.info("app=%s pooler=%s action=%s outcome=%s request_id=%s", self.settings.app_id,
                    pooler, action, outcome, event["request_id"])
        return event


def create_app(settings=None):
    settings = settings or Settings.from_env()
    app = FastAPI(title="Passwordless pooler lab", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runner = Runner(settings)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "::1", "app1", "app2"])

    @app.middleware("http")
    async def origin_and_headers(request: Request, call_next):
        if request.method == "POST":
            origin = request.headers.get("origin")
            expected_origin = f"{request.url.scheme}://{request.url.netloc}"
            if (origin is not None and origin != expected_origin) or request.headers.get("sec-fetch-site") == "cross-site":
                return JSONResponse({"detail": "Only same-origin requests are accepted"}, status_code=403)
            if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                return JSONResponse({"detail": "Use application/json"}, status_code=415)
        response = await call_next(request)
        response.headers.update({
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Cache-Control": "no-store"})
        return response

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "app": settings.app_id}

    @app.get("/api/config")
    def config():
        return {"app": settings.app_id, "other_app": settings.other_app_id,
                "other_app_port": settings.other_app_port or (8081 if settings.other_app_id == "app1" else 8082),
                "database": "productdb", "schema": settings.app_id,
                "workload_certificate": f"{settings.app_id}.internal",
                "poolers": [{"id": key, **value} for key, value in POOLERS.items()],
                "actions": ACTIONS, "event_limit": 100}

    @app.post("/api/run")
    def run(request: RunRequest):
        return app.state.runner.run(request.action.value, request.pooler.value)

    @app.get("/api/events")
    def events():
        return {"app": settings.app_id, "events": app.state.runner.events(), "limit": 100}

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app


app = create_app()
