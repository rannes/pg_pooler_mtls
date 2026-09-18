"""Adversarial live checks. The runner deliberately has access to all demo networks.

It is never part of the application deployment. Positive controls precede every
denial so an unavailable stack cannot pass as an enforced security boundary.
"""
import concurrent.futures
import os
from pathlib import Path
import re
import unittest

import psycopg

TLS = Path(os.environ.get("TEST_TLS", "/tls"))
POOLERS = ("pgbouncer", "pgdog")
# Match only a complete, observed server diagnostic at the end of libpq's
# variable connection-error prefix. A SQLSTATE or the words "SSL", "database"
# and "certificate" alone do not demonstrate authorization enforcement.
DENIAL_PATTERNS = {
    name: re.compile(r"(?:\A|failed:\s+)" + diagnostic + r"\s*\Z", re.IGNORECASE)
    for name, diagnostic in {
        "pgbouncer_identity": r"FATAL:\s+certificate authentication failed",
        "pgbouncer_plaintext": r"FATAL:\s+SSL required",
        "pgbouncer_missing_certificate": r"SSL error: tlsv13 alert certificate required",
        "expired_certificate": r"SSL error: ssl/tls alert certificate expired",
        "untrusted_certificate": r"SSL error: tlsv1 alert unknown ca",
        "pgbouncer_other_database": r"FATAL:\s+login rejected",
        "pgdog_identity": r'FATAL:\s+password for user "app[12]" and database "productdb" is wrong, or the database does not exist',
        "pgdog_plaintext": r"FATAL:\s+only TLS connections are allowed",
        "pgdog_other_database": r'FATAL:\s+password for user "app1" and database "postgres" is wrong, or the database does not exist',
        "postgres_gateway_role": r'FATAL:\s+pg_hba\.conf rejects connection for host "[0-9a-f:.]+", user "postgres", database "productdb", SSL encryption',
        "postgres_missing_certificate": r"FATAL:\s+connection requires a valid client certificate",
        "postgres_plaintext": r'FATAL:\s+pg_hba\.conf rejects connection for host "[0-9a-f:.]+", user "app1", database "productdb", no encryption',
    }.items()
}


def connect(host, user="app1", certificate="app1", mode="verify-full", database="productdb"):
    root = "database-ca.crt" if host == "postgres" else "pooler-ca.crt"
    args = dict(host=host, port=5432 if host == "postgres" else 6432,
                user=user, dbname=database, sslmode=mode,
                sslrootcert=str(TLS / root), connect_timeout=3,
                application_name="security-suite", prepare_threshold=None)
    if certificate:
        args.update(sslcert=str(TLS / f"{certificate}.crt"),
                    sslkey=str(TLS / f"{certificate}.key"))
    return psycopg.connect(**args)


def identity(connection):
    with connection:
        return connection.execute("SELECT session_user, current_user, ssl, client_dn "
                                  "FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()


class DenialHelperTests(unittest.TestCase):
    def test_transport_failures_do_not_count_as_security_denials(self):
        failures = (
            "SSL SYSCALL error: EOF detected",
            "SSL error: unexpected EOF while reading",
            "SSL connection has been closed unexpectedly",
            "could not receive data from server: Connection reset by peer",
            "server closed the connection unexpectedly",
            "connection timeout expired",
            "connection failed: Connection refused",
            'could not translate host name "pgdog" to address: Name or service not known',
            "SSL error: certificate verify failed",
            'server certificate for "wrong-name" does not match host name "pgdog"',
            'could not open certificate file "/tls/expired.crt": No such file or directory',
            'could not load private key file "/tls/expired.key": No such file or directory',
            'could not load private key file "/tls/app1.key": Permission denied',
        )
        for case in DENIAL_PATTERNS:
            for diagnostic in failures:
                for prefix in ("", 'connection failed: connection to server at "172.30.83.4", port 6432 failed: '):
                    with self.subTest(case=case, diagnostic=diagnostic, prefix=prefix):
                        def refused():
                            raise psycopg.OperationalError(prefix + diagnostic)
                        with self.assertRaises(AssertionError):
                            SecurityTests().denied(refused, case)

    def test_observed_diagnostics_pass_only_their_expected_matchers(self):
        diagnostics = {
            "pgbouncer_identity": "FATAL:  certificate authentication failed",
            "pgbouncer_plaintext": "FATAL:  SSL required",
            "pgbouncer_missing_certificate": "SSL error: tlsv13 alert certificate required",
            "expired_certificate": "SSL error: ssl/tls alert certificate expired",
            "untrusted_certificate": "SSL error: tlsv1 alert unknown ca",
            "pgbouncer_other_database": "FATAL:  login rejected",
            "pgdog_identity": 'FATAL:  password for user "app2" and database "productdb" is wrong, or the database does not exist',
            "pgdog_plaintext": "FATAL:  only TLS connections are allowed",
            "pgdog_other_database": 'FATAL:  password for user "app1" and database "postgres" is wrong, or the database does not exist',
            "postgres_gateway_role": 'FATAL:  pg_hba.conf rejects connection for host "172.30.83.4", user "postgres", database "productdb", SSL encryption',
            "postgres_missing_certificate": "FATAL:  connection requires a valid client certificate",
            "postgres_plaintext": 'FATAL:  pg_hba.conf rejects connection for host "172.30.83.4", user "app1", database "productdb", no encryption',
        }
        for case in DENIAL_PATTERNS:
            for observed_case, diagnostic in diagnostics.items():
                with self.subTest(case=case, observed_case=observed_case):
                    def denied():
                        raise psycopg.OperationalError('connection failed: connection to server at "172.30.83.4", port 6432 failed: ' + diagnostic)
                    if case == observed_case:
                        SecurityTests().denied(denied, case)
                    else:
                        with self.assertRaises(AssertionError):
                            SecurityTests().denied(denied, case)

    def test_diagnostic_must_be_complete_and_final(self):
        diagnostic = "FATAL:  certificate authentication failed"
        for suffix in (" because of a network error", "\nSSL SYSCALL error: EOF detected"):
            with self.subTest(suffix=suffix):
                def failed():
                    raise psycopg.OperationalError(diagnostic + suffix)
                with self.assertRaises(AssertionError):
                    SecurityTests().denied(failed, "pgbouncer_identity")

    def test_sqlstate_cannot_bypass_the_diagnostic_match(self):
        for case in DENIAL_PATTERNS:
            with self.subTest(case=case):
                def failed():
                    raise psycopg.errors.InvalidAuthorizationSpecification("unrecognized authorization failure")
                with self.assertRaises(AssertionError):
                    SecurityTests().denied(failed, case)


class SecurityTests(unittest.TestCase):
    def control(self, pooler, app="app1"):
        row = identity(connect(pooler, user=app, certificate=app))
        self.assertEqual(row[:3], (app, app, True))
        self.assertEqual(row[3], f"/CN={pooler}-gateway")

    def denied(self, callback, denial_case):
        try:
            with callback() as connection:
                connection.execute("SELECT 1")
        except psycopg.Error as exc:
            self.assertRegex(str(exc), DENIAL_PATTERNS[denial_case],
                             f"Unexpected failure for {denial_case}, not an authenticated denial: {exc!r}")
        else:
            self.fail("Unauthorized connection succeeded")

    def test_01_both_roles_and_tls_identity_through_both_poolers(self):
        for pooler in POOLERS:
            for app in ("app1", "app2"):
                with self.subTest(pooler=pooler, app=app):
                    self.control(pooler, app)

    def test_02_trusted_workload_cannot_impersonate_other_role(self):
        for pooler in POOLERS:
            for app, other in (("app1", "app2"), ("app2", "app1")):
                with self.subTest(pooler=pooler, app=app):
                    self.control(pooler, app)
                    self.denied(lambda: connect(pooler, user=other, certificate=app),
                                f"{pooler}_identity")

    def test_03_plaintext_and_missing_certificate_are_denied(self):
        for pooler in POOLERS:
            self.control(pooler)
            for mode in ("disable", "verify-full"):
                with self.subTest(pooler=pooler, mode=mode):
                    denial_case = (f"{pooler}_plaintext" if mode == "disable" else
                                   "pgdog_identity" if pooler == "pgdog" else "pgbouncer_missing_certificate")
                    self.denied(lambda: connect(pooler, certificate=None, mode=mode),
                                denial_case)

    def test_04_expired_untrusted_and_unmapped_certificates_are_denied(self):
        for pooler in POOLERS:
            for cert in ("expired", "rogue", "unmapped"):
                with self.subTest(pooler=pooler, cert=cert):
                    self.control(pooler)
                    denial_case = {"expired": "expired_certificate", "rogue": "untrusted_certificate",
                                   "unmapped": f"{pooler}_identity"}[cert]
                    self.denied(lambda: connect(pooler, certificate=cert),
                                denial_case)

    def test_05_sql_privileges_prevent_cross_schema_access_and_set_role(self):
        for pooler in POOLERS:
            for app, other in (("app1", "app2"), ("app2", "app1")):
                for statement in (f"SELECT * FROM {other}.notes", f"SET ROLE {other}"):
                    with self.subTest(pooler=pooler, app=app, statement=statement):
                        self.control(pooler, app)
                        with connect(pooler, user=app, certificate=app) as conn:
                            self.assertEqual(conn.execute("SELECT current_user").fetchone()[0], app)
                            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                                conn.execute(statement)

    def test_06_database_independently_enforces_gateway_identity(self):
        for pooler in POOLERS:
            row = identity(connect("postgres", certificate=f"{pooler}-gateway"))
            self.assertEqual(row[:3], ("app1", "app1", True))
            self.denied(lambda: connect("postgres", user="postgres", certificate=f"{pooler}-gateway"),
                        "postgres_gateway_role")
        for cert in (None, "app1"):
            self.denied(lambda: connect("postgres", certificate=cert),
                        "postgres_missing_certificate" if cert is None else "untrusted_certificate")
        self.denied(lambda: connect("postgres", certificate=None, mode="disable"),
                    "postgres_plaintext")

    def test_07_parallel_transactions_do_not_leak_database_roles(self):
        def check(item):
            pooler, app = item
            self.control(pooler, app)
        jobs = [(pooler, app) for _ in range(10) for pooler in POOLERS for app in ("app1", "app2")]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(check, jobs))

    def test_08_other_databases_are_not_authorized(self):
        for pooler in POOLERS:
            self.control(pooler)
            self.denied(lambda: connect(pooler, database="postgres"),
                        f"{pooler}_other_database")

    def test_09_deferred_set_role_cannot_gain_access(self):
        # PgDog can acknowledge a SET before acquiring a backend. The first real
        # query must still fail, so a protocol-level SET response is not proof.
        self.control("pgdog")
        with connect("pgdog") as conn:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                conn.execute("SET ROLE app2")
                conn.execute("SELECT current_user, session_user")


if __name__ == "__main__":
    unittest.main(verbosity=2)
