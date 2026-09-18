# Verification record

Verified on 2026-09-18 using macOS ARM64, OrbStack, Docker 29.4, and Docker Compose 5.1.2. These are observations from this implementation run, not a substitute for testing another checkout or environment. The GitHub Actions workflow repeats the container and API checks on an Ubuntu runner.

## Repeat the checks

```sh
docker compose up --build -d --wait
make test
```

The final run completed successfully:

| Layer | Result | Coverage |
| --- | --- | --- |
| App unit tests | 48 passed | Closed API inputs, browser guards, evidence validation, bounded events, failure classification |
| Certificate/security suite | 13 passed | 4 denial-matcher regressions and 9 live cases covering both poolers, identities, invalid certificates, backend policy, SQL grants, deferred `SET ROLE`, and 40 concurrent mixed-role transactions |
| Actual app API matrix | 36 passed | 2 apps × 2 poolers × 9 actions, including actual direct-access probes from each app namespace; both event feeds checked |
| Running deployment checks | 4 passed | Credential-free apps, network/namespace boundaries, loopback-only publication, NULL role passwords and no escalation memberships |

The unit run emitted two upstream test-client/dependency deprecation warnings. It had no failed tests. The security suite accepts specific terminal authentication diagnostics; EOF, resets, timeouts, DNS failures, server-certificate verification errors, and missing local credential fixtures do not count as successful authorization denials.

Successful identity actions returned the correct `current_user` and `session_user`, database `productdb`, TLS enabled, and the expected pooler gateway certificate. Cross-role login, cross-schema reads, `SET ROLE`, and unauthenticated pooler connections were rejected. Direct PostgreSQL probes by name and numeric address were blocked from both apps while the same database remained reachable through each pooler.

## Fresh initialization and browser checks

A second, isolated Compose project was started with new database/PKI volumes, ports `18081`/`18082`, subnet `172.30.84.0/24`, and PostgreSQL address `172.30.84.10`. Its first initialization succeeded; its full 36-action API matrix, 13 security checks, and 4 deployment checks passed. This checked initial provisioning and custom port/subnet behavior independently of retained development volumes. The disposable second project was then removed; the default demo remains running.

Chrome checks exercised App 1's complete nine-action PgDog flow and App 2's complete nine-action PgBouncer flow, each reporting nine expected results. The API matrix covered all four app/pooler combinations. Identity and TLS evidence, the event feed, and raw response details rendered correctly. Browser logs had no errors or warnings. At a 390 × 844 viewport the page had no horizontal overflow.

## Dependency and review checks

The final runtime Python requirement lock was checked with `pip-audit`, which reported **no known vulnerabilities** at verification time. That result applies only to the listed Python runtime packages and the advisory database available then; it is not an audit of container OS packages, Envoy, PostgreSQL, PgBouncer, or PgDog.

An independent code review identified overly broad TLS-error acceptance in the privileged test harness. The fix replaced substring matching with exact observed diagnostics and added regression cases for infrastructure and local-fixture failures. The full suite above passed after that fix and the dependency refresh. A source scan found no private-key PEMs or GitHub access tokens in the files prepared for Git.

The important version-specific implementation discoveries are documented in the [implementation manual](IMPLEMENTATION.md): PgDog's empty backend-password candidate, deferred `SET ROLE` behavior, gateway certificate evidence, and host HTTP publication through the separate nginx ingress. Read the [security model](SECURITY.md) before extending the demonstration or presenting it as evidence for a different deployment.
