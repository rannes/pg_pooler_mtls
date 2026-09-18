# Passwordless demo implementation plan

> For agentic workers: follow this plan task by task; use test-first implementation and independent code review. User authorized autonomous implementation and GitHub push.

**Goal:** A working, tested two-app, two-pooler mTLS identity demo and implementation manual.

**Architecture:** App-local Envoy originates PostgreSQL STARTTLS with a workload certificate. Poolers authorize workload-to-role mappings and independently authenticate to PostgreSQL as constrained gateway identities.

**Tech stack:** Python 3.13, psycopg 3, FastAPI/Uvicorn, vanilla browser JavaScript, Envoy contrib 1.39.1, PgBouncer 1.25.2, PgDog 0.1.59, PostgreSQL 17, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-18-passwordless-demo-design.md`

## Global constraints

- No application or backend passwords; no auth_type=trust for TCP.
- Apps have no key mounts; only app-local loopback carries plaintext queries.
- Verify CA and server identity on both TLS hops; explicit certificate-to-role authorization.
- Only loopback HTTP host ports are published; no host DB/pooler/admin ports.
- Fail tests on outages rather than counting all failures as security denials.
- Document delegation, contrib-filter limitations, and out-of-scope production guarantees.

## Task 1: Infrastructure and PKI

Files: `compose.yaml`, `docker/pki/*`, `docker/pgbouncer/Dockerfile`, `config/{envoy,pgbouncer,pgdog,postgres}/*`, `scripts/render.py`, `tests/security.py`.

- [ ] Write live security tests before implementation: both roles through both loopback ports return their own login identity and TLS=true; cross-role login must fail while control login succeeds. Negative backend tests require exact auth or certificate failures.
- [ ] Run test with missing stack and confirm it fails availability, not passes denials.
- [ ] Implement one-shot certificate provisioning using cryptography, per-service volumes and distinct CA domains. Bootstrap fresh PostgreSQL roles/data and allowlists. Build pinned PgBouncer release with checksum verification.
- [ ] Render Envoy's two listeners with `upstream_ssl: REQUIRE` and `UpstreamStartTlsConfig`; no default certificate verification assumptions.
- [ ] Run `docker compose config --quiet`, boot actual containers, inspect failures, then execute `docker compose --profile test run --rm security-tests`.

## Task 2: App API and UI

Files: `app/*`, `app/static/*`, `tests/test_app.py`.

Consumes the schema, ports and API contract in the spec. Produces same-origin UI on port 8080 and bounded `/api/events`.

- [ ] Write tests for invalid action/pooler rejection, outage vs denial classification, bounded logs, and HTTP origin protections.
- [ ] Implement named psycopg actions with explicit transactions, connect timeout, statement timeout, role/TLS evidence, and no supplied passwords. Do not accept arbitrary SQL/host/role.
- [ ] Implement UI pooler selector, individual test buttons, run-all flow, current/session role display, readable evidence and event feed. Use textContent for untrusted strings.
- [ ] Run unit tests then real API actions through both apps/poolers; review in the browser.

## Task 3: Delivery and evidence

Files: `README.md`, `docs/IMPLEMENTATION.md`, `docs/SECURITY.md`, `Makefile`, `.github/workflows/demo.yml`, `.env.example`.

- [ ] Document exact setup, architecture diagram, certificate and role mappings, lifecycle commands, test matrix, and known limits; cite primary upstream docs and versioned source.
- [ ] Add CI that boots stack, runs unit/security/API integration tests, and collects service logs on failure.
- [ ] Perform independent review, address material findings, cold-start test, browser check, and secret scan.
- [ ] Commit and create/push a private GitHub repository by default because visibility was unspecified. Verify remote commit and provide repository/UI/document links.
