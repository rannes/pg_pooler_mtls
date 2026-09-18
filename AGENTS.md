# Working on this repository

This is a local passwordless PostgreSQL identity demonstration with two apps, Envoy sidecars, PgBouncer, PgDog, and one PostgreSQL database. Read `README.md`, `docs/IMPLEMENTATION.md`, and `docs/SECURITY.md` before changing behavior. The original scope is recorded under `docs/superpowers/specs/` and `docs/superpowers/plans/`.

## Source ownership

- `compose.yaml`: network namespaces, internal bridges, mounts, service dependencies, loopback HTTP publication, image versions.
- `docker/pki/`: offline CA/leaf provisioning and deliberately invalid test credentials.
- `config/envoy/`: app-local loopback listeners and PostgreSQL STARTTLS with upstream verification.
- `config/nginx.conf`: fixed shared HTTP ingress routes; the `ui` service publishes both host-loopback interfaces.
- `config/pgbouncer/`, `config/pgdog/`: frontend identity authorization and backend gateway TLS.
- `config/postgres/`: certificate gateway maps, HBA rules, SQL roles and grants, first-run schema initialization.
- `app/`: fixed-purpose API/probes, UI, actual attempt feed, safe result/error classification.
- `tests/`, `Makefile`, `.github/workflows/`: unit and live verification.

## Security invariants

1. Apps have no password or certificate/private-key mount. Do not mount the Docker socket, CA-private volume, or test credentials into an app.
2. An app shares only its own Envoy network namespace. PostgreSQL remains on the backend bridge; only poolers join both frontend and backend networks in the runtime stack.
3. Host publication is limited to loopback HTTP on nginx `ui`. Only nginx joins the ordinary `web` bridge; it also joins both app bridges, but has no backend membership or keys. Apps/Envoys remain internal-only. Envoy PostgreSQL listeners remain loopback-only, and no Envoy admin endpoint is exposed. Do not claim that the unauthenticated shared UI enforces per-caller workload isolation.
4. Envoy uses the PostgreSQL contrib filter with required upstream STARTTLS and an upstream starttls transport socket. Verify the pooler's CA and exact DNS SAN. Preserve the documented non-hardened limitation.
5. A trusted workload certificate must match the requested app role at each pooler. CA trust alone is insufficient. Do not use TCP `trust`, permissive identity maps, password fallback for these users, or a forced shared backend username. PgDog v0.1.59 needs its documented non-secret `server_password=""` sentinel to attempt a certificate-authenticated backend connection; preserve it until an upgrade is verified. Its virtual admin path uses a separate startup-generated random password; never introduce well-known admin credentials.
6. Each pooler uses its own backend gateway certificate and verifies the PostgreSQL server. PostgreSQL trusts the gateway CA, not the workload CA, and maps gateways only to allowed app roles/database.
7. Preserve both `current_user` and `session_user` as the authorized app role. PostgreSQL sees a gateway certificate; never describe that as original certificate forwarding.
8. App SQL privileges remain separate from login authentication. Use the NOLOGIN owner and explicit grants; do not grant app superuser, owner membership, or cross-role membership to make a test pass.
9. Negative tests need healthy controls and narrow error classification. An unavailable service, generic EOF/reset, or missing table is not an authorization denial. Direct DB isolation requires the numeric address as well as DNS.
10. The API stays closed to arbitrary SQL, network targets, caller-supplied roles, and credentials. Preserve same-origin/browser guards and safe DOM text rendering.

## Verification and maintenance

Run `docker compose config --quiet` after Compose/config edits. Boot with `docker compose up --build -d --wait`, then use `make test` for the complete verification entry point. `docker compose --profile test run --rm security-tests` runs the privileged live certificate/backend suite separately. App liveness and container startup do not establish security correctness.

For behavior changes, add or adjust a test for the boundary being changed. Exercise both apps and both poolers when changing identities, database grants, TLS, error classification, or connection setup. Preserve explicit transactions around SQL actions and their identity/TLS evidence.

Keep the direct database IP synchronized between Compose's static PostgreSQL address and app probe configuration. Run isolation probes inside the apps, not inside the deliberately backend-connected test runner.

Do not edit dependency versions or release checksums opportunistically. For an intended upgrade, inspect primary upstream documentation and version-tagged code when necessary, update pins together, and rerun the full live matrix. PgDog's certificate identity and auth behavior is version-specific; the manual links v0.1.59 source.

Initialization SQL executes only for a fresh database volume. Use a migration for retained data or explicitly identify a reset as destructive. `docker compose down` preserves data. `docker compose down --volumes --remove-orphans` deletes notes, CAs, leaf keys, and test credentials; never run it against retained user data without authorization.

PKI provisioning is idempotent and local leaf certificates expire after 30 days. Do not claim it implements automatic renewal, revocation, or online rotation. Do not print private keys or export credentials to Git. The bootstrap password file is local initialization plumbing; SQL clears the PostgreSQL role password immediately, and runtime TCP auth remains certificate-only.

## Extending the demo

For a new workload, update its namespace/service, PKI leaf, both pooler identity allowlists, backend role map, SQL grants, app identity validation, UI, and cross-role tests together. For a new pooler, use a separate gateway identity and run the same matrix against the same database before making comparison claims.

Document actual evidence and material limitations. UI events are actual app attempts/SQL results, not aggregated service logs; use `docker compose logs` for raw logs. Do not invent screenshots, measurements, test passes, or production guarantees. This scope is pooling-only against one PostgreSQL instance, with no sharding, HA, or performance claim.
