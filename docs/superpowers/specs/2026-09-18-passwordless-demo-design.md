# Passwordless pooler identity demo

## Objective and authority

Build and run the user's requested two-app Docker Compose demo, write a complete implementation manual, verify the security claims, and push to GitHub. The user explicitly requested autonomous implementation. The initially supplied ChatGPT link redirected to the homepage; the matching conversation, “Compare Postgres sharding solutions”, was located through ChatGPT search and read. Its core requirement is delegated, passwordless certificate-to-role authorization with both PgBouncer and PgDog.

## Architecture

Two instances of one Python web app, each sharing only its own Envoy's network namespace. The app connects to loopback port 15432 (PgBouncer) or 15433 (PgDog), with `sslmode=disable`, a requested username and no password. Envoy holds the app certificate and uses the PostgreSQL contrib filter with upstream STARTTLS REQUIRE. Envoy checks the pooler's CA and DNS SAN. Each pooler requires a workload certificate and authorizes it for app1 or app2. Each pooler connects to PostgreSQL over verified TLS with its own gateway certificate. PostgreSQL maps each gateway CN to app1/app2 only. There is no forced backend user.

Networks: separate internal app1/app2 frontend bridges, shared by the respective Envoy and both poolers; one internal database bridge shared only by PostgreSQL and poolers. App processes have no certificate/private key mount. Envoy listeners and admin are loopback only. Only HTTP ports 8081 and 8082 are published, bound to host 127.0.0.1. Direct DB probes use both DNS and a configured numeric backend IP to avoid confusing failed name resolution with isolation.

Use fresh local CAs for workload, pooler-server, backend-client and database-server trust domains. Init service generates leaf keys into per-service volumes; CA signing keys remain on an unmounted CA volume. All keys remain outside Git. Dedicated negative-test certificate material is mounted only in a one-shot test container.

## Demonstrable claims

- app1 and app2 succeed through both poolers; current_user and session_user match the requested authorized role.
- Both identities read/write only their own schema. Cross-schema reads and SET ROLE are denied by PostgreSQL.
- A valid app1 certificate requesting app2 is denied, and vice versa.
- Direct pooler plaintext and TLS without a certificate are denied.
- Direct DB DNS and IP access from each app is unavailable; service health is checked separately so outages cannot count as security success.
- On the backend network, DB TLS/certificate rules deny missing certificates, workload certificates, and gateway requests for an unauthorized role.
- Repeated concurrent app transactions show no role leakage. TLS evidence shows a gateway certificate at PostgreSQL, never claims end-to-end certificate forwarding.

## API contract and schema

`APP_ID=app1|app2`, `OTHER_APP_ID`, `UI_PORT=8080`, `DIRECT_DB_IP=172.30.83.10`. Backend selects pooler via explicit enum. `GET /healthz` is process liveness. `GET /api/config` returns app metadata and available actions. `POST /api/run` takes `{pooler: "pgbouncer"|"pgdog", action: "identity"|"read"|"write"|"impersonate"|"cross_read"|"set_role"|"direct_db"|"direct_pooler_plain"|"direct_pooler_tls"}`. `GET /api/events` returns a bounded log of actual attempts. Only named actions; no arbitrary SQL, targets, or credentials accepted. Responses include `outcome` (allowed/blocked/error/unexpected), `expected`, `passed`, `evidence`, duration, request_id, action, app and pooler. Expected denials require the appropriate error class/SQLSTATE, never arbitrary exceptions.

Database `productdb`; login roles app1/app2 without passwords and without role membership. Schemas app1/app2 each contain `notes(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, body text NOT NULL, created_at timestamptz DEFAULT now())`. Owners are a separate NOLOGIN role; each app gets USAGE plus SELECT/INSERT only on its schema and sequence. Identity query returns session_user/current_user, backend PID, database, inet_server_addr(), and its own pg_stat_ssl row including ssl/version/client_dn. Use explicit transactions so a transaction pool cannot change backend between the identity and evidence queries.

## UI and logs

Light cool slate canvas #eef3f7, deep blue text #16324a, white work surface #ffffff, blue action #245edb, teal success #087f75, red denial #b64040. System sans type; monospace for SQL and raw evidence only. Full-width connection-path diagram is the signature element; below it, an action workbench beside an evidence panel and bounded live attempt feed. App1/App2 distinguished by name and restrained accent. Keyboard focus and mobile layout required. Logs are real app attempt events and SQL/TLS results, clearly labeled; service logs remain available via Docker Compose without exposing the Docker socket to web apps.

## Scope and limits

This is a local demonstrator, not production certification. Envoy's PostgreSQL contrib filter is not hardened. Poolers are trusted identity delegates. Docker/host administrators can defeat network isolation and inspect keys. Single PostgreSQL instance, pooling only; no sharding, HA, production PKI automation, revocation, or online rotation claims. Both poolers included together for comparison, not chained.

## Acceptance

Cold `docker compose up --build -d --wait` succeeds. `make test` executes positive and adversarial checks against live services and fails on unexpected outcomes. Browser actions work in both UIs. No secret files are committed. CI performs the same live integration checks. Full manual covers setup, architecture, exact mappings, testing, troubleshooting, reset, risks and agent extension steps.
