# Security model and acceptance matrix

This lab separates three questions: **which identity connected**, **what that identity may do**, and **whether a connection can reach the target**. Passing one check does not establish the other two. The repository demonstrates these boundaries for two known workloads, two alternative poolers, and one PostgreSQL database.

## Trust assumptions

The host, Docker daemon, image/build inputs, configuration, PKI init process, HTTP ingress, sidecars, and poolers are trusted. Docker/host administrators can enter containers, attach networks, read volume data, replace images, or change the security policy. This demo does not defend against them.

Each app can open arbitrary network connections within its own namespace and choose a PostgreSQL startup username; its certificate is held by its Envoy. The fixed UI exposes representative attacks, while the privileged integration suite supplies invalid and unauthorized certificates directly. A compromised app can use its local Envoy to act as its authorized role. Keeping keys out of the app limits key possession; it does not prevent that app from using its own identity.

Each pooler holds a gateway certificate authorized to request both `app1` and `app2`. It is consequently an identity-delegation trust boundary. A compromised pooler can use either app role and access both schemas with their granted privileges. Backend mappings still exclude `postgres`, `demo_owner`, and other roles. Do not call this end-to-end workload certificate authentication.

## Authentication, authorization, and isolation

| Boundary | Authentication | Authorization | Network restriction |
| --- | --- | --- | --- |
| Browser → nginx → app | No individual HTTP user authentication | Only fixed named demo actions | Host-loopback publication; nginx joins both app bridges but no backend |
| App → Envoy | No client TLS; workload access is bound to its namespace | Local listener selects pooler, not DB privileges | Listener is loopback within that app's namespace |
| Envoy → pooler | mTLS; pooler validates workload CA; Envoy validates pooler CA and DNS SAN | PgBouncer map or PgDog user identity binds certificate to requested role/database | Each Envoy joins only its app bridge |
| Pooler → PostgreSQL | mTLS; DB validates gateway CA; pooler verifies database CA/hostname | Gateway map permits only `app1`/`app2` on `productdb` | PostgreSQL joins only backend bridge |
| SQL session → data | Authenticated database role already established | Schema/table/sequence grants; no cross-role membership | Not a network decision |

Certificate validation proves possession of a key belonging to an accepted certificate. It does not automatically authorize every username in a PostgreSQL startup message. That is why each frontend has an explicit certificate-to-role map and the backend has its own constrained gateway map.

Likewise, mTLS does not make PostgreSQL unreachable. Docker network membership supplies that restriction; direct authentication checks are tested independently from a container that can reach the backend.

## Exact identity policy

| Presented workload identity | Requested role | PgBouncer | PgDog |
| --- | --- | --- | --- |
| `app1.internal` | `app1` | Allow | Allow |
| `app1.internal` | `app2` | Deny | Deny |
| `app2.internal` | `app2` | Allow | Allow |
| `app2.internal` | `app1` | Deny | Deny |
| Trusted but `unmapped.internal` | Either app role | Deny | Deny |
| Missing, expired, or rogue-CA certificate | Either app role | Deny | Deny |

PgBouncer maps the certificate CN. PgDog v0.1.59 takes the first DNS SAN, falling back to CN; generated workload leaves put the same value in both. Confirm this behavior against the pinned [PgDog TLS implementation](https://github.com/pgdogdev/pgdog/blob/v0.1.59/pgdog/src/net/tls.rs) when upgrading.

| Presented backend certificate | Requested role/database | PostgreSQL policy |
| --- | --- | --- |
| `pgbouncer-gateway` from gateway CA | `app1` or `app2` / `productdb` | Allow |
| `pgdog-gateway` from gateway CA | `app1` or `app2` / `productdb` | Allow |
| Either gateway | `postgres` or other unauthorized role | Deny |
| Workload certificate | Either app role | Deny: wrong trust domain |
| No certificate, or plaintext | Any role | Deny |

The original workload certificate terminates at the pooler. PostgreSQL's `pg_stat_ssl.client_dn` reports the gateway CN. `current_user` and `session_user` report the app role because the poolers preserve its backend login name. Neither result implies that PostgreSQL verified the original workload certificate.

PostgreSQL certificate authentication uses the requested role and configured identity map; see the [PostgreSQL 17 certificate authentication documentation](https://www.postgresql.org/docs/17/auth-cert.html). The local superuser maintenance path uses OS peer authentication, with no TCP administrator access.

## Password and key handling

Apps have no certificate/private-key volume, supplied database password, password file, or Docker socket. PostgreSQL TCP rules do not enable password authentication. PgBouncer's two empty userlist fields declare users for its cert-auth policy. PgDog's configured SCRAM fallback is not used by its mandatory-certificate app identities.

PgDog v0.1.59 needs `server_password=""` as a non-secret empty backend connection candidate; omitting it prevents that version from opening the certificate-authenticated backend connection. PostgreSQL's NULL role passwords and certificate-only HBA ensure the value is not a usable password. The [implementation manual](IMPLEMENTATION.md#pgdog-authorization) explains the version-specific code path.

PgDog's virtual administration path is separate: this demo leaves its startup-generated random admin password in place and makes no claim of certificate-only administration. The admin path has no host-published database port. Do not configure well-known admin credentials when adapting the lab.

For official-image initialization, a random bootstrap password is generated locally and passed to PostgreSQL through a volume file. Initialization immediately sets the `postgres` role password to NULL; the file itself remains in its volume. App roles are created with NULL passwords. This bootstrap detail is not a runtime password-authentication mechanism.

Four independent runtime CA domains separate workload, pooler-server, gateway-client, and database-server trust. CA signing keys are available only to the offline init container. Runtime leaf mounts are read-only and per service. The test profile has a deliberately privileged fixture volume with workload and gateway key copies; it must remain separate from web applications.

Leaf certificates expire after 30 days. Provisioning is idempotent, with no renewal loop, revocation checks, online rotation procedure, external secret manager, or HSM. Deleting all demo volumes creates a new local PKI and destroys database data. It is a reset, not a rotation strategy.

## Required negative tests

The following matrix describes required outcomes, not a stored test run. Use `make test` on the checkout to obtain current results.

| Check | Where executed | Required evidence | What it establishes |
| --- | --- | --- | --- |
| Both app roles through both poolers | UI/API and privileged security suite | Correct `current_user`, `session_user`, `productdb`, SSL, gateway CN | Authorized paths are working |
| Own-schema SELECT and INSERT | Each app, each pooler | Actual returned/inserted note | Intended SQL privileges work |
| Valid app certificate asks for other role | Each app, each pooler; certificate suite | Specific authentication denial plus healthy authorized control | Certificate-to-role authorization |
| Cross-schema read | Each app, each pooler | SQLSTATE `42501` plus healthy control | PostgreSQL schema/table authorization |
| `SET ROLE` to other app | Each app, each pooler | SQLSTATE `42501` plus healthy control | No cross-role privilege membership |
| Pooler plaintext connection | Each app and certificate suite | Explicit TLS/authentication refusal with live control | TLS required on frontend |
| Pooler TLS without client certificate | Each app and certificate suite | Explicit certificate-required refusal with live control | Certificate required for app login |
| Expired certificate | Privileged security suite | Certificate/auth refusal; valid certificate still works | Expiration rejection |
| Rogue-CA certificate | Privileged security suite | Certificate/auth refusal; valid certificate still works | Issuer trust restriction |
| Trusted but unmapped certificate | Privileged security suite | Identity/auth refusal; valid identity still works | Trust does not imply role permission |
| Unauthorized database name | Privileged security suite | Database/auth refusal with valid `productdb` control | Configured database allowlist |
| Direct DB by name and numeric IP | Each app's actual namespace | Numeric TCP attempt unreachable and selected pooler reaches the live DB | App/backend network separation |
| Backend plaintext or no certificate | Privileged suite on backend bridge | PostgreSQL HBA/certificate refusal with a working gateway control | DB independently enforces TLS/client authentication |
| Workload cert presented to DB | Privileged suite on backend bridge | Certificate refusal with working gateway control | Separate client CA trust domains |
| Gateway asks for `postgres` | Privileged suite on backend bridge | HBA/certificate refusal with authorized app-role control | Backend delegation is constrained |
| Concurrent mixed-role transactions | Privileged suite | Every result retains its requested role and gateway identity | No role leakage observed in tested workload |

An outage cannot count as an authentication denial. Arbitrary timeouts, refused pooler connections, resets, EOF, and missing relations are errors. The application records raw errors and successful controls. A network isolation test is different: a numeric TCP timeout/unreachable/refused result can be expected only when the target is the configured database and a control concurrently reaches that same live database through the selected pooler. DNS failure alone is insufficient.

The certificate suite is intentionally connected to the backend, so its ability to reach PostgreSQL does not contradict app isolation. App isolation must be tested from the app namespaces.

## Local HTTP surface and logs

Only host-loopback HTTP ports are published by the shared nginx `ui` service. nginx joins an ordinary `web` network plus the two internal app bridges; it has no backend membership or certificate mounts. Apps and Envoys remain on their respective internal bridges. nginx forwards only fixed HTTP routes, preserving the browser Host header.

The UI has no user login; anyone able to reach its endpoints can trigger named app actions. This includes the trusted ingress and potentially other containers with access to it. Database role separation is not HTTP caller authentication: the demo does not prevent a caller that can reach App 2's UI from asking App 2 to execute an authorized App 2 action. It is not intended as a public or adversarial multi-user web service. Browser POST protections check Origin/Fetch Metadata and JSON content type; Host validation, CSP, and safe text rendering constrain browser use.

The HTTP API accepts an enum action and pooler, not SQL, a database host, certificates, passwords, or a caller-supplied role. Writes generate a bounded-format note server-side. SQL identifiers are safely composed. The event buffer holds only the latest 100 events per process, with truncated error text, and resets on restart.

UI events are application attempt records and SQL/TLS evidence. They do not claim to mirror every upstream log. Inspect raw service logs with:

```sh
docker compose logs --tail=100 ui envoy-app1 envoy-app2 pgbouncer pgdog postgres
```

No Docker socket is exposed to the web application to implement log viewing. Query bodies, role names, certificate subjects, and note contents can appear in app evidence; treat any exported demonstration logs accordingly.

## Limits that remain after a passing run

- Envoy 1.39.1's PostgreSQL proxy filter is a contrib extension, explicitly not hardened, with a work-in-progress API outside upstream's supported security threat model. Read the [versioned Envoy warning](https://www.envoyproxy.io/docs/envoy/v1.39.1/api-v3/extensions/filters/network/postgres_proxy/v3alpha/postgres_proxy.proto).
- Plaintext exists on app/Envoy loopback. The app namespace and sidecar are trusted; this is not encryption within a compromised workload.
- Poolers terminate workload TLS and establish gateway TLS. They can act as both allowed app roles. PostgreSQL does not independently attest the original workload.
- Docker bridges and loopback bindings are local development controls. Host administrators, daemon access, changed firewall rules, or privileged containers can bypass them.
- Version tags/digests and the PgBouncer release checksum limit accidental drift. They are not a complete supply-chain security program.
- A finite concurrent test provides evidence for that run, not a general proof against every transaction-state leak or protocol exploit.
- There is one PostgreSQL instance. The demo uses pooling only and does not validate sharding, HA, failover, production performance, RLS, multi-tenant HTTP access, disaster recovery, certificate revocation, or online rotation.

When reporting a finding, include the source commit, selected app/pooler/action, a minimal reproduction, relevant redacted logs, and whether the healthy control succeeded. Do not attach private keys or the privileged fixture volume.
