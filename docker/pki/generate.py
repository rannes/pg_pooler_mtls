"""Idempotent demo CA/leaf provisioning into isolated Docker volumes.

Only this one-shot, offline container can read CA signing keys. Runtime services
receive the minimum leaf keys/trust roots they need. Test credentials are a
deliberately privileged fixture and never mounted into the web applications.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOW = datetime.now(timezone.utc)
ROOT = Path("/pki")


def write(path, data, uid=0, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(data)
    temp.chmod(0o600 if private else 0o644)
    os.chown(temp, uid, uid)
    temp.replace(path)


def key_bytes(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def cert_bytes(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def authority(name):
    folder = ROOT / name
    folder.mkdir(parents=True, exist_ok=True)
    folder.chmod(0o700)
    if (folder / "ca.key").exists():
        return (serialization.load_pem_private_key((folder / "ca.key").read_bytes(), None),
                x509.load_pem_x509_certificate((folder / "ca.crt").read_bytes()))
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Demo {name} CA")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(minutes=5)).not_valid_after(NOW + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    write(folder / "ca.key", key_bytes(key), private=True)
    write(folder / "ca.crt", cert_bytes(cert))
    return key, cert


def leaf(folder, name, ca, uid=10001, server=False, expired=False, prefix="tls"):
    key_path, cert_path = folder / f"{prefix}.key", folder / f"{prefix}.crt"
    if cert_path.exists() and key_path.exists():
        return
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca[1].subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=3) if expired else NOW - timedelta(minutes=5))
            .not_valid_after(NOW - timedelta(days=1) if expired else NOW + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .sign(ca[0], hashes.SHA256()))
    write(key_path, key_bytes(key), uid, private=True)
    write(cert_path, cert_bytes(cert), uid)


def main():
    cas = {name: authority(name) for name in ("workload", "pooler", "gateway", "database", "rogue")}
    tests = Path("/out/tests")
    for app in ("app1", "app2"):
        folder = Path("/out") / app
        leaf(folder, f"{app}.internal", cas["workload"])
        write(folder / "pooler-ca.crt", cert_bytes(cas["pooler"][1]))
        for suffix in ("crt", "key"):
            write(tests / f"{app}.{suffix}", (folder / f"tls.{suffix}").read_bytes(), 10001, suffix == "key")
    for pooler in ("pgbouncer", "pgdog"):
        folder = Path("/out") / pooler
        leaf(folder, pooler, cas["pooler"], server=True, prefix="server")
        leaf(folder, f"{pooler}-gateway", cas["gateway"], prefix="gateway")
        for root in ("workload", "database"):
            write(folder / f"{root}-ca.crt", cert_bytes(cas[root][1]))
        for suffix in ("crt", "key"):
            write(tests / f"{pooler}-gateway.{suffix}", (folder / f"gateway.{suffix}").read_bytes(), 10001, suffix == "key")
    folder = Path("/out/postgres")
    leaf(folder, "postgres", cas["database"], uid=999, server=True)
    write(folder / "gateway-ca.crt", cert_bytes(cas["gateway"][1]))
    # Official-image bootstrap only. SQL initialization immediately removes this
    # superuser password; no TCP HBA rule permits password authentication.
    if not (folder / "bootstrap-password").exists():
        write(folder / "bootstrap-password", secrets.token_urlsafe(48).encode(), 999, private=True)
    for root in ("pooler", "database"):
        write(tests / f"{root}-ca.crt", cert_bytes(cas[root][1]))
    leaf(tests, "app1.internal", cas["workload"], expired=True, prefix="expired")
    leaf(tests, "app1.internal", cas["rogue"], prefix="rogue")
    leaf(tests, "unmapped.internal", cas["workload"], prefix="unmapped")
    print(json.dumps({"pki": "ready", "leaf_lifetime_days": 30, "keys": "isolated service volumes"}))


if __name__ == "__main__":
    main()
