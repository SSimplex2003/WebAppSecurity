"""Run the app over HTTPS for local development.

Creates a self-signed certificate for localhost on first run (stored in the
git-ignored `certs/` folder at the repository root), then starts uvicorn with it.
"""

import datetime
import ipaddress
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BACKEND_DIR = Path(__file__).resolve().parent
CERT_DIR = BACKEND_DIR.parent / "certs"
CERT_FILE = CERT_DIR / "localhost.pem"
KEY_FILE = CERT_DIR / "localhost-key.pem"
HOST = "127.0.0.1"
PORT = 8443


def ensure_certificate() -> None:
    if CERT_FILE.exists() and KEY_FILE.exists():
        return

    CERT_DIR.mkdir(exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    CERT_FILE.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"Created a self-signed certificate in {CERT_DIR}")


def main() -> None:
    ensure_certificate()
    print(f"Serving on https://localhost:{PORT} (self-signed certificate: accept the browser warning)")
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        ssl_keyfile=str(KEY_FILE),
        ssl_certfile=str(CERT_FILE),
        app_dir=str(BACKEND_DIR),
    )


if __name__ == "__main__":
    main()
