from __future__ import annotations

import os
import ssl
import subprocess
from pathlib import Path


def prepare_server_context(
    certfile: Path,
    keyfile: Path,
    *,
    auto_generate: bool = False,
) -> ssl.SSLContext:
    if auto_generate:
        _ensure_self_signed_certificate(certfile, keyfile)
    if not certfile.is_file() or not keyfile.is_file():
        raise ValueError(
            "TLS requires both LOGSERVER_TLS_CERTFILE and LOGSERVER_TLS_KEYFILE to exist"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    return context


def _ensure_self_signed_certificate(certfile: Path, keyfile: Path) -> None:
    if certfile.is_file() and keyfile.is_file():
        return
    if certfile.exists() or keyfile.exists():
        raise ValueError("Refusing to replace an incomplete TLS certificate/key pair")
    if certfile.parent != keyfile.parent:
        raise ValueError("Automatically generated TLS certificate and key must share a directory")

    certfile.parent.mkdir(parents=True, exist_ok=True)
    temporary_cert = certfile.with_suffix(certfile.suffix + ".new")
    temporary_key = keyfile.with_suffix(keyfile.suffix + ".new")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
                "-keyout", str(temporary_key), "-out", str(temporary_cert), "-days", "3650",
                "-subj", "/CN=LogServer",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
                "-addext", "extendedKeyUsage=serverAuth",
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(temporary_key, 0o600)
        os.replace(temporary_key, keyfile)
        os.replace(temporary_cert, certfile)
    except Exception:
        temporary_key.unlink(missing_ok=True)
        temporary_cert.unlink(missing_ok=True)
        raise
