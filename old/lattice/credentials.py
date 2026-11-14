"""Credential loading for daemon operations and CLI key management."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lattice.crypto import load_private_key, save_private_key


class CredentialError(ValueError):
    """Raised when a required credential cannot be loaded."""


# Default paths used by systemd's LoadCredential=/LoadCredentialEncrypted=.
# In a systemd service these resolve to /run/credentials/lattice.service/.
DEFAULT_CREDENTIAL_DIR = Path("/run/credentials/lattice.service")


def _read_credential_file(name: str, path: Path | None) -> bytes:
    """Read a credential from ``path`` or from the systemd credential directory."""
    target = path if path is not None else DEFAULT_CREDENTIAL_DIR / name

    if not target.exists():
        raise CredentialError(f"credential file not found: {target}")
    return target.read_bytes()


def load_credential(
    name: str,
    *,
    path: Path | str | None = None,
) -> bytes:
    """Load a raw credential by name.

    In production the credential is provided by systemd credentials. For
    development or testing, an explicit path may be supplied.
    """
    resolved_path = Path(path) if path is not None else None
    return _read_credential_file(name, resolved_path)


def load_operational_key(
    *,
    path: Path | str | None = None,
    password: bytes | None = None,
) -> Ed25519PrivateKey:
    """Load the daemon operational private key from a credential."""
    data = load_credential("operational_key", path=path)
    key = load_private_key(data, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise CredentialError("operational_key is not an Ed25519 private key")
    return key


def load_webhook_bearer(
    *,
    path: Path | str | None = None,
) -> str:
    """Load the loopback webhook bearer token from a credential."""
    data = load_credential("webhook_bearer", path=path)
    return data.decode("utf-8").strip()


def load_admin_bearer(
    *,
    path: Path | str | None = None,
) -> str:
    """Load the local admin API bearer token from a credential."""
    data = load_credential("admin_bearer", path=path)
    return data.decode("utf-8").strip()


def save_root_key(
    key: Ed25519PrivateKey,
    path: Path | str,
    password: bytes,
) -> None:
    """Encrypt and save the root private key to ``path``."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = save_private_key(key, password=password)
    path.write_bytes(data)
    path.chmod(0o600)


def load_root_key(
    path: Path | str,
    password: bytes,
) -> Ed25519PrivateKey:
    """Load and decrypt the root private key from ``path``."""
    path = Path(path)
    if not path.exists():
        raise CredentialError(f"root key not found: {path}")
    data = path.read_bytes()
    key = load_private_key(data, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise CredentialError("root key is not an Ed25519 private key")
    return key
