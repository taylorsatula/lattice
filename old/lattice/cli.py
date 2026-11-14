"""Lattice operator command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import uvicorn

from lattice.addressing import NODE_ID_RE, AddressError, parse_address
from lattice.api import create_app
from lattice.canonical import canonicalize, signature_preimage
from lattice.config import ConfigError, load_config, render_default_config
from lattice.credentials import (
    CredentialError,
    load_admin_bearer,
    load_operational_key,
    load_root_key,
    load_webhook_bearer,
    save_root_key,
)
from lattice.crypto import (
    SignatureError,
    generate_private_key,
    load_private_key,
    load_public_key_b64url,
    public_key_b64url,
    save_private_key,
    sign,
)
from lattice.encoding import b64url_encode
from lattice.identity import (
    IdentityError,
    OperationalCertificate,
    OperationalIdentity,
    RootIdentity,
    create_operational_certificate,
    node_id_from_public_key_b64url,
    sign_with_root,
    verify_object,
    verify_transfer,
)
from lattice.network_policy import NetworkPolicy
from lattice.protocol.models import WellKnownDocument
from lattice.resolution import ResolutionError, WellKnownResolver
from lattice.runtime import RuntimeCoordinator
from lattice.storage.cache import initialize_cache_db
from lattice.storage.connection import open_connection
from lattice.storage.migrations import MigrationError, migrate
from lattice.storage.repositories import ContactRepository, DomainPinRepository
from lattice.transport import OutboundTransport

DEFAULT_CONFIG_PATH = Path("/etc/lattice/config.toml")
DEFAULT_STATE_DIR = Path("/var/lib/lattice")
DEFAULT_CACHE_DIR = Path("/var/cache/lattice")


class CLIError(RuntimeError):
    """Raised for CLI-level errors with actionable messages."""


def _read_password(prompt: str = "Password: ") -> bytes:
    password = getpass.getpass(prompt)
    if not password:
        raise CLIError("password cannot be empty")
    return password.encode("utf-8")


def _confirm_password(password: bytes) -> None:
    again = getpass.getpass("Confirm password: ").encode("utf-8")
    if password != again:
        raise CLIError("passwords do not match")


def _state_paths(
    config_path: Path,
    state_dir: Path | None = None,
    cache_dir: Path | None = None,
) -> tuple[Path, Path]:
    """Derive durable and cache database paths."""
    base_state = state_dir or DEFAULT_STATE_DIR
    base_cache = cache_dir or DEFAULT_CACHE_DIR
    return (base_state / "lattice.durable.db", base_cache / "lattice.cache.db")


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new Lattice node."""
    config_path = Path(args.config)
    if config_path.exists() and not args.force:
        raise CLIError(f"config already exists: {config_path}; use --force to overwrite")

    domain: str = args.domain
    public_base_url: str = args.public_base_url

    config_dir = config_path.parent
    root_key_path = config_dir / "root_key.pem"

    # Root key: reuse the existing one when asked (the identity-preserving
    # recovery path) or mint a fresh one — but never silently overwrite an
    # existing root key: that orphans every peer pin for the old node ID.
    # --force only licenses config/operational/bearer overwrite.
    if getattr(args, "reuse_root_key", False):
        if not root_key_path.exists():
            raise CLIError(f"--reuse-root-key: no root key found at: {root_key_path}")
        password = _read_password("Root key password: ")
        root_key = load_root_key(root_key_path, password)
    else:
        if root_key_path.exists():
            raise CLIError(
                f"root key already exists: {root_key_path}; use --reuse-root-key "
                "to preserve this node's identity, or remove the file to mint "
                "a new one (--force does not license root key overwrite)"
            )
        root_key = generate_private_key()

    op_key = generate_private_key()

    root_identity = RootIdentity.from_public_key(root_key.public_key())
    node_id = root_identity.node_id

    now = datetime.now(UTC)
    cert = create_operational_certificate(
        root_key=root_key,
        operational_public_key=op_key.public_key(),
        sequence=1,
        valid_from=now,
        valid_until=now + timedelta(days=30),
    )

    # Prompt for root key password and encrypt.
    print(f"Initializing Lattice node {node_id} for domain {domain}")
    if not getattr(args, "reuse_root_key", False):
        password = _read_password("Enter root key encryption password: ")
        _confirm_password(password)

    config_dir.mkdir(parents=True, exist_ok=True)

    # Stage operational key and bearer as plaintext; operator encrypts with systemd-creds.
    op_key_path = config_dir / "operational_key.pem"
    op_key_path.write_bytes(save_private_key(op_key))
    op_key_path.chmod(0o600)

    webhook_bearer = "lwb_" + secrets.token_urlsafe(32)
    webhook_bearer_path = config_dir / "webhook_bearer"
    webhook_bearer_path.write_text(webhook_bearer, encoding="utf-8")
    webhook_bearer_path.chmod(0o600)

    admin_bearer = "lab_" + secrets.token_urlsafe(32)
    admin_bearer_path = config_dir / "admin_bearer"
    admin_bearer_path.write_text(admin_bearer, encoding="utf-8")
    admin_bearer_path.chmod(0o600)

    # Write identity manifest.
    manifest = {
        "node_id": node_id,
        "domain": domain,
        "root_public_key": public_key_b64url(root_key.public_key()),
        "operational_certificate": cert.to_dict(),
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    manifest_path = config_dir / "identity.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest_path.chmod(0o644)

    # Write config.
    config_text = render_default_config(domain, public_base_url)
    config_path.write_text(config_text, encoding="utf-8")
    config_path.chmod(0o640)

    # Write the root-signed well-known document the daemon will serve.
    base = public_base_url.rstrip("/")
    well_known: dict[str, object] = {
        "kind": "well_known",
        "node_id": node_id,
        "domain": domain.lower(),
        "root_public_key": public_key_b64url(root_key.public_key()),
        "operational_certificate": cert.to_dict(),
        "endpoints": {
            "gossip": f"{base}/lattice/v1/gossip",
            "messages": f"{base}/lattice/v1/messages",
        },
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    well_known = sign_with_root(root_key, well_known, "well_known")
    well_known_path = config_dir / "well-known.json"
    well_known_path.write_text(
        json.dumps(well_known, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    well_known_path.chmod(0o644)

    if getattr(args, "reuse_root_key", False):
        print(f"Root key reused from: {root_key_path} (node identity preserved)")
    else:
        save_root_key(root_key, root_key_path, password)
        print(f"Root key written to: {root_key_path} (mode 600)")
    print(f"Operational key staged at: {op_key_path} (encrypt with systemd-creds)")
    print(f"Webhook bearer staged at: {webhook_bearer_path} (encrypt with systemd-creds)")
    print(f"Admin bearer staged at: {admin_bearer_path} (encrypt with systemd-creds)")
    print(f"Identity manifest written to: {manifest_path}")
    print(f"Well-known document written to: {well_known_path}")
    print(f"Config written to: {config_path}")
    print()
    print("Next steps:")
    print("  1. Encrypt credentials with systemd-creds:")
    print(
        f"     sudo systemd-creds encrypt --name=operational_key "
        f"{op_key_path} {config_dir}/operational_key.cred"
    )
    print(
        f"     sudo systemd-creds encrypt --name=webhook_bearer "
        f"{webhook_bearer_path} {config_dir}/webhook_bearer.cred"
    )
    print(
        f"     sudo systemd-creds encrypt --name=admin_bearer "
        f"{admin_bearer_path} {config_dir}/admin_bearer.cred"
    )
    print("  2. Update your systemd service to use LoadCredentialEncrypted=.")
    print("  3. Delete the plaintext staging files.")
    return 0


def cmd_config_check(args: argparse.Namespace) -> int:
    """Validate the configuration file."""
    try:
        load_config(args.config)
    except ConfigError as exc:
        print(f"CONFIG INVALID: {exc}", file=sys.stderr)
        return 1
    print("Configuration is valid.")
    return 0


def cmd_upgrade(args: argparse.Namespace) -> int:
    """Run durable database migrations."""
    config_path = Path(args.config)
    durable_path, cache_path = _state_paths(
        config_path,
        state_dir=getattr(args, "state_dir", None),
        cache_dir=getattr(args, "cache_dir", None),
    )
    try:
        version = migrate(durable_path)
        print(f"Durable database migrated to version {version}.")
    except MigrationError as exc:
        print(f"MIGRATION FAILED: {exc}", file=sys.stderr)
        return 1

    try:
        conn = initialize_cache_db(cache_path)
        conn.close()
        print("Cache database initialized.")
    except Exception as exc:
        print(f"CACHE INITIALIZATION FAILED: {exc}", file=sys.stderr)
        return 1

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Print node status."""
    config_path = Path(args.config)
    durable_path, cache_path = _state_paths(
        config_path,
        state_dir=getattr(args, "state_dir", None),
        cache_dir=getattr(args, "cache_dir", None),
    )

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"CONFIG INVALID: {exc}", file=sys.stderr)
        return 1

    manifest_path = config_path.parent / "identity.json"
    if not manifest_path.exists():
        print("Node not initialized.")
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(f"domain: {manifest['domain']}")
    print(f"node_id: {manifest['node_id']}")
    print(f"public_base_url: {config.public_base_url}")
    print(f"durable_db: {durable_path}")
    print(f"cache_db: {cache_path}")
    return 0


def _load_local_identity(config_path: Path) -> OperationalIdentity:
    """Load the node's operational identity for CLI signing operations."""
    manifest_path = config_path.parent / "identity.json"
    if not manifest_path.exists():
        raise CLIError("Node not initialized.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cert = OperationalCertificate.from_dict(manifest["operational_certificate"])
    op_key = load_operational_key(path=_credential_path("operational_key", config_path.parent))
    return OperationalIdentity(node_id=cert.node_id, private_key=op_key, certificate=cert)


def cmd_contacts_export(args: argparse.Namespace) -> int:
    """Export a signed contact card for a local username."""
    config_path = Path(args.config)
    try:
        identity = _load_local_identity(config_path)
    except (CLIError, CredentialError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    username = args.username.strip().lower()
    if not username:
        print("username cannot be empty", file=sys.stderr)
        return 1

    card: dict[str, object] = {
        "kind": "contact_card",
        "username": username,
        "address": f"{username}@{identity.node_id}",
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if args.display_name:
        card["display_name"] = args.display_name
    if args.avatar_url:
        card["avatar_url"] = args.avatar_url
    signed = identity.sign_object(card, "contact_card")

    output_path = Path(args.output) if args.output else Path(f"{username}.contact.json")
    output_path.write_text(json.dumps(signed, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Contact card written to: {output_path}")
    return 0


def cmd_contacts_import(args: argparse.Namespace) -> int:
    """Import and verify a signed contact card into the contact book."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"contact card not found: {input_path}", file=sys.stderr)
        return 1
    card = json.loads(input_path.read_text(encoding="utf-8"))
    if card.get("kind") != "contact_card":
        print("input is not a contact card", file=sys.stderr)
        return 1
    if not isinstance(card.get("address"), str):
        print("contact card missing address", file=sys.stderr)
        return 1

    try:
        parsed = parse_address(str(card["address"]))
    except AddressError as exc:
        print(f"invalid contact address: {exc}", file=sys.stderr)
        return 1
    if parsed.node_id is None:
        print("contact address must be canonical (user@lat_...)", file=sys.stderr)
        return 1

    config_path = Path(args.config)
    durable_path, _cache_path = _state_paths(
        config_path,
        state_dir=getattr(args, "state_dir", None),
    )
    try:
        migrate(durable_path)
    except MigrationError as exc:
        print(f"MIGRATION FAILED: {exc}", file=sys.stderr)
        return 1

    conn = open_connection(durable_path)
    try:
        pin_repo = DomainPinRepository(conn)
        pin = pin_repo.get_by_node_id(parsed.node_id)
        if pin is None:
            print(
                f"node {parsed.node_id} is not pinned; resolve its domain first",
                file=sys.stderr,
            )
            return 1

        # Verify the card's operational signature against the pinned chain.
        root_key = load_public_key_b64url(str(pin["root_public_key"]))
        cert = OperationalCertificate.from_dict(pin["operational_certificate"])
        cert.verify(RootIdentity(node_id=parsed.node_id, public_key=root_key))
        if not cert.is_valid_at(datetime.now(UTC)):
            print(
                "pinned operational certificate is expired or not yet valid",
                file=sys.stderr,
            )
            return 1
        verify_object(cert.operational_public_key, card, "contact_card")

        username = str(card.get("username") or parsed.username).lower()
        display_name = card.get("display_name")
        avatar_url = card.get("avatar_url")
        contacts = ContactRepository(conn)
        contacts.upsert(
            node_id=parsed.node_id,
            username=username,
            domain=pin["domain"] if isinstance(pin.get("domain"), str) else None,
            display_name=display_name if isinstance(display_name, str) else None,
            avatar_url=avatar_url if isinstance(avatar_url, str) else None,
            root_public_key=str(pin["root_public_key"]),
            card_json=json.dumps(card, separators=(",", ":"), ensure_ascii=False),
            imported_at=datetime.now(UTC),
        )
    except (SignatureError, IdentityError) as exc:
        print(f"contact card signature invalid: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print(f"Imported contact {parsed.username}@{parsed.node_id}.")
    return 0


def cmd_contacts_list(args: argparse.Namespace) -> int:
    """List the contact book."""
    config_path = Path(args.config)
    durable_path, _cache_path = _state_paths(
        config_path,
        state_dir=getattr(args, "state_dir", None),
    )
    if not durable_path.exists():
        print("No contact book (run `lattice upgrade` first).", file=sys.stderr)
        return 1
    conn = open_connection(durable_path)
    try:
        rows = ContactRepository(conn).list_all()
    finally:
        conn.close()
    if not rows:
        print("No contacts.")
        return 0
    for row in rows:
        display = row["display_name"] or ""
        domain = row["domain"] or ""
        print(f"{row['username']}@{row['node_id']}  {domain}  {display}")
    return 0


def cmd_trust_reset_domain(args: argparse.Namespace) -> int:
    """Remove the durable pin for a domain (docs/ADDRESSING.md trust reset)."""
    config_path = Path(args.config)
    try:
        load_config(config_path)
    except ConfigError as exc:
        print(f"CONFIG INVALID: {exc}", file=sys.stderr)
        return 1

    durable_path, _cache_path = _state_paths(
        config_path,
        state_dir=getattr(args, "state_dir", None),
    )
    try:
        migrate(durable_path)
    except MigrationError as exc:
        print(f"MIGRATION FAILED: {exc}", file=sys.stderr)
        return 1

    conn = open_connection(durable_path)
    try:
        repo = DomainPinRepository(conn)
        repo.delete(args.domain)
    finally:
        conn.close()

    print(f"Removed pin for {args.domain.lower()}.")
    print("Re-verify the new binding out of band before sending.")
    return 0


def _transfer_signature_preimage(transfer: dict[str, object]) -> bytes:
    """Canonical preimage covered by both transfer signatures."""
    bare = {k: v for k, v in transfer.items() if k not in ("signature", "new_signature")}
    return signature_preimage("transfer", canonicalize(bare))


def cmd_keys_create_transfer(args: argparse.Namespace) -> int:
    """Create a root-signed transfer statement (old root side)."""
    config_path = Path(args.config)
    manifest_path = config_path.parent / "identity.json"
    if not manifest_path.exists():
        print("Node not initialized.", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    new_node_id = args.new_node_id.strip().lower()
    if not NODE_ID_RE.match(new_node_id):
        print(f"invalid new node ID: {new_node_id}", file=sys.stderr)
        return 1

    password = _read_password("Root key password: ")
    root_key = load_root_key(config_path.parent / "root_key.pem", password)

    now = datetime.now(UTC)
    transfer: dict[str, object] = {
        "kind": "transfer",
        "domain": args.domain.strip().lower(),
        "old_node_id": manifest["node_id"],
        "new_node_id": new_node_id,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    transfer["signature"] = b64url_encode(sign(root_key, _transfer_signature_preimage(transfer)))

    output_path = Path(args.output)
    output_path.write_text(json.dumps(transfer, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Transfer statement written to: {output_path}")
    print("Next: the new node's operator must co-sign it:")
    print(f"  lattice keys co-sign-transfer --input {output_path}")
    return 0


def cmd_keys_cosign_transfer(args: argparse.Namespace) -> int:
    """Add the new root's signature to a transfer statement (new root side)."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"transfer statement not found: {input_path}", file=sys.stderr)
        return 1
    transfer = json.loads(input_path.read_text(encoding="utf-8"))
    if transfer.get("kind") != "transfer":
        print("input is not a transfer statement", file=sys.stderr)
        return 1
    if "new_signature" in transfer:
        print("transfer statement is already co-signed", file=sys.stderr)
        return 1

    config_path = Path(args.config)
    manifest_path = config_path.parent / "identity.json"
    if not manifest_path.exists():
        print("Node not initialized.", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if transfer.get("new_node_id") != manifest["node_id"]:
        print(
            f"statement names new node {transfer.get('new_node_id')!r} "
            f"but this node is {manifest['node_id']!r}",
            file=sys.stderr,
        )
        return 1

    password = _read_password("Root key password: ")
    root_key = load_root_key(config_path.parent / "root_key.pem", password)
    transfer["new_signature"] = b64url_encode(
        sign(root_key, _transfer_signature_preimage(transfer))
    )
    input_path.write_text(json.dumps(transfer, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Co-signed transfer statement written to: {input_path}")
    return 0


def cmd_trust_accept_transfer(args: argparse.Namespace) -> int:
    """Accept a dual-signed transfer statement and rewrite the domain pin.

    Fails closed unless: the current pin's root key matches the statement's
    old node ID, the domain's live well-known document derives the statement's
    new node ID, and both signatures verify.
    """
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"transfer statement not found: {input_path}", file=sys.stderr)
        return 1
    transfer = json.loads(input_path.read_text(encoding="utf-8"))
    if transfer.get("kind") != "transfer":
        print("input is not a transfer statement", file=sys.stderr)
        return 1
    for field in ("domain", "old_node_id", "new_node_id", "signature", "new_signature"):
        if not isinstance(transfer.get(field), str):
            print(f"transfer statement missing field: {field}", file=sys.stderr)
            return 1

    domain = str(transfer["domain"]).lower()
    durable_path, _cache_path = _state_paths(
        Path(args.config),
        state_dir=getattr(args, "state_dir", None),
    )
    try:
        migrate(durable_path)
    except MigrationError as exc:
        print(f"MIGRATION FAILED: {exc}", file=sys.stderr)
        return 1
    conn = open_connection(durable_path)
    try:
        repo = DomainPinRepository(conn)
        pin = repo.get(domain)
        if pin is None:
            print(f"no pin exists for {domain}; nothing to transfer", file=sys.stderr)
            return 1

        old_root_key = load_public_key_b64url(str(pin["root_public_key"]))
        if node_id_from_public_key_b64url(str(pin["root_public_key"])) != transfer["old_node_id"]:
            print(
                f"pinned root key does not match statement old node ID {transfer['old_node_id']!r}",
                file=sys.stderr,
            )
            return 1

        # Fetch the live well-known document for the domain; after the DNS
        # cutover it is served by the new node.
        resolver = WellKnownResolver(OutboundTransport(NetworkPolicy.public()), repo)
        try:
            doc = resolver.resolve(domain)
        except ResolutionError as exc:
            print(f"cannot resolve {domain}: {exc}", file=sys.stderr)
            return 1
        if doc.get("node_id") != transfer["new_node_id"]:
            print(
                f"live well-known for {domain} derives node "
                f"{doc.get('node_id')!r}, not the statement's new node "
                f"{transfer['new_node_id']!r}",
                file=sys.stderr,
            )
            return 1

        new_root_key = load_public_key_b64url(str(doc["root_public_key"]))
        try:
            verify_transfer(transfer, old_root_key, new_root_key)
        except SignatureError as exc:
            print(f"transfer statement signature invalid: {exc}", file=sys.stderr)
            return 1

        doc_model = WellKnownDocument.model_validate(doc)
        repo.upsert(
            domain=domain,
            node_id=doc_model.node_id,
            root_public_key=doc_model.root_public_key,
            operational_certificate=doc_model.operational_certificate.model_dump(mode="json"),
            endpoints={
                "gossip": doc_model.endpoints.gossip,
                "messages": doc_model.endpoints.messages,
            },
        )
    finally:
        conn.close()

    print(f"Pin for {domain} transferred to {transfer['new_node_id']}.")
    return 0


def cmd_identity_show(args: argparse.Namespace) -> int:
    """Display the node identity manifest."""
    manifest_path = Path(args.config).parent / "identity.json"
    if not manifest_path.exists():
        print("Node not initialized.", file=sys.stderr)
        return 1
    print(manifest_path.read_text(encoding="utf-8"))
    return 0


def _credential_path(name: str, config_dir: Path) -> Path:
    """Resolve a systemd credential or a staging plaintext file."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        return Path(cred_dir) / name
    for suffix in ("", ".pem", ".txt"):
        candidate = config_dir / f"{name}{suffix}"
        if candidate.exists():
            return candidate
    raise CredentialError(f"credential not found: {name} in {config_dir}")


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the Lattice daemon."""
    config_path = Path(args.config)
    config_dir = config_path.parent

    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"CONFIG INVALID: {exc}", file=sys.stderr)
        return 1

    manifest_path = config_dir / "identity.json"
    if not manifest_path.exists():
        print("Node not initialized.", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    well_known_path = config_dir / "well-known.json"
    if not well_known_path.exists():
        print(
            "Signed well-known document not found. Run `lattice init` first.",
            file=sys.stderr,
        )
        return 1
    well_known = json.loads(well_known_path.read_text(encoding="utf-8"))

    try:
        op_key = load_operational_key(path=_credential_path("operational_key", config_dir))
        webhook_bearer = load_webhook_bearer(path=_credential_path("webhook_bearer", config_dir))
        admin_bearer = load_admin_bearer(path=_credential_path("admin_bearer", config_dir))
    except CredentialError as exc:
        print(f"CREDENTIAL ERROR: {exc}", file=sys.stderr)
        return 1

    cert = OperationalCertificate.from_dict(manifest["operational_certificate"])
    if cert.node_id != manifest["node_id"]:
        print("Identity manifest node_id/certificate mismatch.", file=sys.stderr)
        return 1
    identity = OperationalIdentity(
        node_id=cert.node_id,
        private_key=op_key,
        certificate=cert,
    )

    from lattice.crypto import load_public_key_b64url

    try:
        root_public_key = load_public_key_b64url(manifest["root_public_key"])
    except Exception as exc:
        print(f"Invalid root public key: {exc}", file=sys.stderr)
        return 1

    durable_path, cache_path = _state_paths(
        config_path,
        state_dir=getattr(args, "state_dir", None),
        cache_dir=getattr(args, "cache_dir", None),
    )

    try:
        migrate(durable_path)
    except MigrationError as exc:
        print(f"MIGRATION FAILED: {exc}", file=sys.stderr)
        return 1

    durable_conn = open_connection(durable_path)
    cache_conn = initialize_cache_db(cache_path)

    runtime = RuntimeCoordinator(
        config=config,
        identity=identity,
        root_public_key=root_public_key,
        durable_conn=durable_conn,
        cache_conn=cache_conn,
        well_known_document=well_known,
        admin_bearer=admin_bearer,
        webhook_bearer=webhook_bearer,
        own_domains={config.domain} if config.domain else None,
    )

    app = create_app(runtime)
    runtime.start()
    try:
        uvicorn.run(
            app,
            host=config.bind_host,
            port=config.bind_port,
            workers=1,
            log_level=getattr(args, "log_level", "info"),
        )
    finally:
        runtime.stop(timeout=30.0)
        durable_conn.close()
        cache_conn.close()
    return 0


def cmd_keys_rotate_operational(args: argparse.Namespace) -> int:
    """Rotate the operational key."""
    config_path = Path(args.config)
    config_dir = config_path.parent
    root_key_path = config_dir / "root_key.pem"
    manifest_path = config_dir / "identity.json"

    if not manifest_path.exists():
        print("Node not initialized.", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    old_cert = OperationalCertificate.from_dict(manifest["operational_certificate"])

    # The old operational key must sign the rotation statement before the
    # staging file is overwritten (docs/PROTOCOL.md §4.4).
    old_op_key_path = config_dir / "operational_key.pem"
    if not old_op_key_path.exists():
        print(
            "Old operational key not found at "
            f"{old_op_key_path}; it is required to sign the rotation statement.",
            file=sys.stderr,
        )
        return 1
    old_op_key = load_private_key(old_op_key_path.read_bytes())

    password = _read_password("Root key password: ")
    root_key = load_root_key(root_key_path, password)

    new_op_key = generate_private_key()
    now = datetime.now(UTC)
    new_cert = create_operational_certificate(
        root_key=root_key,
        operational_public_key=new_op_key.public_key(),
        sequence=old_cert.sequence + 1,
        valid_from=now,
        valid_until=now + timedelta(days=30),
    )

    # Build the three-signed rotation statement. All three signatures cover
    # the same canonical object (see tests/vectors/generate_vectors.py).
    rotation: dict[str, object] = {
        "kind": "rotation",
        "node_id": manifest["node_id"],
        "old_operational_public_key": public_key_b64url(old_op_key.public_key()),
        "new_operational_public_key": public_key_b64url(new_op_key.public_key()),
        "old_certificate_sequence": old_cert.sequence,
        "new_certificate_sequence": new_cert.sequence,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    canonical = canonicalize(rotation)
    preimage = signature_preimage("rotation", canonical)
    rotation["signature"] = b64url_encode(sign(root_key, preimage))
    rotation["old_signature"] = b64url_encode(sign(old_op_key, preimage))
    rotation["new_signature"] = b64url_encode(sign(new_op_key, preimage))

    op_key_path = config_dir / "operational_key.pem"
    op_key_path.write_bytes(save_private_key(new_op_key))
    op_key_path.chmod(0o600)

    rotation_path = config_dir / "rotation.json"
    rotation_path.write_text(json.dumps(rotation, indent=2, ensure_ascii=False), encoding="utf-8")
    rotation_path.chmod(0o644)

    manifest["operational_certificate"] = new_cert.to_dict()
    manifest["rotated_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    # Regenerate the root-signed well-known document with the new certificate.
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"CONFIG INVALID: {exc}", file=sys.stderr)
        return 1
    base = config.public_base_url.rstrip("/")
    well_known: dict[str, object] = {
        "kind": "well_known",
        "node_id": manifest["node_id"],
        "domain": manifest["domain"].lower(),
        "root_public_key": manifest["root_public_key"],
        "operational_certificate": new_cert.to_dict(),
        "endpoints": {
            "gossip": f"{base}/lattice/v1/gossip",
            "messages": f"{base}/lattice/v1/messages",
        },
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    well_known = sign_with_root(root_key, well_known, "well_known")
    well_known_path = config_dir / "well-known.json"
    well_known_path.write_text(
        json.dumps(well_known, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    well_known_path.chmod(0o644)

    print(f"New operational certificate sequence {new_cert.sequence} created.")
    print(f"Operational key staged at: {op_key_path} (encrypt with systemd-creds)")
    print(f"Well-known document updated: {well_known_path}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lattice", description="Lattice node operator CLI")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help=f"Path to config.toml (default: {DEFAULT_CONFIG_PATH})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="initialize a new node")
    init.add_argument("--domain", required=True, help="canonical domain")
    init.add_argument(
        "--public-base-url",
        required=True,
        help="public HTTPS base URL (e.g., https://example.com)",
    )
    init.add_argument("--force", action="store_true", help="overwrite existing configuration")
    init.add_argument(
        "--reuse-root-key",
        action="store_true",
        help="reuse the existing root key (preserves this node's identity; "
        "prompts for its password)",
    )
    init.set_defaults(func=cmd_init)

    check = subparsers.add_parser("config", help="validate configuration")
    check.set_defaults(func=cmd_config_check)

    upgrade = subparsers.add_parser("upgrade", help="run database migrations")
    upgrade.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"durable database directory (default: {DEFAULT_STATE_DIR})",
    )
    upgrade.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"cache database directory (default: {DEFAULT_CACHE_DIR})",
    )
    upgrade.set_defaults(func=cmd_upgrade)

    status = subparsers.add_parser("status", help="show node status")
    status.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"durable database directory (default: {DEFAULT_STATE_DIR})",
    )
    status.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"cache database directory (default: {DEFAULT_CACHE_DIR})",
    )
    status.set_defaults(func=cmd_status)

    identity = subparsers.add_parser("identity", help="show identity manifest")
    identity.set_defaults(func=cmd_identity_show)

    serve = subparsers.add_parser("serve", help="run the Lattice daemon")
    serve.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"durable database directory (default: {DEFAULT_STATE_DIR})",
    )
    serve.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
        help=f"cache database directory (default: {DEFAULT_CACHE_DIR})",
    )
    serve.add_argument(
        "--log-level",
        default="info",
        choices=("debug", "info", "warning", "error", "critical"),
        help="uvicorn log level (default: info)",
    )
    serve.set_defaults(func=cmd_serve)

    trust = subparsers.add_parser("trust", help="manage pinned trust state")
    trust_sub = trust.add_subparsers(dest="trust_command", required=True)
    reset_domain = trust_sub.add_parser(
        "reset-domain",
        help="remove the durable pin for a domain (force out-of-band re-verification)",
    )
    reset_domain.add_argument("--domain", required=True, help="domain whose pin is removed")
    reset_domain.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"durable database directory (default: {DEFAULT_STATE_DIR})",
    )
    reset_domain.set_defaults(func=cmd_trust_reset_domain)

    rotate = subparsers.add_parser("keys", help="manage keys")
    rotate_sub = rotate.add_subparsers(dest="keys_command", required=True)
    rotate_op = rotate_sub.add_parser("rotate-operational", help="rotate the operational key")
    rotate_op.set_defaults(func=cmd_keys_rotate_operational)

    create_transfer = rotate_sub.add_parser(
        "create-transfer",
        help="create a root-signed transfer statement (old root side)",
    )
    create_transfer.add_argument("--domain", required=True, help="domain being transferred")
    create_transfer.add_argument("--new-node-id", required=True, help="new node ID (lat_...)")
    create_transfer.add_argument(
        "--output",
        default="transfer.json",
        help="output path (default: ./transfer.json)",
    )
    create_transfer.set_defaults(func=cmd_keys_create_transfer)

    cosign_transfer = rotate_sub.add_parser(
        "co-sign-transfer",
        help="add the new root's signature to a transfer statement (new root side)",
    )
    cosign_transfer.add_argument("--input", required=True, help="transfer statement path")
    cosign_transfer.set_defaults(func=cmd_keys_cosign_transfer)

    accept_transfer = trust_sub.add_parser(
        "accept-transfer",
        help="accept a dual-signed transfer statement and rewrite the domain pin",
    )
    accept_transfer.add_argument("--input", required=True, help="co-signed transfer statement path")
    accept_transfer.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"durable database directory (default: {DEFAULT_STATE_DIR})",
    )
    accept_transfer.set_defaults(func=cmd_trust_accept_transfer)

    contacts = subparsers.add_parser("contacts", help="manage the contact book")
    contacts_sub = contacts.add_subparsers(dest="contacts_command", required=True)

    contacts_export = contacts_sub.add_parser("export", help="export a signed contact card")
    contacts_export.add_argument("--username", required=True, help="local username")
    contacts_export.add_argument("--display-name", default=None, help="optional display name")
    contacts_export.add_argument("--avatar-url", default=None, help="optional avatar URL")
    contacts_export.add_argument(
        "--output",
        default=None,
        help="output path (default: <username>.contact.json)",
    )
    contacts_export.set_defaults(func=cmd_contacts_export)

    contacts_import = contacts_sub.add_parser(
        "import",
        help="import and verify a signed contact card",
    )
    contacts_import.add_argument("--input", required=True, help="contact card path")
    contacts_import.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"durable database directory (default: {DEFAULT_STATE_DIR})",
    )
    contacts_import.set_defaults(func=cmd_contacts_import)

    contacts_list = contacts_sub.add_parser("list", help="list contacts")
    contacts_list.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help=f"durable database directory (default: {DEFAULT_STATE_DIR})",
    )
    contacts_list.set_defaults(func=cmd_contacts_list)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    func: Callable[[argparse.Namespace], int] = args.func
    try:
        return func(args)
    except CLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (ConfigError, CredentialError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
