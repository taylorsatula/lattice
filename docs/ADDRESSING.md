# Lattice Addressing and Contact Cards

Lattice supports two address forms:

- **Human form:** `alice@example.com`
- **Canonical form:** `alice@lat_abc234...`

The human form is for people. The canonical form binds a username to an immutable node ID and is the authoritative identifier.

## Parsing

```python
from lattice.addressing import parse_address

addr = parse_address("alice@example.com")
print(addr.username)  # alice
print(addr.domain)  # example.com
print(addr.node_id)  # None

addr = parse_address("alice@lat_abc234")
print(addr.node_id)  # lat_abc234
print(addr.is_canonical)  # True
```

## Resolving a human address

The first time a human address is used, Lattice fetches `https://example.com/.well-known/lattice`, validates the root signature and operational certificate, derives the node ID from the root public key, and stores a durable pin.

```python
from lattice.network_policy import NetworkPolicy
from lattice.transport import OutboundTransport
from lattice.resolution import WellKnownResolver
from lattice.storage.repositories import DomainPinRepository
from lattice.storage.connection import open_connection

policy = NetworkPolicy.public()
transport = OutboundTransport(policy)
conn = open_connection("/var/lib/lattice/lattice.durable.db")
repo = DomainPinRepository(conn)
resolver = WellKnownResolver(transport, repo)

resolver.pin("example.com")
```

After pinning, `alice@example.com` resolves to `alice@lat_<node_id>` without further DNS lookups. The domain can be updated only through a signed transfer or an explicit local trust reset.

## Contact cards

A signed contact card contains:

- username
- canonical `user@lat_...` address
- optional display name and avatar URL

Import and export are CLI operations:

```bash
lattice contacts export --username alice --output alice.contact.json
lattice contacts import --input bob.contact.json
```

Contact cards are signed by the node's operational key. They are a convenience layer, not a trust root.

## Short fingerprints

Display node IDs as the first 16 characters after `lat_` in UI contexts:

```python
node_id = "lat_abc234def567ghi890"
short = node_id[4:20]  # abc234def567ghi8
```

Always show the full node ID on security-sensitive screens.

## Domain binding warnings

If a pinned domain returns a different node ID on re-resolution, Lattice fails closed. The operator must run:

```bash
lattice trust reset-domain --domain example.com
```

and re-verify the new binding out of band.

If the change is a planned migration, prefer a dual-signed transfer statement
(see `docs/KEY_MANAGEMENT.md` §Domain transfer):

```bash
lattice keys create-transfer --domain example.com --new-node-id lat_<new>  # old node
lattice keys co-sign-transfer --input transfer.json                        # new node
lattice trust accept-transfer --input transfer.json                        # any peer holding a pin
```

`accept-transfer` rewrites the pin only after both root signatures verify
against the pinned old root key and the live well-known document of the new
node.

## UI guidance

- Distinguish node authentication (cryptographic) from human identity (social).
- A verified node ID means the remote node vouches for messages it signs; it does not prove the human username is authentic.
- Show "verified domain" only after successful well-known resolution and pinning.
