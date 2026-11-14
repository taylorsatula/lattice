# Lattice v1 Protocol Specification

**Status:** Draft. The protocol uses `application/vnd.lattice+json; version=1` and fixed public routes. The final stable external standard requires IANA media-type and well-known URI registration.

## 1. Scope

This document defines the Lattice v1 wire protocol for a DNS-bootstrapped, key-anchored flat mesh. It covers:

- Node identity and addressing.
- Ed25519-based signing, certificates, and rotation.
- Canonical JSON serialization and signature preimages.
- Public HTTP routes: `/.well-known/lattice`, `/lattice/v1/gossip`, `/lattice/v1/messages`.
- Signed objects: well-known document, operational certificate, peer card, message, durable-custody receipt, block record, transfer statement, rotation statement.
- Error format and stable machine codes.
- Operational limits.

## 2. Conventions

- ** MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are interpreted per RFC 2119.
- Byte strings are shown as UTF-8 text inside double quotes; `\0` means a single NUL byte (0x00).
- All protocol timestamps are RFC 3339 strings in UTC with an explicit `Z` suffix, e.g. `2024-01-15T10:30:00Z`.

## 3. Identity

### 3.1 Root key

Each node has one immutable Ed25519 root key pair. The root public key is the ultimate anchor of identity.

### 3.2 Node ID derivation

The node ID is derived from the root public key bytes:

```text
node_id = "lat_" || lowercase-unpadded-RFC4648-Base32(
    SHA-256("lattice-node-id-v1\0" || raw_root_public_key)
)
```

- `raw_root_public_key` is the 32-byte Ed25519 public key (not PEM, not base64).
- Base32 encoding is lowercase and unpadded per RFC 4648 §6.
- The prefix is exactly `lat_` (lowercase).
- The resulting node ID is case-insensitive for comparison but MUST be transmitted in lowercase.

Example node ID: `lat_bafybeigdyrzt5sfp7udm7hu76uh6y26nf3efuylqabf3oclgtqy55fbzdi`.

### 3.3 Operational key and certificate

The daemon signs protocol traffic with a separate Ed25519 operational key. The operational private key is never the root private key. The root signs an operational certificate binding the operational public key to the node ID for a validity window.

Operational certificate fields:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Constant `"operational_certificate"`. |
| `node_id` | string | The node ID of the certificate owner. |
| `operational_public_key` | string | Base64url (RFC 4648 §5) of the 32-byte Ed25519 operational public key, without padding. |
| `valid_from` | string | RFC 3339 UTC timestamp. |
| `valid_until` | string | RFC 3339 UTC timestamp. |
| `sequence` | integer | Monotonically increasing certificate sequence number, starting at 1. |

The certificate is signed by the root private key. A daemon MUST reject a certificate whose `valid_until` is in the past, whose `sequence` is not greater than the previously accepted certificate for that node, or whose signature does not verify with the root public key matching `node_id`.

### 3.4 Addressing

A **human address** has the form `local@domain`. A **canonical address** has the form `local@lat_<node_id>`. Both forms are accepted locally. When a human address is resolved, the local node stores a durable pin mapping `domain -> node_id`. Canonical addresses do not require DNS at send time.

The canonical form is the authoritative recipient identifier for signatures and storage.

## 4. Canonicalization and signing

### 4.1 JSON parsing

Before canonicalization or validation, a JSON payload MUST be parsed with these restrictions:

- Duplicate object keys MUST be rejected.
- Numbers MUST be within the I-JSON safe integer range (`-(2**53)+1` to `2**53-1`). Non-integer values (floating-point) are allowed only when the schema explicitly permits them.
- `NaN`, `Infinity`, and `-Infinity` MUST be rejected.
- UTF-8 MUST be enforced; invalid byte sequences MUST be rejected.
- Object key order MUST NOT be semantically significant.

### 4.2 RFC 8785 JCS

The canonical byte representation of a signed object is produced by RFC 8785 JSON Canonicalization Scheme (JCS). The output is UTF-8 bytes with no whitespace and keys sorted by UTF-16 code-unit order.

Implementations SHOULD use a tested RFC 8785 library and validate against the vectors in `tests/vectors/canonical.json`.

### 4.3 Signature preimage

The Ed25519 signature for a signed object is computed over the following UTF-8 string:

```text
"lattice-signature-v1\0" || kind || "\0" || media_type || "\0" || canonical_bytes
```

Where:

- `kind` is the value of the object's `kind` field, e.g. `"peer_card"`.
- `media_type` is the normalized media type `application/vnd.lattice+json; version=1`.
- `canonical_bytes` is the RFC 8785 canonicalization of the object **excluding** the `signature` field.

The object as transmitted includes a base64url-unpadded `signature` field appended after canonicalization. The signing process:

1. Build the object dict without `signature`.
2. Canonicalize to `canonical_bytes`.
3. Build the preimage string.
4. Sign the preimage with the appropriate Ed25519 private key.
5. Add `signature`: base64url-unpadded of the 64-byte signature.

Verification:

1. Extract `signature`.
2. Build the object dict without `signature`.
3. Recompute the preimage.
4. Verify the signature against the asserted public key.

### 4.4 Allowed kinds

| Kind | Signer | Purpose |
|------|--------|---------|
| `well_known` | Root | Domain binding in `/.well-known/lattice`. |
| `operational_certificate` | Root | Authorizes an operational key. |
| `peer_card` | Operational | Advertises endpoints and certificate. |
| `message` | Operational | Carries a federated message. |
| `receipt` | Operational | Acknowledges durable custody. |
| `block` | Operational | Declares a local block of another node. |
| `contact_card` | Operational | Shares a verified human contact binding. |
| `transfer` | Root + new root | Authorizes domain/node ID transfer. |
| `rotation` | Root + old op + new op | Authorizes operational key rotation. |

## 5. Public routes

### 5.1 `GET /.well-known/lattice`

Returns the node's well-known document. The response body is a JSON object with:

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | `"well_known"`. |
| `node_id` | string | Node ID. |
| `domain` | string | The canonical domain this document represents. |
| `root_public_key` | string | Base64url of the 32-byte Ed25519 root public key. |
| `operational_certificate` | object | Root-signed operational certificate. |
| `endpoints` | object | `{"gossip": "<https-url>", "messages": "<https-url>"}`. URLs MUST be absolute HTTPS URLs. |
| `issued_at` | string | RFC 3339 timestamp. |
| `signature` | string | Root signature over the object. |

The document is signed by the root key. The `domain` field MUST match the requested host. The receiving node verifies the root signature, derives the node ID from the root public key implied by the signature, and verifies the operational certificate before pinning.

The daemon MAY cache a pre-signed well-known document. It MUST regenerate it when the operational certificate or endpoints change.

### 5.2 `POST /lattice/v1/gossip`

Receives a batch of peer cards. Request body:

```json
{
  "cards": [ peer_card, peer_card, ... ],
  "introduced_by": "lat_..."
}
```

- `cards` is an array of signed peer cards (see §6).
- The first card SHOULD be the sender's own current peer card. Receivers MUST
  verify it (root signature chain, node-ID derivation, card signature) and,
  when it verifies, rate limit gossip by its node ID. When it is absent or
  does not verify, receivers fall back to transport-level identification
  (client IP) for rate limiting.
- `introduced_by` is OPTIONAL and identifies the introducer's node ID.
- Maximum batch size: 32 cards.
- Maximum request body: 256 KiB.

Response:

- `200 OK` with `{ "accepted": <int>, "rejected": <int>, "errors": [ ... ] }` on success.
- Errors use the standard Problem Details format (§9).

The receiver MUST attribute each card to its introducer and enforce candidate caps before expensive verification.

### 5.3 `POST /lattice/v1/messages`

Receives a signed federated message. Request body is a `message` signed object (§7). Response is a signed `receipt` object (§8) with HTTP status `202 Accepted`.

Maximum request body: 128 KiB.

If the same `message_id` is received again and the message is already in durable custody, the receiver MUST return the identical signed receipt bytes.

## 6. Peer card

A peer card advertises a node's current endpoints and operational certificate for gossip propagation.

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | `"peer_card"`. |
| `node_id` | string | Node ID. |
| `domain` | string | Canonical domain. |
| `operational_certificate` | object | Root-signed certificate for the card signer. |
| `endpoints` | object | `{"gossip": "<url>", "messages": "<url>"}`. |
| `sequence` | integer | Card sequence number, monotonically increasing. |
| `issued_at` | string | RFC 3339 timestamp. |
| `expires_at` | string | RFC 3339 timestamp; maximum 7 days after `issued_at`. |
| `signature` | string | Operational signature. |

Validation:

- Verify the operational signature.
- Verify the operational certificate against the root public key derived from `node_id`.
- Reject if `expires_at` is past.
- Reject if `sequence` is not greater than the last accepted card from this node.
- Independently fetch `/.well-known/lattice` from the domain to confirm the binding before marking verified.

## 7. Message

A federated message.

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | `"message"`. |
| `message_id` | string | UUIDv7 or 32-byte random base64url-unpadded identifier; globally unique. |
| `from_address` | string | Canonical or human sender address. |
| `to_address` | string | Canonical or human recipient address. |
| `content` | string | UTF-8 text, maximum 64 KiB encoded bytes. |
| `priority` | string | `"normal"`, `"high"`, or `"urgent"`. |
| `ttl_seconds` | integer | Time-to-live in seconds; default 86400, maximum 604800. |
| `extension` | object | OPTIONAL. `{"namespace": "<URI>", "data": <JSON>}`. Maximum 16 KiB encoded bytes. |
| `timestamp` | string | RFC 3339 timestamp. |
| `signature` | string | Operational signature. |

Validation:

- Verify operational signature.
- Reject oversized `content` or `extension`.
- Reject unknown `priority` values.
- Reject `ttl_seconds` outside bounds.
- Reject malformed addresses.
- Reject messages addressed to a different node.

## 8. Durable-custody receipt

Returned by the destination node after accepting durable custody.

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | `"receipt"`. |
| `message_id` | string | Message ID being acknowledged. |
| `node_id` | string | Node issuing the receipt. |
| `status` | string | `"accepted"` or `"rejected"`. |
| `received_at` | string | RFC 3339 timestamp. |
| `signature` | string | Operational signature. |

A `rejected` receipt indicates the destination node will not take custody (e.g., recipient blocked, message malformed after signature check). A `202 Accepted` with a rejected receipt is final. The receipt bytes MUST be persisted and returned identically for duplicate `message_id` values.

## 9. Error format

All protocol errors use RFC 9457 Problem Details with `Content-Type: application/problem+json`:

```json
{
  "type": "https://lattice.dev/errors/<code>",
  "title": "Human-readable title",
  "status": 400,
  "detail": "Human-readable detail",
  "code": "LATTICE_<SNAKE_CASE_CODE>"
}
```

The `code` field is stable and machine-readable. Clients SHOULD use `code`, not `title` or `detail`, for programmatic handling. Example codes:

| Code | HTTP | Meaning |
|------|------|---------|
| `LATTICE_INVALID_SIGNATURE` | 401 | Signature verification failed. |
| `LATTICE_UNKNOWN_NODE` | 404 | Node not pinned and resolution failed. |
| `LATTICE_EXPIRED_CERTIFICATE` | 401 | Operational certificate expired. |
| `LATTICE_RATE_LIMITED` | 429 | Per-peer quota exceeded. |
| `LATTICE_MESSAGE_TOO_LARGE` | 413 | Request body exceeds limit. |
| `LATTICE_INVALID_ADDRESS` | 400 | Address malformed or unsupported. |
| `LATTICE_DOMAIN_BINDING_MISMATCH` | 403 | Well-known domain does not match requested host. |

## 10. Limits

| Resource | Limit |
|----------|-------|
| Message text | 64 KiB UTF-8 bytes |
| Message extension | 16 KiB encoded JSON bytes |
| Message TTL | default 86400 s, max 604800 s |
| Gossip batch | 32 cards |
| Gossip request body | 256 KiB |
| Message request body | 128 KiB |
| Peer card lifetime | max 7 days |
| Operational certificate lifetime | max 90 days |
| Well-known cache lifetime | max 1 hour |

## 11. Version policy

- The media type carries the major version: `application/vnd.lattice+json; version=1`.
- Implementations MUST reject requests with an unsupported or missing `version` parameter in the `Content-Type` or `Accept` header, as applicable.
- A new major version may change signatures, routes, or identity derivation. Minor protocol improvements within a major version MUST NOT change signed-object schemas or node ID derivation.
- Skipped minor releases are upgraded through durable SQL migrations, not protocol negotiation.

## 12. Examples

### 12.1 Well-known document (unsigned canonical form)

```json
{
  "kind": "well_known",
  "node_id": "lat_bafybeigdyrzt5sfp7udm7hu76uh6y26nf3efuylqabf3oclgtqy55fbzdi",
  "domain": "example.com",
  "operational_certificate": { ... },
  "endpoints": {
    "gossip": "https://example.com/lattice/v1/gossip",
    "messages": "https://example.com/lattice/v1/messages"
  },
  "issued_at": "2024-01-15T10:30:00Z"
}
```

### 12.2 Signature preimage

For a peer card with canonical bytes `C`, the preimage is:

```text
lattice-signature-v1\0peer_card\0application/vnd.lattice+json; version=1\0<C>
```

Where `\0` is the NUL byte and `<C>` is the literal UTF-8 byte sequence of the canonical JSON.
