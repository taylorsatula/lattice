"""Lattice wire objects and verification (test-suite only).

These helpers verify the shared wire-format vectors and the objects the
tests handle. They are NOT part of the ``lattice`` package: the package is
the local-API client only (see the README). They are kept in the test suite
and mirror the Rust implementation in ``crates/lattice-proto``; if the two
disagree, the Rust code and ``vectors/vectors.json`` are authoritative.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lattice import wire
from crypto import open_layer, ENVELOPE_CONTEXT

PROTOCOL_VERSION = 1
EVENT_INCEPTION = 1
EVENT_ROTATION = 2
KIND_RECORD = 10
KEL_OBJECT_TYPE = 11

KIND_MESSAGE = 0
KIND_RECEIPT = 1
KIND_NEGATIVE_RECEIPT = 2
REASON_UNKNOWN_SERVICE = 1
REASON_INVALID = 2

SCOPE_WAN = 0
SCOPE_HIVE = 1
MODE_PUBLIC = 0
MODE_PRIVATE = 1

# The four message buckets are the frame buckets minus the 64-byte AEAD tag.
MESSAGE_BUCKETS = (2048 - 64, 4096 - 64, 8192 - 64, 32768 - 64)
RECORD_MAX = 3072
MAX_KEL_BYTES = 16 * 1024
MAX_MESSAGE_HORIZON = 14 * 24 * 3600
MAX_RECORD_HORIZON = 30 * 24 * 3600
CLOCK_SKEW = 6 * 3600
KEM_CIPHERTEXT_LEN = 1120
XWING_PUBLIC_KEY_LEN = 1216
MAX_ENDPOINTS = 16
MAX_LINKS = 32
MAX_GATEWAYS = 3
MAX_SERVES = 16

# Domain-separated signature preimages (V2_SPEC §1). The context string is
# never part of the encoded object; it prefixes the bytes fed to the signer.
KEY_EVENT_CONTEXT = "lattice v1 key event"
RECORD_CONTEXT = "lattice v1 record"
RECEIPT_CONTEXT = "lattice v1 receipt"
# ENVELOPE_CONTEXT is shared with the AEAD KDF context (spec §1).

KEY_EVENT_KEYS = frozenset(range(0, 7))
RECORD_KEYS = frozenset(range(0, 19))
HEADER_KEYS = frozenset(range(0, 5))
ENVELOPE_KEYS = frozenset(range(0, 12))
SEALED_KEYS = frozenset({0, 1})
KEL_OBJECT_KEYS = frozenset({0, 1, 2, 3})
ENDPOINT_KEYS = frozenset({0, 1})


def signing_preimage(context: str, body: bytes) -> bytes:
    return context.encode() + b"\x00" + body


def _b3(data: bytes) -> bytes:
    return blake3.blake3(data).digest()


def _verify(pubkey: bytes, message: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _uint(value, name: str) -> int:
    # bool is a subclass of int; the wire has no booleans in uint fields.
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a uint")
    return value


def _opt_uint(value, name: str):
    if value is None:
        return None
    return _uint(value, name)


def _bytes(value, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError(f"{name} must be bytes")
    return bytes(value)


def _fixed_bytes(obj, key: int, n: int) -> bytes:
    value = obj.get(key)
    if value is None:
        raise ValueError(f"missing key {key}")
    value = _bytes(value, f"key {key}")
    if len(value) != n:
        raise ValueError(f"key {key} must be {n} bytes")
    return value


def _opt_bytes(value, n: int | None, name: str):
    if value is None:
        return None
    value = _bytes(value, name)
    if n is not None and len(value) != n:
        raise ValueError(f"{name} must be {n} bytes")
    return value


def _text(obj, key: int) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise ValueError(f"key {key} must be text")
    return value


def _deny_unknown_keys(obj, allowed) -> None:
    for key in obj:
        if type(key) is not int or key not in allowed:
            raise ValueError(f"unknown key {key!r}")


def _id_list(value, name: str) -> list[bytes]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    out = []
    for item in value:
        item = _bytes(item, name)
        if len(item) != 32:
            raise ValueError(f"{name} entries must be 32 bytes")
        out.append(item)
    return out


# ---------- key events ----------

@dataclass
class KeyEvent:
    kind: int
    seq: int
    prev: bytes | None
    key: bytes
    next: bytes | None
    sig: bytes

    def unsigned_value(self) -> dict:
        pairs = {0: PROTOCOL_VERSION, 1: self.kind, 2: self.seq}
        if self.prev is not None:
            pairs[3] = self.prev
        pairs[4] = self.key
        if self.next is not None:
            pairs[5] = self.next
        return pairs

    def unsigned_bytes(self) -> bytes:
        return wire.encode(self.unsigned_value())

    def to_value(self) -> dict:
        obj = dict(self.unsigned_value())
        obj[6] = self.sig
        return obj

    def commitment(self) -> bytes:
        return _b3(self.unsigned_bytes())

    def encode(self) -> bytes:
        return wire.encode(self.to_value())

    def verify_signature(self) -> bool:
        preimage = signing_preimage(KEY_EVENT_CONTEXT, self.unsigned_bytes())
        return _verify(self.key, preimage, self.sig)


def _key_event_from_value(obj) -> KeyEvent:
    if not isinstance(obj, dict):
        raise ValueError("key event must be a map")
    _deny_unknown_keys(obj, KEY_EVENT_KEYS)
    if _uint(obj.get(0), "v") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    kind = _uint(obj.get(1), "t")
    if kind not in (EVENT_INCEPTION, EVENT_ROTATION):
        raise ValueError("unknown key event kind")
    seq = _uint(obj.get(2), "sn")
    prev = _opt_bytes(obj.get(3), 32, "prev")
    key = _fixed_bytes(obj, 4, 32)
    nxt = _opt_bytes(obj.get(5), 32, "n")
    sig = _fixed_bytes(obj, 6, 64)
    return KeyEvent(kind=kind, seq=seq, prev=prev, key=key, next=nxt, sig=sig)


def parse_key_event(data: bytes) -> KeyEvent:
    return _key_event_from_value(wire.decode(data))


def kel_identifier(events: list[KeyEvent]) -> bytes:
    if not events or events[0].kind != EVENT_INCEPTION:
        raise ValueError("KEL must start with an inception event")
    return _b3(events[0].unsigned_bytes())


@dataclass(frozen=True)
class KelHead:
    seq: int
    commitment: bytes
    current_key: bytes
    next: bytes | None

    @property
    def is_abandoned(self) -> bool:
        return self.next is None


class ValidatedKel:
    """A KEL that passed full chain validation.

    Construct via :func:`validate_kel` or :func:`parse_kel_object`; there is
    no other way to obtain one, mirroring the Rust ``ValidatedKel``.
    """

    def __init__(self, events: list[KeyEvent]):
        self.events = list(events)
        head = self.events[-1]
        self._head = KelHead(
            seq=head.seq,
            commitment=head.commitment(),
            current_key=head.key,
            next=head.next,
        )
        self._id = kel_identifier(self.events)

    @property
    def head(self) -> KelHead:
        return self._head

    @property
    def identifier(self) -> bytes:
        return self._id

    @property
    def is_abandoned(self) -> bool:
        return self._head.is_abandoned

    def __len__(self) -> int:
        return len(self.events)


def validate_kel(events: list[KeyEvent]) -> ValidatedKel:
    """Validate a KEL the way the Rust implementation does.

    Enforces: inception shape, chain linkage, per-event signatures, that
    every rotation's key matches the previous commitment to the next key,
    and that nothing follows an abandonment.
    """
    if not events:
        raise ValueError("empty KEL")
    first = events[0]
    if first.kind != EVENT_INCEPTION or first.seq != 0 or first.prev is not None:
        raise ValueError("first event is not a valid inception")
    if not first.verify_signature():
        raise ValueError("inception signature invalid")
    prev = first
    for ev in events[1:]:
        if prev.next is None:
            raise ValueError("event follows an abandonment")
        if ev.kind != EVENT_ROTATION:
            raise ValueError("non-rotation after inception")
        if ev.seq != prev.seq + 1:
            raise ValueError("KEL sequence gap")
        if ev.prev != prev.commitment():
            raise ValueError("KEL chain broken")
        if _b3(ev.key) != prev.next:
            raise ValueError("rotation key does not match the previous commitment")
        if not ev.verify_signature():
            raise ValueError("rotation signature invalid")
        prev = ev
    return ValidatedKel(events)


def parse_kel_object(data: bytes) -> ValidatedKel:
    """Decode and validate a KEL object (V2_SPEC §2, object type 11)."""
    if len(data) > MAX_KEL_BYTES:
        raise ValueError(f"KEL object exceeds {MAX_KEL_BYTES} bytes")
    obj = wire.decode(data)
    if not isinstance(obj, dict):
        raise ValueError("KEL object must be a map")
    _deny_unknown_keys(obj, KEL_OBJECT_KEYS)
    if _uint(obj.get(0), "v") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if _uint(obj.get(1), "t") != KEL_OBJECT_TYPE:
        raise ValueError("not a KEL object")
    id_bytes = _fixed_bytes(obj, 2, 32)
    raw_events = obj.get(3)
    if not isinstance(raw_events, list):
        raise ValueError("KEL object events must be an array")
    events = [_key_event_from_value(e) for e in raw_events]
    kel = validate_kel(events)
    if kel.identifier != id_bytes:
        raise ValueError("KEL object id does not match its inception event")
    return kel


def encode_kel_object(kel: ValidatedKel) -> bytes:
    obj = {
        0: PROTOCOL_VERSION,
        1: KEL_OBJECT_TYPE,
        2: kel.identifier,
        3: [e.to_value() for e in kel.events],
    }
    data = wire.encode(obj)
    if len(data) > MAX_KEL_BYTES:
        raise ValueError(f"KEL object exceeds {MAX_KEL_BYTES} bytes")
    return data


# ---------- peer records ----------

@dataclass
class PeerRecord:
    id: bytes
    scope: int
    seq: int
    exp: int
    khs: int
    khc: bytes
    k: bytes
    channel_key: bytes
    envelope_key: bytes
    mode: int
    endpoints: list = None  # list[{"url": str, "ips": list[str]}]
    links: list = None      # list[bytes]
    gateways: list = None   # list[bytes]
    capabilities: int = 0
    serves: list = None     # list[bytes]
    sig: bytes = b""
    channel_sig: bytes = b""

    def __post_init__(self):
        if self.endpoints is None:
            self.endpoints = []
        if self.links is None:
            self.links = []
        if self.gateways is None:
            self.gateways = []
        if self.serves is None:
            self.serves = []

    def unsigned_value(self) -> dict:
        pairs = {
            0: PROTOCOL_VERSION,
            1: KIND_RECORD,
            2: self.id,
            3: self.scope,
            4: self.seq,
            5: self.exp,
            6: self.khs,
            7: self.channel_key,
            8: self.envelope_key,
            9: self.mode,
        }
        if self.mode == MODE_PUBLIC:
            pairs[10] = [
                {0: e["url"], **({1: e["ips"]} if e.get("ips") else {})}
                for e in self.endpoints
            ]
            pairs[11] = list(self.links)
        else:
            pairs[12] = list(self.gateways)
        pairs[13] = self.capabilities
        pairs[16] = self.khc
        pairs[17] = self.k
        if self.serves:
            pairs[18] = list(self.serves)
        return pairs

    def unsigned_bytes(self) -> bytes:
        return wire.encode(self.unsigned_value())

    def signature_preimage(self) -> bytes:
        return signing_preimage(RECORD_CONTEXT, self.unsigned_bytes())

    def current_signing_key(self) -> bytes:
        return self.k


def _parse_endpoint(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError("endpoint must be a map")
    _deny_unknown_keys(value, ENDPOINT_KEYS)
    url = value.get(0)
    if not isinstance(url, str):
        raise ValueError("endpoint url must be text")
    ips = value.get(1, [])
    if not isinstance(ips, list):
        raise ValueError("endpoint ips must be an array")
    for ip in ips:
        if not isinstance(ip, str):
            raise ValueError("endpoint ip must be text")
    return {"url": url, "ips": list(ips)}


def _is_v4_global(ip: ipaddress.IPv4Address) -> bool:
    o = ip.packed
    if o[0] == 0:
        return False
    if o[0] == 10:
        return False
    if o[0] == 100 and 64 <= o[1] <= 127:
        return False
    if o[0] == 127:
        return False
    if o[0] == 169 and o[1] == 254:
        return False
    if o[0] == 172 and 16 <= o[1] <= 31:
        return False
    if o[0] == 192 and o[1] == 0 and o[2] == 0:
        return False
    if o[0] == 192 and o[1] == 0 and o[2] == 2:
        return False
    if o[0] == 192 and o[1] == 88 and o[2] == 99:
        return False
    if o[0] == 192 and o[1] == 175 and o[2] == 48:
        return False
    if o[0] == 192 and o[1] == 168:
        return False
    if o[0] == 198 and o[1] in (18, 19):
        return False
    if o[0] == 198 and o[1] == 51 and o[2] == 100:
        return False
    if o[0] == 203 and o[1] == 0 and o[2] == 113:
        return False
    if o[0] >= 224:
        return False
    return True


def _is_ipv4_embedding(ip: ipaddress.IPv6Address) -> bool:
    s = ip.exploded.split(":")
    seg = [int(x, 16) for x in s]
    # ::/96 — deprecated IPv4-compatible addresses
    if all(x == 0 for x in seg[:6]):
        return True
    # 64:ff9b::/96 — NAT64 well-known prefix
    if seg[0] == 0x0064 and seg[1] == 0xFF9B and all(x == 0 for x in seg[2:6]):
        return True
    # 2002::/16 — 6to4
    if seg[0] == 0x2002:
        return True
    # 2001::/32 — Teredo
    if seg[0] == 0x2001 and seg[1] == 0x0000:
        return True
    return False


def _is_globally_routable(ip) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return _is_v4_global(ip)
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return _is_v4_global(mapped)
    if _is_ipv4_embedding(ip):
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return False
    seg = [int(x, 16) for x in ip.exploded.split(":")]
    if (seg[0] & 0xFFC0) == 0xFE80:  # fe80::/10 link-local
        return False
    if (seg[0] & 0xFE00) == 0xFC00:  # fc00::/7 unique-local
        return False
    if seg[0] == 0x2001 and seg[1] == 0x0DB8:  # 2001:db8::/32 documentation
        return False
    return True


def _validate_endpoint(ep: dict, scope: int) -> None:
    url = ep["url"]
    if not url.startswith("ws://"):
        raise ValueError("endpoint scheme must be ws (Noise provides confidentiality)")
    hostport = url[len("ws://"):].split("/", 1)[0]
    if not hostport or "@" in hostport:
        raise ValueError("endpoint has no host or carries userinfo")
    if ":" in hostport:
        host, sep, port = hostport.rpartition(":")
        if not host:
            raise ValueError("bad endpoint port")
        try:
            port_num = int(port)
        except ValueError:
            raise ValueError("bad endpoint port") from None
        if port_num == 0 or port_num > 65535:
            raise ValueError("bad endpoint port")
    else:
        host = hostport
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if scope == SCOPE_WAN and not _is_globally_routable(ip):
            raise ValueError("WAN endpoint host is not globally routable")
    else:
        if any(not (c.isascii() and (c.isalnum() or c in "-.")) for c in host):
            raise ValueError("bad endpoint hostname")
        if host.startswith("-") or host.endswith("-"):
            raise ValueError("bad endpoint hostname")
    for ip_str in ep["ips"]:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError("invalid IP literal") from None
        if scope == SCOPE_WAN and not _is_globally_routable(ip):
            raise ValueError("WAN endpoint address is not globally routable")


def _validate_serves(serves: list[bytes], mode: int) -> None:
    if len(serves) > MAX_SERVES:
        raise ValueError("too many serves entries")
    if mode == MODE_PRIVATE and serves:
        raise ValueError("private record carries serves")
    if len(set(serves)) != len(serves):
        raise ValueError("duplicate serves entry")


def parse_record(data: bytes, now: int, kel: ValidatedKel) -> PeerRecord:
    """Parse and fully validate a record against the KEL the caller holds.

    Mirrors the Rust validator (``crates/lattice-proto/src/record.rs``):
    size cap, unknown keys, expiry horizon, mode/field consistency,
    endpoint rules, the KEL head binding (khs/khc/k, not abandoned), and
    both signatures. ``now`` is required; there is no unchecked variant.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("record must be bytes")
    if len(data) > RECORD_MAX:
        raise ValueError(f"record exceeds {RECORD_MAX} bytes")
    obj = wire.decode(bytes(data))
    if not isinstance(obj, dict):
        raise ValueError("record must be a map")
    _deny_unknown_keys(obj, RECORD_KEYS)
    if _uint(obj.get(0), "v") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if _uint(obj.get(1), "t") != KIND_RECORD:
        raise ValueError("not a peer record")
    id_ = _fixed_bytes(obj, 2, 32)
    scope = _uint(obj.get(3), "scope")
    if scope not in (SCOPE_WAN, SCOPE_HIVE):
        raise ValueError("unknown scope")
    seq = _uint(obj.get(4), "seq")
    exp = _uint(obj.get(5), "exp")
    khs = _uint(obj.get(6), "khs")
    channel_key = _fixed_bytes(obj, 7, 32)
    envelope_key = _fixed_bytes(obj, 8, XWING_PUBLIC_KEY_LEN)
    mode = _uint(obj.get(9), "mode")
    if mode not in (MODE_PUBLIC, MODE_PRIVATE):
        raise ValueError("unknown mode")
    capabilities = _uint(obj.get(13), "cap")
    sig = _fixed_bytes(obj, 14, 64)
    channel_sig = _fixed_bytes(obj, 15, 64)
    khc = _fixed_bytes(obj, 16, 32)
    k = _fixed_bytes(obj, 17, 32)

    raw_eps = obj.get(10)
    if raw_eps is None:
        endpoints = []
    elif isinstance(raw_eps, list):
        endpoints = [_parse_endpoint(e) for e in raw_eps]
    else:
        raise ValueError("endpoints must be an array")
    links = _id_list(obj.get(11), "links")
    gateways = _id_list(obj.get(12), "gateways")
    serves = _id_list(obj.get(18), "serves")

    # Mode/field consistency.
    if mode == MODE_PUBLIC:
        if gateways:
            raise ValueError("public record carries gateways")
        if len(endpoints) > MAX_ENDPOINTS:
            raise ValueError("too many endpoints")
        if len(links) > MAX_LINKS:
            raise ValueError("too many links")
    else:
        if endpoints or links:
            raise ValueError("private record carries endpoints or links")
        if not 1 <= len(gateways) <= MAX_GATEWAYS:
            raise ValueError("private record needs 1-3 gateways")
        if serves:
            raise ValueError("private record carries serves")
    _validate_serves(serves, mode)
    for ep in endpoints:
        _validate_endpoint(ep, scope)

    # Expiry horizon.
    if exp <= now:
        raise ValueError("record expired")
    if exp > now + MAX_RECORD_HORIZON + CLOCK_SKEW:
        raise ValueError("record expiry beyond the horizon")

    # KEL binding: the record must cite exactly the head of the held KEL,
    # and that head must not be an abandonment.
    head = kel.head
    if kel.identifier != id_:
        raise ValueError("identifier does not match inception event")
    if khs != head.seq:
        raise ValueError("record cites a different KEL head sn than the held KEL")
    if khc != head.commitment:
        raise ValueError("record cites a different KEL head event than the held KEL")
    if k != head.current_key:
        raise ValueError("record key does not match the KEL head event's key")
    if head.is_abandoned:
        raise ValueError("KEL head is an abandonment")

    record = PeerRecord(
        id=id_,
        scope=scope,
        seq=seq,
        exp=exp,
        khs=khs,
        khc=khc,
        k=k,
        channel_key=channel_key,
        envelope_key=envelope_key,
        mode=mode,
        endpoints=endpoints,
        links=links,
        gateways=gateways,
        capabilities=capabilities,
        serves=serves,
        sig=sig,
        channel_sig=channel_sig,
    )
    preimage = record.signature_preimage()
    if not _verify(k, preimage, sig):
        raise ValueError("record signature invalid")
    # The channel key must endorse the record too: without this, anyone
    # could publish a record claiming someone else's channel key.
    if not _verify(channel_key, preimage, channel_sig):
        raise ValueError("record channel signature invalid")
    return record


# ---------- messages ----------

@dataclass
class Envelope:
    kind: int
    mid: bytes
    from_: bytes
    fsvc: str
    fmbx: bytes
    tsvc: str
    tmbx: bytes
    created: int
    body: bytes | None
    reference: bytes | None
    reason: int | None
    sig: bytes

    def unsigned_value(self) -> dict:
        pairs = {
            0: self.kind,
            11: self.mid,
            1: self.from_,
            2: self.fsvc,
            3: self.fmbx,
            4: self.tsvc,
            5: self.tmbx,
            6: self.created,
        }
        if self.body is not None:
            pairs[7] = self.body
        if self.reference is not None:
            pairs[8] = self.reference
        if self.reason is not None:
            pairs[9] = self.reason
        return pairs

    def unsigned_bytes(self) -> bytes:
        return wire.encode(self.unsigned_value())

    def signature_context(self) -> str:
        return ENVELOPE_CONTEXT if self.kind == KIND_MESSAGE else RECEIPT_CONTEXT

    def signature_preimage(self, raw_header: bytes) -> bytes:
        return signing_preimage(self.signature_context(), raw_header + self.unsigned_bytes())


@dataclass
class Message:
    raw: bytes
    header: dict
    hop_layer: object
    envelope_layer: dict
    padding: bytes
    raw_header: bytes

    @property
    def dst(self) -> bytes:
        return self.header[3]

    @property
    def leg(self) -> bytes:
        return self.header[2]

    @property
    def exp(self) -> int:
        return self.header[4]


def _parse_sealed_layer(obj) -> dict:
    if not isinstance(obj, dict):
        raise ValueError("sealed layer must be a map")
    _deny_unknown_keys(obj, SEALED_KEYS)
    kem = _fixed_bytes(obj, 0, KEM_CIPHERTEXT_LEN)
    ct = _bytes(obj.get(1), "ct")
    return {0: kem, 1: ct}


def parse_message(data: bytes, now: int | None = None) -> Message:
    if len(data) not in MESSAGE_BUCKETS:
        raise ValueError("message is not a bucket size")
    obj = wire.decode(data)
    if not isinstance(obj, list) or len(obj) != 4:
        raise ValueError("message must be a 4-element array")
    header, hop_layer, envelope, padding = obj
    if not isinstance(header, dict):
        raise ValueError("header must be a map")
    _deny_unknown_keys(header, HEADER_KEYS)
    if _uint(header.get(0), "v") != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    if _uint(header.get(1), "t") != 30:
        raise ValueError("not a routing header")
    _fixed_bytes(header, 2, 16)  # leg
    _fixed_bytes(header, 3, 32)  # dst
    exp = _uint(header.get(4), "exp")
    if now is not None:
        if exp <= now:
            raise ValueError("message expired")
        if exp > now + MAX_MESSAGE_HORIZON + CLOCK_SKEW:
            raise ValueError("message expiry beyond the horizon")
    if hop_layer is not None:
        hop_layer = _parse_sealed_layer(hop_layer)
    envelope = _parse_sealed_layer(envelope)
    if not isinstance(padding, (bytes, bytearray)) or any(padding):
        raise ValueError("padding must be zero bytes")
    padding = bytes(padding)
    # Re-encode the header to recover its exact bytes for use as AAD. The
    # codec is canonical, so this is byte-identical to the original.
    raw_header = wire.encode(header)
    if not data.startswith(b"\x84" + raw_header):
        raise ValueError("header re-encoding mismatch")
    return Message(
        raw=bytes(data),
        header=header,
        hop_layer=hop_layer,
        envelope_layer=envelope,
        padding=padding,
        raw_header=raw_header,
    )


def _parse_envelope(obj) -> Envelope:
    if not isinstance(obj, dict):
        raise ValueError("envelope must be a map")
    _deny_unknown_keys(obj, ENVELOPE_KEYS)
    kind = _uint(obj.get(0), "kind")
    if kind not in (KIND_MESSAGE, KIND_RECEIPT, KIND_NEGATIVE_RECEIPT):
        raise ValueError("unknown envelope kind")
    mid = _fixed_bytes(obj, 11, 16)
    from_ = _fixed_bytes(obj, 1, 32)
    fsvc = _text(obj, 2)
    fmbx = _bytes(obj.get(3), "fmbx")
    tsvc = _text(obj, 4)
    tmbx = _bytes(obj.get(5), "tmbx")
    created = _uint(obj.get(6), "created")
    body = _opt_bytes(obj.get(7), None, "body")
    reference = _opt_bytes(obj.get(8), 16, "ref")
    reason = _opt_uint(obj.get(9), "reason")
    sig = _fixed_bytes(obj, 10, 64)
    if kind == KIND_MESSAGE:
        if body is None or reference is not None or reason is not None:
            raise ValueError("message envelope needs a body and no reference or reason")
    elif kind == KIND_RECEIPT:
        if body is not None or reference is None:
            raise ValueError("receipt needs a reference and no body")
        if reason is not None:
            raise ValueError("receipt carries no reason")
    else:  # KIND_NEGATIVE_RECEIPT
        if body is not None or reference is None:
            raise ValueError("negative receipt needs a reference and no body")
        if reason not in (REASON_UNKNOWN_SERVICE, REASON_INVALID):
            raise ValueError("negative receipt needs a known reason")
    return Envelope(
        kind=kind,
        mid=mid,
        from_=from_,
        fsvc=fsvc,
        fmbx=fmbx,
        tsvc=tsvc,
        tmbx=tmbx,
        created=created,
        body=body,
        reference=reference,
        reason=reason,
        sig=sig,
    )


def open_envelope(msg: Message, recipient_seed: bytes) -> Envelope:
    plaintext = open_layer(
        ENVELOPE_CONTEXT,
        recipient_seed,
        msg.raw_header,
        msg.envelope_layer[0],
        msg.envelope_layer[1],
    )
    return _parse_envelope(wire.decode(plaintext))


def verify_envelope_signature(env: Envelope, raw_header: bytes, sender_key: bytes) -> bool:
    return _verify(sender_key, env.signature_preimage(raw_header), env.sig)
