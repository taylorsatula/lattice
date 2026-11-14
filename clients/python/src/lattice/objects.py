"""Lattice object parsing and verification (V2_SPEC §2, §3, §5).

These are the wire objects: key events, peer records and messages. The
local API does not require them, but they are needed to verify the shared
test vectors and are useful to applications that want to check records or
messages themselves.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import wire
from .crypto import open_layer, ENVELOPE_CONTEXT

PROTOCOL_VERSION = 1
EVENT_INCEPTION = 1
EVENT_ROTATION = 2
KIND_RECORD = 10

KIND_MESSAGE = 0
KIND_RECEIPT = 1
KIND_NEGATIVE_RECEIPT = 2

MESSAGE_BUCKETS = (2048 - 64, 8192 - 64, 32768 - 64)
MAX_MESSAGE_HORIZON = 14 * 24 * 3600
CLOCK_SKEW = 6 * 3600
KEM_CIPHERTEXT_LEN = 1120


def _b3(data: bytes) -> bytes:
    return blake3.blake3(data).digest()


def _verify(pubkey: bytes, message: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


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
        return _verify(self.key, self.unsigned_bytes(), self.sig)


def parse_key_event(data: bytes) -> KeyEvent:
    obj = wire.decode(data)
    if not isinstance(obj, dict):
        raise ValueError("key event must be a map")
    if obj.get(0) != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")
    kind = obj[1]
    if kind not in (EVENT_INCEPTION, EVENT_ROTATION):
        raise ValueError("unknown key event kind")
    prev = obj.get(3)
    nxt = obj.get(5)
    return KeyEvent(
        kind=kind,
        seq=obj[2],
        prev=bytes(prev) if prev is not None else None,
        key=bytes(obj[4]),
        next=bytes(nxt) if nxt is not None else None,
        sig=bytes(obj[6]),
    )


def kel_identifier(events: list[KeyEvent]) -> bytes:
    if not events or events[0].kind != EVENT_INCEPTION:
        raise ValueError("KEL must start with an inception event")
    return _b3(events[0].unsigned_bytes())


def validate_kel(events: list[KeyEvent]) -> None:
    """Validate a KEL the way the Rust implementation does."""
    if not events:
        raise ValueError("empty KEL")
    first = events[0]
    if first.kind != EVENT_INCEPTION or first.seq != 0 or first.prev is not None:
        raise ValueError("first event is not a valid inception")
    if not first.verify_signature():
        raise ValueError("inception signature invalid")
    prev = first
    for ev in events[1:]:
        if ev.kind != EVENT_ROTATION:
            raise ValueError("non-rotation after inception")
        if ev.seq != prev.seq + 1:
            raise ValueError("KEL sequence gap")
        if ev.prev != prev.commitment():
            raise ValueError("KEL chain broken")
        # The rotation's key must match the previous event's next-key commitment.
        if prev.next is not None and _b3(ev.key) != prev.next:
            raise ValueError("rotation key does not match the previous commitment")
        if not ev.verify_signature():
            raise ValueError("rotation signature invalid")
        prev = ev


# ---------- peer records ----------

@dataclass
class PeerRecord:
    id: bytes
    scope: int
    seq: int
    exp: int
    kel: list[KeyEvent]
    channel_key: bytes
    envelope_key: bytes
    mode: int
    endpoints: list = field(default_factory=list)
    links: list = field(default_factory=list)
    gateways: list = field(default_factory=list)
    capabilities: int = 0
    sig: bytes = b""
    channel_sig: bytes = b""

    def unsigned_value(self) -> dict:
        pairs = {
            0: PROTOCOL_VERSION,
            1: KIND_RECORD,
            2: self.id,
            3: self.scope,
            4: self.seq,
            5: self.exp,
            6: [e.to_value() for e in self.kel],
            7: self.channel_key,
            8: self.envelope_key,
            9: self.mode,
        }
        if self.mode == 0:  # public
            pairs[10] = [
                ({0: e["url"], **({1: e["ips"]} if e.get("ips") else {})})
                for e in self.endpoints
            ]
            pairs[11] = list(self.links)
        else:
            pairs[12] = list(self.gateways)
        pairs[13] = self.capabilities
        return pairs

    def unsigned_bytes(self) -> bytes:
        return wire.encode(self.unsigned_value())

    def current_signing_key(self) -> bytes:
        return self.kel[-1].key


def parse_record(data: bytes, now: int | None = None) -> PeerRecord:
    obj = wire.decode(data)
    if not isinstance(obj, dict):
        raise ValueError("record must be a map")
    if obj.get(0) != PROTOCOL_VERSION or obj.get(1) != KIND_RECORD:
        raise ValueError("not a peer record")
    kel = [parse_key_event(wire.encode(e)) for e in obj[6]]
    mode = obj[9]
    rec = PeerRecord(
        id=bytes(obj[2]),
        scope=obj[3],
        seq=obj[4],
        exp=obj[5],
        kel=kel,
        channel_key=bytes(obj[7]),
        envelope_key=bytes(obj[8]),
        mode=mode,
        endpoints=[
            {"url": e[0], **({"ips": e[1]} if 1 in e else {})} for e in obj.get(10, [])
        ],
        links=[bytes(l) for l in obj.get(11, [])],
        gateways=[bytes(g) for g in obj.get(12, [])],
        capabilities=obj.get(13, 0),
        sig=bytes(obj[14]),
        channel_sig=bytes(obj[15]),
    )
    if now is not None and rec.exp <= now:
        raise ValueError("record expired")
    validate_kel(rec.kel)
    if kel_identifier(rec.kel) != rec.id:
        raise ValueError("record id does not match its KEL")
    preimage = rec.unsigned_bytes()
    if not _verify(rec.current_signing_key(), preimage, rec.sig):
        raise ValueError("record signature invalid")
    if not _verify(rec.channel_key, preimage, rec.channel_sig):
        raise ValueError("record channel signature invalid")
    return rec


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
    if set(obj) != {0, 1}:
        raise ValueError("sealed layer must have exactly keys 0 and 1")
    kem = obj[0]
    ct = obj[1]
    if not isinstance(kem, bytes) or len(kem) != KEM_CIPHERTEXT_LEN:
        raise ValueError("sealed layer KEM ciphertext must be 1120 bytes")
    if not isinstance(ct, bytes):
        raise ValueError("sealed layer ciphertext must be bytes")
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
    if header.get(0) != PROTOCOL_VERSION or header.get(1) != 30:
        raise ValueError("not a routing header")
    if not isinstance(header.get(2), bytes) or len(header[2]) != 16:
        raise ValueError("bad leg id")
    if not isinstance(header.get(3), bytes) or len(header[3]) != 32:
        raise ValueError("bad dst")
    if not isinstance(header.get(4), int):
        raise ValueError("bad expiry")
    if now is not None:
        if header[4] <= now:
            raise ValueError("message expired")
        if header[4] > now + MAX_MESSAGE_HORIZON + CLOCK_SKEW:
            raise ValueError("message expiry beyond the horizon")
    if hop_layer is not None:
        hop_layer = _parse_sealed_layer(hop_layer)
    envelope = _parse_sealed_layer(envelope)
    if not isinstance(padding, bytes) or any(padding):
        raise ValueError("padding must be zero bytes")
    # Re-encode the header to recover its exact bytes for use as AAD. The
    # codec is canonical, so this is byte-identical to the original.
    raw_header = wire.encode(header)
    if not data.startswith(b"\x84" + raw_header):
        raise ValueError("header re-encoding mismatch")
    return Message(
        raw=data,
        header=header,
        hop_layer=hop_layer,
        envelope_layer=envelope,
        padding=padding,
        raw_header=raw_header,
    )


def open_envelope(msg: Message, recipient_seed: bytes) -> Envelope:
    plaintext = open_layer(
        ENVELOPE_CONTEXT,
        recipient_seed,
        msg.raw_header,
        msg.envelope_layer[0],
        msg.envelope_layer[1],
    )
    obj = wire.decode(plaintext)
    return Envelope(
        kind=obj[0],
        mid=bytes(obj[11]),
        from_=bytes(obj[1]),
        fsvc=obj[2],
        fmbx=bytes(obj[3]),
        tsvc=obj[4],
        tmbx=bytes(obj[5]),
        created=obj[6],
        body=bytes(obj[7]) if 7 in obj else None,
        reference=bytes(obj[8]) if 8 in obj else None,
        reason=obj.get(9),
        sig=bytes(obj[10]),
    )


def verify_envelope_signature(env: Envelope, raw_header: bytes, sender_key: bytes) -> bool:
    preimage = raw_header + env.unsigned_bytes()
    return _verify(sender_key, preimage, env.sig)
