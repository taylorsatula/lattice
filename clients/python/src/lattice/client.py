"""Synchronous client for the Lattice local API (V2_SPEC §7).

Talks to a running ``latticed`` over its Unix sockets: the application
socket (service-authenticated) or the admin socket (owner-only). Frames are
length-prefixed CBOR; see ``wire.py``.

Typical use::

    from lattice import Client

    with Client.connect_app("/run/lattice/app.sock", "mira", b"secret") as c:
        mid = c.send(to=peer_id, tsvc="mira", tmbx=b"inbox",
                     fmbx=b"outbox", body=b"hello")
        for delivery in c.fetch(16):
            ...
            c.ack([delivery.delivery_id])
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from . import wire
from .errors import BadResponse, ConnectionError_, Rejected, Timeout

# Op codes (wire contract; see lattice-proto local.rs).
OP_HELLO = 1
OP_SEND = 2
OP_STATUS = 3
OP_FETCH = 4
OP_ACK = 5
OP_LOOKUP = 6
OP_NODE = 101
OP_ROTATE = 102
OP_ABANDON = 103
OP_ROTATE_ENVELOPE = 104
OP_LINK = 105
OP_UNLINK = 106
OP_DRAIN = 107

ERR_NOT_FOUND = 4

EVENT_INBOX = 1
EVENT_STATUS = 2

ROUTE_DEFAULT = 0
ROUTE_WAYPOINT = 1
ROUTE_DIRECT = 2

MSG_STATUS_QUEUED = 1
MSG_STATUS_IN_TRANSIT = 2
MSG_STATUS_DELIVERED = 3
MSG_STATUS_FAILED = 4
MSG_STATUS_EXPIRED = 5

_READ_TIMEOUT = 30.0


def _req_uint(result: dict, key: int, name: str) -> int:
    value = result.get(key)
    # bool is a subclass of int; the wire has no booleans in uint fields.
    if type(value) is not int or value < 0:
        raise BadResponse(f"node: missing or invalid {name}")
    return value


def _req_bool(result: dict, key: int, name: str) -> bool:
    value = result.get(key)
    if not isinstance(value, bool):
        raise BadResponse(f"node: missing or invalid {name}")
    return value


@dataclass
class Delivery:
    delivery_id: bytes
    mid: bytes
    from_: bytes
    fsvc: str
    fmbx: bytes
    tmbx: bytes
    body: bytes
    received: int


@dataclass
class Lookup:
    have: bool
    mode: int | None
    path: bool


@dataclass
class NodeInfo:
    id: bytes
    mode: str
    links: int
    records: int
    custody_bytes: int
    draining: bool


@dataclass
class Event:
    event: int
    data: dict

    @property
    def kind(self) -> str:
        return {EVENT_INBOX: "inbox", EVENT_STATUS: "status"}.get(self.event, f"unknown({self.event})")


class Client:
    """A connection to a latticed local socket."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = bytearray()
        self._next_id = 1
        self._events: list[Event] = []
        self.node_id: bytes | None = None
        self.service: str | None = None

    # ---------- connection ----------

    @classmethod
    def connect_app(cls, path: str, service: str, secret: bytes) -> "Client":
        """Connect to the application socket and authenticate as `service`."""
        c = cls._connect(path)
        result = c._call(OP_HELLO, {0: service, 1: secret})
        c.node_id = bytes(result[0])
        c.service = result.get(1, service)
        return c

    @classmethod
    def connect_admin(cls, path: str) -> "Client":
        """Connect to the admin socket (owner-only; no handshake)."""
        return cls._connect(path)

    @classmethod
    def _connect(cls, path: str) -> "Client":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(_READ_TIMEOUT)
        sock.connect(path)
        return cls(sock)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------- application operations ----------

    def send(self, *, to: bytes, tsvc: str, tmbx: bytes, fmbx: bytes, body: bytes,
             exp: int | None = None, priority: int | None = None,
             route: int | None = None) -> bytes:
        """Queue a message; returns the 16-byte message id."""
        if len(to) != 32:
            raise ValueError("to must be a 32-byte id")
        if priority is not None and not 0 <= priority <= 3:
            raise ValueError("priority must be 0..3")
        if route is not None and route not in (ROUTE_DEFAULT, ROUTE_WAYPOINT, ROUTE_DIRECT):
            raise ValueError("route must be 0 (default), 1 (waypoint) or 2 (direct)")
        args: dict = {0: to, 1: tsvc, 2: tmbx, 3: fmbx, 4: body}
        if exp is not None:
            args[5] = exp
        if priority is not None:
            args[6] = priority
        if route is not None:
            args[7] = route
        result = self._call(OP_SEND, args)
        return bytes(result[0])

    def status(self, mid: bytes):
        """Status of a message id, or None if the daemon has no record of it.

        Returns (status, detail) where status is one of MSG_STATUS_*.
        """
        if len(mid) != 16:
            raise ValueError("mid must be 16 bytes")
        try:
            result = self._call(OP_STATUS, {0: mid})
        except Rejected as e:
            if e.code == ERR_NOT_FOUND:
                return None
            raise
        return (result[0], result.get(1))

    def fetch(self, max: int = 16) -> list[Delivery]:
        """Fetch up to `max` deliveries from this service's inbox."""
        result = self._call(OP_FETCH, {0: max})
        items = result.get(0, [])
        return [
            Delivery(
                delivery_id=bytes(item[0]),
                mid=bytes(item[1]),
                from_=bytes(item[2]),
                fsvc=item[3],
                fmbx=bytes(item[4]),
                tmbx=bytes(item[5]),
                body=bytes(item[6]),
                received=item[7],
            )
            for item in items
        ]

    def ack(self, delivery_ids: list[bytes]) -> int:
        """Acknowledge deliveries; returns how many were removed."""
        result = self._call(OP_ACK, {0: list(delivery_ids)})
        return result[0]

    def lookup(self, id: bytes) -> Lookup:
        """Whether a valid record for `id` is held, its mode, and whether a path exists."""
        if len(id) != 32:
            raise ValueError("id must be 32 bytes")
        result = self._call(OP_LOOKUP, {0: id})
        return Lookup(have=bool(result[0]), mode=result.get(1), path=bool(result[2]))

    # ---------- admin operations ----------

    def node(self) -> NodeInfo:
        result = self._call(OP_NODE, {})
        if not isinstance(result, dict):
            raise BadResponse("node: result is not a map")
        node_id = result.get(0)
        if not isinstance(node_id, (bytes, bytearray)) or len(node_id) != 32:
            raise BadResponse("node: missing or invalid id")
        mode = result.get(1)
        if not isinstance(mode, str):
            raise BadResponse("node: missing mode")
        return NodeInfo(
            id=bytes(node_id),
            mode=mode,
            links=_req_uint(result, 2, "links"),
            records=_req_uint(result, 3, "records"),
            custody_bytes=_req_uint(result, 4, "custody_bytes"),
            draining=_req_bool(result, 5, "draining"),
        )

    def drain(self, draining: bool | None = None):
        """Set or query drain mode. Returns (draining, custody_bytes)."""
        args = {} if draining is None else {0: draining}
        result = self._call(OP_DRAIN, args)
        return bool(result[0]), result[1]

    def link(self, addr: str, channel_key: bytes | None = None,
             path: str | None = None, id: bytes | None = None) -> bool:
        """Queue a dial to `addr`. Exactly one of channel_key (IK) or path (XX)."""
        args: dict = {0: addr}
        if channel_key is not None:
            args[1] = channel_key
        if path is not None:
            args[2] = path
        if id is not None:
            args[3] = id
        result = self._call(OP_LINK, args)
        return bool(result[0])

    def unlink(self, id: bytes) -> bool:
        """Drop every link to `id`. Returns True if any were open."""
        result = self._call(OP_UNLINK, {0: id})
        return bool(result[0])

    def rotate(self, next_key: bytes, next_next_commitment: bytes) -> str:
        """Rotate the signing key.

        ``next_key`` is the 32-byte pre-committed next signing key, kept
        offline by the operator. ``next_next_commitment`` is the 32-byte
        BLAKE3 commitment to the following key, generated offline. The
        daemon verifies ``next_key`` against the commitment stored in its
        identity directory and refuses the rotation on mismatch.
        """
        if len(next_key) != 32 or len(next_next_commitment) != 32:
            raise ValueError("next_key and next_next_commitment must be 32 bytes each")
        return self._call(OP_ROTATE, {0: next_key, 1: next_next_commitment})[0]

    def abandon(self, next_key: bytes) -> str:
        """Permanently abandon the identity (a rotation with no next-key commitment).

        ``next_key`` is the 32-byte pre-committed next signing key, kept
        offline by the operator.
        """
        if len(next_key) != 32:
            raise ValueError("next_key must be 32 bytes")
        return self._call(OP_ABANDON, {0: next_key})[0]

    def rotate_envelope(self) -> str:
        """Rotate the envelope key; the old key is kept decrypt-only for a grace period."""
        return self._call(OP_ROTATE_ENVELOPE, {})[0]

    # ---------- events ----------

    def take_events(self) -> list[Event]:
        """Drain events received while waiting for responses."""
        events, self._events = self._events, []
        return events

    def next_event(self, timeout: float | None = None) -> Event:
        """Block until the next event arrives.

        Only call this when no request is in flight. Events received while
        waiting for a response are stashed and returned first.
        """
        if self._events:
            return self._events.pop(0)
        payload = self._read_frame(timeout)
        obj = wire.decode(payload)
        if isinstance(obj, dict) and 3 in obj:
            return Event(event=obj[3], data=obj.get(2, {}))
        raise BadResponse("expected an event frame, got a response")

    # ---------- internals ----------

    def _call(self, op: int, args: dict):
        req_id = self._next_id
        self._next_id += 1
        frame = wire.frame(wire.encode({0: req_id, 1: op, 2: args}))
        self._sock.sendall(frame)
        while True:
            payload = self._read_frame(_READ_TIMEOUT)
            obj = wire.decode(payload)
            if not isinstance(obj, dict):
                raise BadResponse("frame is not a map")
            if 3 in obj:  # event, stash it
                self._events.append(Event(event=obj[3], data=obj.get(2, {})))
                continue
            rid = obj.get(0)
            if rid != req_id:
                raise BadResponse("response id mismatch")
            if 1 in obj:
                return obj[1]
            if 2 in obj:
                raise Rejected(obj[2])
            raise BadResponse("response carries neither result nor error")

    def _read_frame(self, timeout: float | None) -> bytes:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            payload, used = wire.deframe(self._buf)
            if payload is not None:
                del self._buf[:used]
                return payload
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise Timeout("timed out waiting for the daemon")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(8192)
            except socket.timeout as e:
                raise Timeout("timed out waiting for the daemon") from e
            if not chunk:
                raise ConnectionError_("daemon closed the socket")
            self._buf.extend(chunk)
            if len(self._buf) > wire.LOCAL_MAX_FRAME + wire.LOCAL_PREFIX_LEN:
                raise BadResponse("frame exceeds maximum size")
