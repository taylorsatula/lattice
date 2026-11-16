"""Integration test: the Python client against a live latticed daemon.

Boots two real daemons on loopback (like the Rust e2e suite) and drives
them through the local API: hello, send, fetch, ack, status, lookup, and
the inbox/status events.

The daemon binary is located via $LATTICE_DAEMON, else target/debug/latticed
or target/release/latticed relative to the repo root. If none exists, the
test builds it with `cargo build -p latticed`.
"""

import base64
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SECRET = b"test-secret-with-plenty-of-entropy"


def find_daemon() -> Path:
    env = os.environ.get("LATTICE_DAEMON")
    if env:
        return Path(env)
    for profile in ("debug", "release"):
        candidate = REPO_ROOT / "target" / profile / "latticed"
        if candidate.exists():
            return candidate
    subprocess.run(["cargo", "build", "-p", "latticed"], cwd=REPO_ROOT, check=True)
    return REPO_ROOT / "target" / "debug" / "latticed"


def parse_node_id(text: str) -> bytes:
    """Parse the `node id:` line printed by `latticed init`.

    Current daemons print the 52-char lowercase base32 text form (RFC 4648,
    no padding); older ones printed 64-char hex. Both are accepted.
    """
    token = text.strip()
    if len(token) == 64:
        return bytes.fromhex(token)
    if len(token) == 52:
        padded = token.upper() + "=" * ((8 - len(token) % 8) % 8)
        raw = base64.b32decode(padded)
        if len(raw) != 32:
            raise ValueError(f"base32 node id decoded to {len(raw)} bytes, expected 32")
        return raw
    raise ValueError(f"unrecognized node id form: {token!r}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def init_node(daemon: Path, dir: Path) -> tuple[bytes, bytes]:
    out = subprocess.run(
        [str(daemon), "init", "--dir", str(dir)],
        check=True, capture_output=True, text=True,
    ).stdout
    id_text = next(
        line.split(":", 1)[1].strip()
        for line in out.splitlines()
        if line.startswith("node id:")
    )
    node_id = parse_node_id(id_text)
    channel_key = (dir / "channel_key.pub").read_bytes()
    return node_id, channel_key


def write_config(dir: Path, port: int, app: Path, admin: Path,
                 peer: tuple[str, bytes, bytes] | None):
    roots = ""
    if peer:
        addr, key, node_id = peer
        roots = (
            f'[[roots]]\naddr = "{addr}"\n'
            f'channel_key = "{key.hex()}"\nid = "{node_id.hex()}"\n'
        )
    config = dir / "lattice.toml"
    config.write_text(
        f"""identity_dir = "{dir}"
mode = "public"
listen = ["127.0.0.1:{port}"]
app_socket = "{app}"
admin_socket = "{admin}"

[services]
test = {{ secret = "{SECRET.decode()}" }}

[limits]
reconcile_interval_secs = 1

{roots}"""
    )
    # The daemon refuses to start if the config (which carries service
    # secrets) is readable by group/other.
    config.chmod(0o600)


class Node:
    def __init__(self, daemon: Path, tmp: Path, name: str,
                 peer: tuple[str, bytes, bytes] | None):
        self.dir = tmp / name
        self.dir.mkdir(parents=True)
        self.id, self.channel_key = init_node(daemon, self.dir)
        self.port = free_port()
        self.app = tmp / f"{name}.app.sock"
        self.admin = tmp / f"{name}.admin.sock"
        write_config(self.dir, self.port, self.app, self.admin, peer)
        self.log = open(self.dir / "daemon.log", "wb")
        self.proc = subprocess.Popen(
            [str(daemon), "run", "--config", str(self.dir / "lattice.toml")],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )

    def wait_sockets(self, timeout: float = 15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.log.flush()
                raise RuntimeError(
                    f"daemon exited early (code {self.proc.returncode}); log:\n"
                    + (self.dir / "daemon.log").read_text()
                )
            ok = True
            for sock in (self.app, self.admin):
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(0.2)
                    s.connect(str(sock))
                    s.close()
                except OSError:
                    ok = False
            if ok:
                return
            time.sleep(0.1)
        self.log.flush()
        raise TimeoutError(
            f"daemon sockets never came up for {self.dir}; log:\n"
            + (self.dir / "daemon.log").read_text()
        )

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture()
def daemon():
    return find_daemon()


@pytest.fixture()
def two_nodes(daemon):
    # Unix socket paths must fit in SUN_LEN (~104 bytes on macOS), so use a
    # short temp dir rather than pytest's deep tmp_path.
    tmp = Path(tempfile.mkdtemp(prefix="lattice-it-", dir="/tmp"))
    a = Node(daemon, tmp, "a", None)
    b_addr = f"127.0.0.1:{a.port}"
    # B dials A; A learns B through gossip.
    b = Node(daemon, tmp, "b", (b_addr, a.channel_key, a.id))
    a.wait_sockets()
    b.wait_sockets()
    yield a, b
    a.stop()
    b.stop()
    shutil.rmtree(tmp, ignore_errors=True)


def wait_for_path(client, target: bytes, timeout: float = 60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lookup = client.lookup(target)
        if lookup.have and lookup.path:
            return
        time.sleep(0.25)
    raise TimeoutError("never learned a path")


def test_send_fetch_ack_roundtrip(daemon, two_nodes):
    from lattice import Client, MSG_STATUS_DELIVERED

    a, b = two_nodes
    with Client.connect_app(str(a.app), "test", SECRET) as ca, \
         Client.connect_app(str(b.app), "test", SECRET) as cb:
        wait_for_path(ca, b.id)

        mid = ca.send(to=b.id, tsvc="test", tmbx=b"inbox", fmbx=b"outbox",
                      body=b"hello from python", route=2)
        assert isinstance(mid, bytes) and len(mid) == 16

        # B fetches the delivery.
        deadline = time.monotonic() + 30
        delivery = None
        while time.monotonic() < deadline:
            for d in cb.fetch(16):
                if d.mid == mid:
                    delivery = d
                    break
            if delivery:
                break
            time.sleep(0.25)
        assert delivery is not None, "message never arrived at B"
        assert delivery.body == b"hello from python"
        assert delivery.from_ == a.id
        assert delivery.fsvc == "test"

        # Ack it; the inbox drains.
        assert cb.ack([delivery.delivery_id]) == 1
        assert cb.fetch(16) == []

        # A observes the delivered status once B's receipt lands.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status = ca.status(mid)
            if status and status[0] == MSG_STATUS_DELIVERED:
                break
            time.sleep(0.25)
        else:
            pytest.fail("sender never observed Delivered status")


def test_hello_rejects_wrong_secret(daemon, two_nodes):
    from lattice import Client, Rejected

    a, _ = two_nodes
    with pytest.raises(Rejected):
        Client.connect_app(str(a.app), "test", b"wrong-secret-00000000000000000")


def test_lookup_reports_path(daemon, two_nodes):
    from lattice import Client

    a, b = two_nodes
    with Client.connect_app(str(a.app), "test", SECRET) as ca:
        wait_for_path(ca, b.id)
        lookup = ca.lookup(b.id)
        assert lookup.have is True
        assert lookup.path is True


def test_events_arrive(daemon, two_nodes):
    from lattice import Client, EVENT_INBOX

    a, b = two_nodes
    with Client.connect_app(str(a.app), "test", SECRET) as ca, \
         Client.connect_app(str(b.app), "test", SECRET) as cb:
        wait_for_path(ca, b.id)
        mid = ca.send(to=b.id, tsvc="test", tmbx=b"inbox", fmbx=b"outbox",
                      body=b"event probe", route=2)
        # B should see an inbox event when the message lands.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                ev = cb.next_event(timeout=2.0)
            except Exception:
                continue
            if ev.event == EVENT_INBOX:
                break
        else:
            pytest.fail("no inbox event observed")


def test_admin_node_info(daemon, two_nodes):
    from lattice import Client

    a, _ = two_nodes
    with Client.connect_admin(str(a.admin)) as admin:
        info = admin.node()
        assert info.id == a.id
        assert info.mode == "public"
        assert info.draining is False
        draining, _ = admin.drain(True)
        assert draining is True
        draining, _ = admin.drain(False)
        assert draining is False
