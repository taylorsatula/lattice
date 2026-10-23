"""
In-process Lattice networks.

Each node is a full DiscoveryService with its own SQLite database, served by
its own FastAPI app. Outbound HTTP from every node goes through one
MockTransport that routes requests by host to the target node's app, so
tests exercise the real endpoints on both ends.
"""

import uuid
from datetime import timedelta
from typing import Dict

import httpx
import pytest
from fastapi.testclient import TestClient

from lattice import crypto
from lattice.discovery_daemon import DiscoveryService, create_app
from lattice.identity import Identity
from lattice.sqlite_client import SQLiteClient

ADMIN_TOKEN = "test-admin-token"
ADMIN_HEADERS = {"X-Lattice-Admin-Token": ADMIN_TOKEN}

# Public IP literals: endpoint validation rejects private ranges and would resolve hostnames.
HOSTS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4", "149.112.112.112"]


class Network:
    """Routes HTTP between in-process apps by host. Unregistered hosts are unreachable."""

    def __init__(self):
        self.apps: Dict[str, TestClient] = {}

    def handle(self, request: httpx.Request) -> httpx.Response:
        app = self.apps.get(request.url.host)
        if app is None:
            raise httpx.ConnectError(f"{request.url.host} is unreachable", request=request)
        response = app.request(request.method, request.url.path, content=request.content, headers=dict(request.headers))
        return httpx.Response(response.status_code, headers=response.headers, content=response.content)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handle))


class Node:
    """A running Lattice server on the test network."""

    def __init__(self, network: Network, db_path: str, name: str, host: str):
        self.host = host
        self.service = DiscoveryService(db=SQLiteClient(db_path), http=network.client())
        self.service.use_identity(Identity(name, str(uuid.uuid4()), f"https://{host}", crypto.generate_private_key()))
        self.api = TestClient(create_app(self.service))
        network.apps[host] = self.api

    @property
    def identity(self) -> Identity:
        return self.service.identity

    @property
    def trust(self):
        return self.service.trust

    @property
    def uuid(self) -> str:
        return self.identity.server_uuid

    def peer(self, other: "Node"):
        """This node's record of `other`, or None."""
        return self.service.peers.get(other.uuid)

    def invite(self, ttl: timedelta = timedelta(hours=1)) -> str:
        return self.trust.create_invite(ttl)[0]


def pair(inviter: Node, invitee: Node) -> None:
    invitee.trust.accept_invite(inviter.invite())


@pytest.fixture
def network():
    return Network()


@pytest.fixture
def make_node(network, tmp_path, monkeypatch):
    monkeypatch.setenv("LATTICE_ADMIN_TOKEN", ADMIN_TOKEN)
    hosts = iter(HOSTS)

    def _make(name: str) -> Node:
        return Node(network, str(tmp_path / f"{name}.db"), name, next(hosts))

    return _make
