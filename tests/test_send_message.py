"""
Message sending, delivery and receipt.

Uses real SQLite databases and real Ed25519 signing. The remote server is
either mocked at _send_to_remote_server or a second in-process node.
"""

import json
import uuid
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from lattice import username_resolver
from lattice.models import FederatedMessage, MessageAcknowledgment

from conftest import ADMIN_HEADERS, pair


@pytest.fixture
def nodes(make_node):
    local, remote = make_node("local"), make_node("remote")
    pair(local, remote)
    return local, remote


def queued(node, message_id):
    row = node.service.db.execute_single("SELECT * FROM lattice_messages WHERE message_id = ?", (message_id,))
    return row, FederatedMessage(**json.loads(row["message"]))


def send(node, **overrides):
    body = {"to_address": "alice@remote", "from_address": "bob@local", "content": "Hello, Alice!", **overrides}
    return node.api.post("/api/v1/messages/send", json=body, headers=ADMIN_HEADERS)


def circuit_failures(node, peer):
    return node.service.db.execute_single(
        "SELECT circuit_failures FROM lattice_peers WHERE server_uuid = ?", (peer.uuid,)
    )["circuit_failures"]


def remote_ack(remote, message_id, rejection=None):
    return remote.service._ack(message_id, rejection)


def accepted_by(remote):
    return lambda _url, data: {"status": "accepted", "ack": remote_ack(remote, data["message_id"])}


class TestSendEndpoint:
    def test_message_is_signed_and_queued(self, nodes):
        local, _ = nodes
        with patch.object(local.service, "_send_to_remote_server", return_value=None):
            response = send(local)

        assert response.status_code == 200
        row, message = queued(local, response.json()["message_id"])
        assert row["to_domain"] == "remote"
        assert row["status"] == "pending"
        assert row["expires_at"] > row["created_at"]
        assert message.content == "Hello, Alice!"
        assert message.verify(local.identity.public_key)

    def test_addresses_are_normalized_to_lowercase(self, nodes):
        local, _ = nodes
        with patch.object(local.service, "_send_to_remote_server", return_value=None):
            response = send(local, to_address="ALICE@REMOTE", from_address="BOB@LOCAL")

        row, message = queued(local, response.json()["message_id"])
        assert (message.to_address, message.from_address, row["to_domain"]) == ("alice@remote", "bob@local", "remote")

    def test_priority_and_metadata_are_signed(self, nodes):
        local, _ = nodes
        metadata = {"thread_id": "abc123", "tags": ["urgent", "work"]}
        with patch.object(local.service, "_send_to_remote_server", return_value=None):
            response = send(local, priority=2, metadata=metadata)

        row, message = queued(local, response.json()["message_id"])
        assert row["priority"] == 2
        assert message.metadata == metadata
        assert message.verify(local.identity.public_key)

    @pytest.mark.parametrize("field", ["to_address", "from_address"])
    def test_invalid_address_is_rejected(self, nodes, field):
        assert send(nodes[0], **{field: "no-at-sign"}).status_code == 400

    def test_foreign_sender_domain_is_rejected(self, nodes):
        assert send(nodes[0], from_address="bob@elsewhere").status_code == 400

    def test_oversized_content_is_rejected(self, nodes):
        assert send(nodes[0], content="x" * 10001).status_code == 422

    def test_priority_out_of_range_is_rejected(self, nodes):
        assert send(nodes[0], priority=5).status_code == 422

    def test_requires_admin_token(self, nodes):
        response = nodes[0].api.post("/api/v1/messages/send", json={"to_address": "a@remote", "from_address": "b@local", "content": "x"})
        assert response.status_code == 403


class TestDelivery:
    def test_successful_delivery_marks_delivered(self, nodes):
        local, remote = nodes
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "hi")

        with patch.object(local.service, "_send_to_remote_server", side_effect=accepted_by(remote)) as mock_send:
            local.service.deliver_message_async(message_id)

        row, _ = queued(local, message_id)
        assert row["status"] == "delivered"
        assert json.loads(row["ack_data"])["status"] == "delivered"
        assert mock_send.call_args[0][0] == f"{remote.identity.endpoint}/api/v1/federation/messages/receive"

    def test_failed_delivery_is_retried(self, nodes):
        local, _ = nodes
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "hi")

        with patch.object(local.service, "_send_to_remote_server", return_value=None):
            local.service.deliver_message_async(message_id)

        row, _ = queued(local, message_id)
        assert (row["status"], row["attempt_count"]) == ("pending", 1)
        assert row["last_error"]

    def test_signed_rejection_fails_permanently(self, nodes):
        local, remote = nodes
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "hi")

        with patch.object(local.service, "_send_to_remote_server", side_effect=lambda _url, data: {
            "status": "rejected", "ack": remote_ack(remote, data["message_id"], "Unknown recipient")
        }):
            local.service.deliver_message_async(message_id)

        row, _ = queued(local, message_id)
        assert (row["status"], row["attempt_count"]) == ("failed", 0)
        assert "Unknown recipient" in row["last_error"]
        assert json.loads(row["ack_data"])["status"] == "rejected"
        assert circuit_failures(local, remote) == 0

    @pytest.mark.parametrize("response", [
        {"status": "rejected"},
        "forged",
    ])
    def test_missing_or_forged_ack_is_retryable(self, nodes, response):
        local, remote = nodes
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "hi")

        def reply(_url, data):
            if response == "forged":
                ack = remote_ack(remote, data["message_id"], "Unknown recipient")
                ack["error_message"] = "tampered"
                return {"status": "rejected", "ack": ack}
            return response

        with patch.object(local.service, "_send_to_remote_server", side_effect=reply):
            local.service.deliver_message_async(message_id)

        row, _ = queued(local, message_id)
        assert (row["status"], row["attempt_count"]) == ("pending", 1)
        assert circuit_failures(local, remote) == 1

    def test_ack_from_another_server_is_rejected(self, nodes, make_node):
        local, remote = nodes
        other = make_node("other")
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "hi")
        ack = other.identity.sign(MessageAcknowledgment(
            ack_type="message_received", message_id=message_id, status="delivered", recipient_server="remote"
        )).model_dump()

        with patch.object(local.service, "_send_to_remote_server", return_value={"status": "accepted", "ack": ack}):
            local.service.deliver_message_async(message_id)

        assert queued(local, message_id)[0]["status"] == "pending"

    def test_unknown_message_is_ignored(self, nodes):
        nodes[0].service.deliver_message_async(str(uuid.uuid4()))

    def test_delivered_message_is_not_resent(self, nodes):
        local, _ = nodes
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "hi")
        local.service.db.execute("UPDATE lattice_messages SET status = 'delivered' WHERE message_id = ?", (message_id,))

        with patch.object(local.service, "_send_to_remote_server") as mock_send:
            local.service.deliver_message_async(message_id)
        mock_send.assert_not_called()

    def test_send_endpoint_attempts_immediate_delivery(self, nodes):
        local, remote = nodes
        with patch.object(local.service, "_send_to_remote_server", side_effect=accepted_by(remote)):
            response = send(local)
        assert queued(local, response.json()["message_id"])[0]["status"] == "delivered"


class TestEndToEnd:
    @pytest.fixture
    def webhook(self, network, monkeypatch):
        received = []
        app = FastAPI()

        @app.post("/deliver")
        async def deliver(request: Request):
            received.append(await request.json())
            return {"ok": True}

        network.apps["webhook.local"] = TestClient(app)
        monkeypatch.setenv("LATTICE_DELIVERY_WEBHOOK", "https://webhook.local/deliver")
        monkeypatch.setattr(username_resolver, "_username_resolver", lambda name: "user-1" if name == "alice" else None)
        return received

    def test_message_reaches_the_remote_webhook(self, nodes, webhook):
        local, remote = nodes
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "Room 302", priority=2)

        assert local.service.process_message_queue()["delivered"] == 1
        assert queued(local, message_id)[0]["status"] == "delivered"
        assert webhook == [{
            "from_address": "bob@local",
            "to_user_id": "user-1",
            "content": "Room 302",
            "priority": 2,
            "message_id": message_id,
            "metadata": {},
            "sender_verified": True,
            "sender_server_id": "local"
        }]

    def test_unknown_recipient_is_rejected_permanently(self, nodes, webhook):
        local, _ = nodes
        message_id = local.service.queue_outbound_message("nobody@remote", "bob@local", "hi")

        local.service.process_message_queue()

        assert queued(local, message_id)[0]["status"] == "failed"
        assert webhook == []

    def test_redelivery_is_idempotent(self, nodes, webhook):
        local, remote = nodes
        message_id = local.service.queue_outbound_message("alice@remote", "bob@local", "hi")
        _, message = queued(local, message_id)
        url = f"{remote.identity.endpoint}/api/v1/federation/messages/receive"

        first = local.service.http.post(url, json=message.model_dump()).json()
        second = local.service.http.post(url, json=message.model_dump()).json()

        assert first == second
        assert len(webhook) == 1

    def test_message_from_unpaired_server_is_rejected(self, nodes, make_node, webhook):
        _, remote = nodes
        stranger = make_node("stranger")
        message = stranger.identity.sign(FederatedMessage(from_address="eve@stranger", to_address="alice@remote", content="hi"))

        response = stranger.service.http.post(f"{remote.identity.endpoint}/api/v1/federation/messages/receive", json=message.model_dump())

        assert response.status_code == 403
        assert webhook == []

    def test_forged_message_is_rejected(self, nodes, make_node, webhook):
        local, remote = nodes
        forger = make_node("forger")
        message = forger.identity.sign(FederatedMessage(from_address="bob@local", to_address="alice@remote", content="hi"))

        response = local.service.http.post(f"{remote.identity.endpoint}/api/v1/federation/messages/receive", json=message.model_dump())

        assert response.status_code == 403
        assert webhook == []
