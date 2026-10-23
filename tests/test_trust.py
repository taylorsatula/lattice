"""
Out-of-band pairing, introductions and key cross-checks across in-process nodes.
"""

from datetime import timedelta

import pytest

from lattice import crypto
from lattice.models import GossipMessage, Introduction, PairRequest, PeerRecord, ServerAnnouncement
from lattice.trust import InviteToken, TrustError, pairing_proof

from conftest import ADMIN_HEADERS, pair


def gossip(sender, recipient, payload):
    """POST a gossip payload from sender to recipient; returns the HTTP status."""
    return sender.service.http.post(
        f"{recipient.identity.endpoint}/api/v1/gossip/receive",
        json=GossipMessage.wrap(payload).model_dump()
    ).status_code


class TestPairing:
    def test_invite_pairs_both_servers_directly(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")

        pair(alpha, bravo)

        assert alpha.peer(bravo)["trust"] == "direct"
        assert bravo.peer(alpha)["trust"] == "direct"
        assert alpha.peer(bravo)["public_key"] == bravo.identity.public_key
        assert bravo.peer(alpha)["public_key"] == alpha.identity.public_key

    def test_pairing_through_admin_endpoints(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")

        token = alpha.api.post("/api/v1/invites", json={"ttl_hours": 2}, headers=ADMIN_HEADERS).json()["token"]
        response = bravo.api.post("/api/v1/invites/accept", json={"token": token}, headers=ADMIN_HEADERS)

        assert response.status_code == 200
        assert response.json()["server_id"] == "alpha"
        assert alpha.peer(bravo)["trust"] == "direct"

    def test_invite_endpoints_require_admin_token(self, make_node):
        alpha = make_node("alpha")
        assert alpha.api.post("/api/v1/invites", json={}).status_code == 403

    def test_invite_is_single_use(self, make_node):
        alpha, bravo, charlie = make_node("alpha"), make_node("bravo"), make_node("charlie")
        token = alpha.invite()
        bravo.trust.accept_invite(token)

        with pytest.raises(TrustError, match="Unknown or expired invite"):
            charlie.trust.accept_invite(token)
        assert alpha.peer(charlie) is None
        assert charlie.peer(alpha) is None

    def test_expired_invite_is_rejected(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")

        with pytest.raises(TrustError, match="Unknown or expired invite"):
            bravo.trust.accept_invite(alpha.invite(ttl=timedelta(seconds=-1)))
        assert bravo.peer(alpha) is None

    def test_impostor_at_inviters_address_is_rejected(self, make_node, network):
        """A man-in-the-middle answering at the inviter's endpoint cannot match the key in the token."""
        alpha, bravo, mallory = make_node("alpha"), make_node("bravo"), make_node("mallory")
        token = alpha.invite()
        network.apps[alpha.host] = mallory.api

        with pytest.raises(TrustError, match="not signed by the key in the invite"):
            bravo.trust.accept_invite(token)
        assert bravo.service.peers.with_trust("direct") == []
        assert mallory.service.peers.with_trust("direct") == []

    def test_substituted_invitee_key_is_rejected(self, make_node):
        """A man-in-the-middle swapping in its own announcement cannot produce the proof."""
        alpha, bravo, mallory = make_node("alpha"), make_node("bravo"), make_node("mallory")
        token = InviteToken.decode(alpha.invite())
        honest_proof = pairing_proof(token.secret, token.public_key, bravo.identity.public_key)

        with pytest.raises(TrustError, match="Invalid pairing proof"):
            alpha.trust.handle_pair(PairRequest(
                invite_id=token.invite_id,
                announcement=mallory.identity.announcement(),
                proof=honest_proof
            ))
        assert alpha.peer(mallory) is None

    def test_pair_endpoint_rejects_bad_proof(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")
        token = InviteToken.decode(alpha.invite())
        request = PairRequest(invite_id=token.invite_id, announcement=bravo.identity.announcement(), proof="AAAA")

        assert alpha.api.post("/api/v1/pair", json=request.model_dump()).status_code == 403
        bravo.trust.accept_invite(token.encode())  # the failed attempt did not burn the invite
        assert alpha.peer(bravo)["trust"] == "direct"

    def test_name_collision_blocks_pairing(self, make_node):
        alpha, bravo, imposter = make_node("alpha"), make_node("bravo"), make_node("bravo")
        pair(alpha, bravo)

        with pytest.raises(TrustError, match="belongs to"):
            imposter.trust.accept_invite(alpha.invite())
        assert alpha.peer(imposter) is None

    @pytest.mark.parametrize("token", ["", "lattice2:abc", "lattice1:!!!", "lattice1:" + crypto.b64encode(b"x" * 40)])
    def test_malformed_tokens_are_rejected(self, token):
        with pytest.raises(TrustError):
            InviteToken.decode(token)

    def test_token_rejects_internal_endpoint(self):
        raw = b"k" * 32 + b"s" * 16 + b"https://127.0.0.1"
        with pytest.raises(TrustError, match="internal"):
            InviteToken.decode("lattice1:" + crypto.b64encode(raw))


class TestGossipAuthentication:
    def test_unknown_sender_is_rejected(self, make_node):
        alpha, mallory = make_node("alpha"), make_node("mallory")
        assert gossip(mallory, alpha, mallory.identity.announcement()) == 403
        assert alpha.peer(mallory) is None

    def test_announcement_under_a_different_key_is_rejected(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")
        pair(alpha, bravo)
        other_key = crypto.generate_private_key()
        forged = ServerAnnouncement(
            server_uuid=bravo.uuid,
            server_id="bravo",
            public_key=crypto.public_key_of(other_key),
            endpoint=bravo.identity.endpoint
        ).sign(other_key)

        assert gossip(bravo, alpha, forged) == 403
        assert alpha.peer(bravo)["public_key"] == bravo.identity.public_key

    def test_tampered_announcement_is_rejected(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")
        pair(alpha, bravo)
        tampered = bravo.identity.announcement()
        tampered.endpoint = "https://149.112.112.112"

        assert gossip(bravo, alpha, tampered) == 403
        assert alpha.peer(bravo)["endpoint"] == bravo.identity.endpoint

    def test_key_rotation_carries_trust_to_the_new_key(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")
        pair(alpha, bravo)

        assert gossip(bravo, alpha, bravo.identity.rotate()) == 200
        assert alpha.peer(bravo)["public_key"] == bravo.identity.public_key
        assert gossip(bravo, alpha, bravo.identity.announcement()) == 200

    def test_revocation_cuts_the_server_off(self, make_node):
        alpha, bravo = make_node("alpha"), make_node("bravo")
        pair(alpha, bravo)

        assert gossip(bravo, alpha, bravo.identity.revocation("decommissioned")) == 200
        assert alpha.peer(bravo)["trust"] == "revoked"
        assert gossip(bravo, alpha, bravo.identity.announcement()) == 403

    def test_cross_kind_signature_does_not_verify(self, make_node):
        """A signature over one message kind never verifies as another."""
        bravo = make_node("bravo")
        revocation = bravo.identity.revocation("x")
        introduction = Introduction(server_uuid=bravo.uuid, timestamp=revocation.timestamp, peers=[])
        introduction.signature = revocation.signature
        assert not introduction.verify(bravo.identity.public_key)


class TestIntroductions:
    def test_friends_of_friends_are_introduced(self, make_node):
        alpha, bravo, charlie = make_node("alpha"), make_node("bravo"), make_node("charlie")
        pair(alpha, bravo)
        pair(charlie, bravo)

        bravo.service.gossip_round()

        assert alpha.peer(charlie)["trust"] == "introduced"
        assert charlie.peer(alpha)["trust"] == "introduced"
        assert alpha.peer(charlie)["public_key"] == charlie.identity.public_key

    def test_introductions_reach_one_hop_only(self, make_node):
        alpha, bravo, charlie, delta = (make_node(name) for name in ("alpha", "bravo", "charlie", "delta"))
        pair(alpha, bravo)
        pair(bravo, charlie)
        pair(charlie, delta)

        bravo.service.gossip_round()
        charlie.service.gossip_round()

        assert alpha.peer(charlie)["trust"] == "introduced"
        assert alpha.peer(delta) is None

    def test_introduced_peers_cannot_introduce(self, make_node):
        alpha, bravo, charlie = make_node("alpha"), make_node("bravo"), make_node("charlie")
        pair(alpha, bravo)
        pair(charlie, bravo)
        bravo.service.gossip_round()

        assert gossip(charlie, alpha, charlie.trust.introduction_for(alpha.uuid)) == 403

    def test_quorum_requires_independent_vouchers(self, make_node):
        alpha, bravo, charlie, delta = (make_node(name) for name in ("alpha", "bravo", "charlie", "delta"))
        alpha.trust.quorum = 2
        for voucher in (bravo, delta):
            pair(alpha, voucher)
            pair(charlie, voucher)

        bravo.service.gossip_round()
        assert alpha.peer(charlie) is None

        delta.service.gossip_round()
        assert alpha.peer(charlie)["trust"] == "introduced"

    def test_disagreeing_vouchers_block_admission(self, make_node):
        alpha, bravo, delta = make_node("alpha"), make_node("bravo"), make_node("delta")
        pair(alpha, bravo)
        pair(alpha, delta)
        subject = PeerRecord(
            server_uuid="00000000-0000-4000-8000-000000000001",
            server_id="charlie",
            public_key=crypto.public_key_of(crypto.generate_private_key()),
            endpoint="https://9.9.9.9"
        )
        conflicting = subject.model_copy(update={"public_key": crypto.public_key_of(crypto.generate_private_key())})

        alpha.trust.record_introduction(Introduction(server_uuid=bravo.uuid, peers=[subject]), alpha.peer(bravo))
        alpha.trust.record_introduction(Introduction(server_uuid=delta.uuid, peers=[conflicting]), alpha.peer(delta))

        assert alpha.trust.evaluate(subject.server_uuid) is False
        assert alpha.service.peers.get(subject.server_uuid) is None

    def test_witness_reporting_a_different_key_blocks_admission(self, make_node):
        """Cross-check: a direct peer that knows the subject under another key vetoes the introduction."""
        alpha, bravo, charlie, witness = (make_node(name) for name in ("alpha", "bravo", "charlie", "witness"))
        pair(alpha, bravo)
        pair(charlie, bravo)
        pair(alpha, witness)
        witness.service.peers.admit(PeerRecord(
            server_uuid=charlie.uuid,
            server_id="charlie",
            public_key=crypto.public_key_of(crypto.generate_private_key()),
            endpoint=charlie.identity.endpoint
        ), "direct")

        bravo.service.gossip_round()

        assert alpha.peer(charlie) is None

    def test_witness_agreeing_allows_admission(self, make_node):
        alpha, bravo, charlie, witness = (make_node(name) for name in ("alpha", "bravo", "charlie", "witness"))
        pair(alpha, bravo)
        pair(charlie, bravo)
        pair(alpha, witness)
        pair(charlie, witness)

        bravo.service.gossip_round()

        assert alpha.peer(charlie)["trust"] == "introduced"

    def test_blocking_a_voucher_forgets_its_introductions(self, make_node):
        alpha, bravo, charlie = make_node("alpha"), make_node("bravo"), make_node("charlie")
        pair(alpha, bravo)
        pair(charlie, bravo)
        bravo.service.gossip_round()

        response = alpha.api.post("/api/v1/peers/bravo/block", headers=ADMIN_HEADERS)

        assert response.status_code == 200
        assert alpha.peer(bravo)["trust"] == "blocked"
        assert alpha.peer(charlie) is None

    def test_withdrawn_vouch_forgets_the_introduction(self, make_node):
        alpha, bravo, charlie = make_node("alpha"), make_node("bravo"), make_node("charlie")
        pair(alpha, bravo)
        pair(charlie, bravo)
        bravo.service.gossip_round()

        bravo.trust.block(charlie.uuid)
        bravo.service.gossip_round()

        assert alpha.peer(charlie) is None

    def test_direct_pairing_upgrades_an_introduced_peer(self, make_node):
        alpha, bravo, charlie = make_node("alpha"), make_node("bravo"), make_node("charlie")
        pair(alpha, bravo)
        pair(charlie, bravo)
        bravo.service.gossip_round()

        pair(alpha, charlie)

        assert alpha.peer(charlie)["trust"] == "direct"
        assert charlie.peer(alpha)["trust"] == "direct"


class TestKeyQuery:
    def test_answers_are_signed_and_bound_to_the_nonce(self, make_node):
        alpha, bravo, charlie = make_node("alpha"), make_node("bravo"), make_node("charlie")
        pair(alpha, bravo)
        pair(charlie, bravo)

        assert alpha.trust._ask_key(alpha.peer(bravo), charlie.uuid) == charlie.identity.public_key
        assert alpha.trust._ask_key(alpha.peer(bravo), "00000000-0000-4000-8000-000000000002") is None

    def test_unknown_requester_is_rejected(self, make_node):
        alpha, mallory = make_node("alpha"), make_node("mallory")
        pair(alpha, make_node("bravo"))
        with pytest.raises(TrustError):
            mallory.trust._request("POST", alpha.identity.endpoint, "/api/v1/keys/query", json={
                "requester_uuid": mallory.uuid,
                "subject_uuid": alpha.uuid,
                "nonce": "0" * 32,
                "signature": ""
            })
