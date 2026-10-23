from lattice import crypto
from lattice.models import ServerAnnouncement


def make_announcement(private_key):
    return ServerAnnouncement(
        server_uuid="00000000-0000-4000-8000-000000000001",
        server_id="test.example.com",
        public_key=crypto.public_key_of(private_key),
        endpoint="https://1.1.1.1"
    ).sign(private_key)


def test_signature_survives_serialization():
    key = crypto.generate_private_key()
    announcement = make_announcement(key)

    reconstructed = ServerAnnouncement(**announcement.model_dump())

    assert reconstructed.verify(crypto.public_key_of(key))


def test_tampered_message_fails_verification():
    key = crypto.generate_private_key()
    tampered = make_announcement(key).model_copy(update={"server_id": "evil.example.com"})

    assert not tampered.verify(crypto.public_key_of(key))


def test_wrong_key_fails_verification():
    announcement = make_announcement(crypto.generate_private_key())

    assert not announcement.verify(crypto.public_key_of(crypto.generate_private_key()))


def test_garbage_signature_and_key_fail_closed():
    key = crypto.generate_private_key()
    announcement = make_announcement(key)

    assert not crypto.verify("not-a-key", announcement.signing_bytes(), announcement.signature)
    assert not crypto.verify(crypto.public_key_of(key), announcement.signing_bytes(), "!!!")


def test_private_key_pem_roundtrip():
    key = crypto.generate_private_key()
    assert crypto.public_key_of(crypto.private_key_from_pem(crypto.private_key_to_pem(key))) == crypto.public_key_of(key)
