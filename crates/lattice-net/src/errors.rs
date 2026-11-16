use crate::frame::FrameError;

/// Why the Noise handshake failed.
#[derive(Debug)]
pub enum HandshakeError {
    /// The Noise protocol itself rejected the exchange (bad key, bad MAC,
    /// decryption failure). Distinguishes "peer is not who they claim"
    /// from a local bug.
    Snow(snow::Error),
    /// The handshake completed but the peer's static key was missing or
    /// malformed. Indicates a bug or a non-conforming peer.
    RemoteStatic,
    /// The peer's static key does not match the expected channel key.
    PeerMismatch,
    /// The channel key could not be converted from Ed25519 to X25519.
    ChannelKey,
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeError::Snow(e) => write!(f, "noise: {e}"),
            HandshakeError::RemoteStatic => {
                write!(f, "peer static key missing or malformed after handshake")
            }
            HandshakeError::PeerMismatch => {
                write!(f, "peer static key does not match the expected channel key")
            }
            HandshakeError::ChannelKey => {
                write!(f, "channel key could not be converted to X25519")
            }
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandshakeError::Snow(e) => Some(e),
            _ => None,
        }
    }
}

/// Errors from the network transport.
///
/// Carries the underlying cause wherever one exists: the `io::Error` for
/// socket failures, the `snow::Error` (via [`HandshakeError`]) for Noise
/// failures, the [`FrameError`] for wire-format failures. [`std::error::Error::source`]
/// returns the cause for those variants.
#[derive(Debug)]
pub enum NetError {
    /// The socket or a local I/O operation failed.
    Io(std::io::Error),
    /// The WebSocket layer failed (protocol error, close, capacity).
    WebSocket(tokio_tungstenite::tungstenite::Error),
    /// The Noise handshake failed.
    Handshake(HandshakeError),
    /// The peer's MAC check failed (IK mac1).
    BadMac,
    /// The responder requires a cookie (under load) and none was presented.
    CookieRequired,
    /// The presented cookie did not verify.
    BadCookie,
    /// A frame exceeded the bucket limit.
    FrameTooLarge,
    /// The decrypted plaintext was not a well-formed wire frame.
    BadWire(FrameError),
    /// A frame's CBOR did not decode or did not match the expected shape.
    BadFrame(lattice_proto::ProtoError),
    /// A transport-mode Noise operation failed.
    Crypto(snow::Error),
    /// A frame arrived that is not valid in the current state.
    UnexpectedFrame,
    /// The link was torn down after a non-binary frame was received; the
    /// socket is no longer usable.
    Closed,
    /// The peer did not respond within the handshake timeout.
    Timeout,
    /// The input or configuration is invalid (bad endpoint, bad path, ...).
    InvalidInput(&'static str),
    /// No address survived scope filtering (or none was provided), so no
    /// connection was attempted — e.g. every record IP was private-scoped
    /// for a WAN record.
    NoUsableAddress,
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e)
    }
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NetError::Io(e) => write!(f, "io error: {e}"),
            NetError::WebSocket(e) => write!(f, "websocket error: {e}"),
            NetError::Handshake(e) => write!(f, "handshake failed: {e}"),
            NetError::BadMac => write!(f, "bad mac"),
            NetError::CookieRequired => write!(f, "cookie required"),
            NetError::BadCookie => write!(f, "bad cookie"),
            NetError::FrameTooLarge => write!(f, "frame too large"),
            NetError::BadWire(e) => write!(f, "malformed wire frame: {e}"),
            NetError::BadFrame(e) => write!(f, "undecodable frame: {e}"),
            NetError::Crypto(e) => write!(f, "cryptographic failure: {e}"),
            NetError::UnexpectedFrame => write!(f, "unexpected frame"),
            NetError::Closed => write!(f, "link closed after a non-binary frame"),
            NetError::Timeout => write!(f, "operation timed out"),
            NetError::InvalidInput(m) => write!(f, "invalid input: {m}"),
            NetError::NoUsableAddress => write!(f, "no usable address for this endpoint"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetError::Io(e) => Some(e),
            NetError::WebSocket(e) => Some(e),
            NetError::Handshake(e) => Some(e),
            NetError::BadWire(e) => Some(e),
            NetError::BadFrame(e) => Some(e),
            NetError::Crypto(e) => Some(e),
            NetError::BadMac
            | NetError::CookieRequired
            | NetError::BadCookie
            | NetError::FrameTooLarge
            | NetError::UnexpectedFrame
            | NetError::Closed
            | NetError::Timeout
            | NetError::InvalidInput(_)
            | NetError::NoUsableAddress => None,
        }
    }
}
