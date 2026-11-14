#[derive(Debug)]
pub enum NetError {
    Io,
    Handshake,
    BadMac,
    CookieRequired,
    BadCookie,
    FrameTooLarge,
    BadWire,
    BadFrame,
    Crypto,
    UnexpectedFrame,
    Timeout,
}

impl From<std::io::Error> for NetError {
    fn from(_: std::io::Error) -> Self {
        NetError::Io
    }
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NetError::Io => write!(f, "io error"),
            NetError::Handshake => write!(f, "handshake failed"),
            NetError::BadMac => write!(f, "bad mac"),
            NetError::CookieRequired => write!(f, "cookie required"),
            NetError::BadCookie => write!(f, "bad cookie"),
            NetError::FrameTooLarge => write!(f, "frame too large"),
            NetError::BadWire => write!(f, "malformed wire frame"),
            NetError::BadFrame => write!(f, "undecodable frame"),
            NetError::Crypto => write!(f, "cryptographic failure"),
            NetError::UnexpectedFrame => write!(f, "unexpected frame"),
            NetError::Timeout => write!(f, "operation timed out"),
        }
    }
}

impl std::error::Error for NetError {}
