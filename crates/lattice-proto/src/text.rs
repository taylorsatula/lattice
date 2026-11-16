//! Text forms (V2_SPEC §1).
//!
//! - **Identifier:** lowercase base32 (RFC 4648, no padding), 52 characters.
//!   Lowercase hexadecimal (64 characters) is accepted everywhere an
//!   identifier is accepted, for compatibility; implementations must emit
//!   base32.
//! - **Address:** `<service>:<mailbox>@<identifier>`, e.g.
//!   `mira:taylor@k7f3…`. The identifier is the part after the `@` and may be
//!   in either form. `service` and `mailbox` are non-empty and contain no
//!   `:`, `@` or whitespace.
//!
//! Lattice routes on the identifier and delivers on the service; the
//! mailbox is opaque to Lattice and belongs to the service.

use base32ct::{Base32Unpadded, Encoding};
use lattice_types::Identifier;

/// Errors from parsing a text-form identifier or address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextError {
    /// The identifier is neither 52-char base32 nor 64-char hex.
    BadIdentifier,
    /// The address is missing its `service:` prefix or `@identifier` part.
    BadAddress,
    /// `service` or `mailbox` is empty or contains `:`, `@` or whitespace.
    BadAddressPart,
}

impl std::fmt::Display for TextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TextError::BadIdentifier => {
                write!(f, "identifier must be 52-char base32 or 64-char hex")
            }
            TextError::BadAddress => {
                write!(f, "address must be <service>:<mailbox>@<identifier>")
            }
            TextError::BadAddressPart => {
                write!(
                    f,
                    "service and mailbox must be non-empty and free of ':', '@' and whitespace"
                )
            }
        }
    }
}

impl std::error::Error for TextError {}

/// Encode an identifier as lowercase base32 (RFC 4648, no padding): 52 chars.
#[must_use]
pub fn encode_id(id: &Identifier) -> String {
    Base32Unpadded::encode_string(id.as_ref())
}

/// Parse an identifier in either accepted text form: 52-char lowercase
/// base32 (no padding) or 64-char hex (either case).
pub fn parse_id(s: &str) -> Result<Identifier, TextError> {
    match s.len() {
        52 => {
            let bytes = Base32Unpadded::decode_vec(s).map_err(|_| TextError::BadIdentifier)?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| TextError::BadIdentifier)?;
            Ok(Identifier::from_bytes(arr))
        }
        64 => {
            let mut out = [0u8; 32];
            for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
                let hi = hex_val(chunk[0]).ok_or(TextError::BadIdentifier)?;
                let lo = hex_val(chunk[1]).ok_or(TextError::BadIdentifier)?;
                out[i] = (hi << 4) | lo;
            }
            Ok(Identifier::from_bytes(out))
        }
        _ => Err(TextError::BadIdentifier),
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A parsed `<service>:<mailbox>@<identifier>` address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub service: String,
    pub mailbox: String,
    pub id: Identifier,
}

/// True if `s` is usable as a service or mailbox: non-empty and free of
/// `:`, `@` and whitespace.
fn valid_part(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c == ':' || c == '@' || c.is_whitespace())
}

/// Format an address as `service:mailbox@<base32 identifier>`.
///
/// Fails if `service` or `mailbox` is empty or contains `:`, `@` or
/// whitespace.
pub fn format_address(service: &str, mailbox: &str, id: &Identifier) -> Result<String, TextError> {
    if !valid_part(service) || !valid_part(mailbox) {
        return Err(TextError::BadAddressPart);
    }
    Ok(format!("{service}:{mailbox}@{}", encode_id(id)))
}

/// Parse `<service>:<mailbox>@<identifier>`. The identifier may be base32
/// or hex; `service` and `mailbox` must be non-empty and free of `:`, `@`
/// and whitespace.
pub fn parse_address(s: &str) -> Result<Address, TextError> {
    let (service, rest) = s.split_once(':').ok_or(TextError::BadAddress)?;
    let (mailbox, id_str) = rest.split_once('@').ok_or(TextError::BadAddress)?;
    if !valid_part(service) || !valid_part(mailbox) {
        return Err(TextError::BadAddressPart);
    }
    // The identifier is the part after the '@'; it may not itself contain
    // one, and parse_id rejects anything that is not 52-char base32 or
    // 64-char hex.
    let id = parse_id(id_str)?;
    Ok(Address {
        service: service.to_string(),
        mailbox: mailbox.to_string(),
        id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_id() -> Identifier {
        Identifier::from_bytes([0xAB; 32])
    }

    #[test]
    fn id_roundtrip_base32() {
        let id = sample_id();
        let s = encode_id(&id);
        assert_eq!(s.len(), 52);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
        assert_eq!(parse_id(&s).unwrap(), id);
    }

    #[test]
    fn id_parses_hex() {
        let id = sample_id();
        let hex: String = id.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex.len(), 64);
        assert_eq!(parse_id(&hex).unwrap(), id);
        // Uppercase hex is accepted too.
        assert_eq!(parse_id(&hex.to_uppercase()).unwrap(), id);
    }

    #[test]
    fn id_rejects_garbage() {
        assert!(parse_id("").is_err());
        assert!(parse_id("abc").is_err());
        // 52 chars but not base32 ('0', '1', '8', '9' are not in the alphabet).
        assert!(parse_id(&"0".repeat(52)).is_err());
        // 64 chars but not hex.
        assert!(parse_id(&"zz".repeat(32)).is_err());
        // Uppercase base32 is not accepted (spec: lowercase).
        let upper = encode_id(&sample_id()).to_uppercase();
        assert!(parse_id(&upper).is_err());
    }

    #[test]
    fn address_roundtrip() {
        let id = sample_id();
        let s = format_address("mira", "taylor", &id).unwrap();
        assert_eq!(s, format!("mira:taylor@{}", encode_id(&id)));
        let parsed = parse_address(&s).unwrap();
        assert_eq!(parsed.service, "mira");
        assert_eq!(parsed.mailbox, "taylor");
        assert_eq!(parsed.id, id);
    }

    #[test]
    fn address_parses_hex_identifier() {
        let id = sample_id();
        let hex: String = id.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let parsed = parse_address(&format!("svc:box@{hex}")).unwrap();
        assert_eq!(parsed.id, id);
    }

    #[test]
    fn address_rejects_bad_parts() {
        let id = encode_id(&sample_id());
        for bad in [
            "",
            "mira",
            ":taylor@",
            "mira:@",
            "mi:ra:taylor@", // mailbox would contain ':'
            "mira:tay lor@",
            "mira:taylor@",
            "mira:taylor@not-an-id",
            "mi ra:taylor@",
            "mira:tay@lor@", // mailbox may not contain '@'
        ] {
            assert!(parse_address(bad).is_err(), "accepted {bad:?}");
        }
        assert!(parse_address(&format!("mira:taylor@{id}")).is_ok());
    }

    #[test]
    fn format_address_rejects_bad_parts() {
        let id = sample_id();
        assert!(format_address("", "taylor", &id).is_err());
        assert!(format_address("mi:ra", "taylor", &id).is_err());
        assert!(format_address("mira", "tay lor", &id).is_err());
        assert!(format_address("mira", "tay@lor", &id).is_err());
        assert!(format_address("mira", "", &id).is_err());
    }
}
