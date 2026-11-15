//! Key material handling for latticed.
//!
//! Secrets are 32-byte raw files with 0600 permissions, or provided by
//! systemd credentials (when $CREDENTIALS_DIRECTORY is set). The daemon
//! never reads the next signing key unless one was explicitly left for it
//! (rotation is an out-of-band act).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use lattice_core::Identity;
use lattice_crypto::{channel_public, generate_seed, hash, public_key, sign, verify};
use lattice_types::{ChannelSeed, Commitment, SigningSeed, XWingSecretKey};

fn credentials_dir() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
}

fn read_seed(dir: &Path, name: &str) -> io::Result<[u8; 32]> {
    let cred_path = credentials_dir().map(|d| d.join(name));
    let binding = dir.join(name);
    let from_credentials = cred_path.is_some();
    let path = cred_path.as_deref().unwrap_or(&binding);
    #[cfg(unix)]
    if !from_credentials {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{}: seed file mode {mode:o} is too open; expected 0600 or 0400 (chmod 600 {})",
                    path.display(),
                    path.display()
                ),
            ));
        }
    }
    let bytes = fs::read(path)?;
    bytes.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name}: expected 32 bytes"),
        )
    })
}

fn write_seed(dir: &Path, name: &str, seed: &impl AsRef<[u8]>) -> io::Result<()> {
    let path = dir.join(name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts.open(&path)?;
        use std::io::Write;
        f.write_all(seed.as_ref())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, seed.as_ref())?;
    }
    Ok(())
}

/// Generate a fresh identity and write it to `dir` (existing files are
/// never overwritten). Returns the node's signing public key id material.
pub fn init_identity(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    if dir.join("signing_seed").exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "identity already exists; refusing to overwrite",
        ));
    }
    let signing_seed = generate_seed();
    let channel_seed = ChannelSeed::from_bytes(lattice_crypto::os_bytes::<32>());
    let kp = lattice_crypto::generate_keypair();
    write_seed(dir, "signing_seed", &signing_seed)?;
    write_seed(dir, "channel_seed", &channel_seed)?;
    write_seed(dir, "envelope_seed", &kp.secret)?;
    // The next signing key: store the seed (operator should move it offline).
    let next_seed = generate_seed();
    write_seed(dir, "next_signing_seed", &next_seed)?;
    fs::write(
        dir.join("channel_key.pub"),
        channel_public(&channel_seed).as_ref(),
    )?;
    fs::write(
        dir.join("signing_seed.pub"),
        public_key(&signing_seed).as_ref(),
    )?;
    // Persist the key event log itself: the node's identity is the hash of
    // this, and it must survive restarts even if next_signing_seed is later
    // moved offline.
    let kel = vec![lattice_proto::kel::KeyEvent::inception(
        &signing_seed,
        Commitment::from_bytes(hash(public_key(&next_seed).as_ref()).into_bytes()),
    )];
    let kel_bytes = lattice_proto::kel::encode_kel(&kel);
    fs::write(dir.join("kel.bin"), kel_bytes)?;
    Ok(())
}

pub fn load_identity(dir: &Path) -> io::Result<Identity> {
    let signing_seed = SigningSeed::from_bytes(read_seed(dir, "signing_seed")?);
    let channel_seed = ChannelSeed::from_bytes(read_seed(dir, "channel_seed")?);
    let envelope_seed = XWingSecretKey::from_bytes(read_seed(dir, "envelope_seed")?);

    let kel = {
        let bytes = fs::read(dir.join("kel.bin")).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "{}: read kel.bin: {e} (identity is corrupt or incomplete)",
                    dir.display()
                ),
            )
        })?;
        lattice_proto::kel::decode_kel(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    };
    let retired_xwing = load_retired_envelope_keys(dir)?;
    // The signing seed must match the KEL's current head key. `decode_kel`
    // already validated the chain; no second pass is needed. (Before
    // rotation support this checked the inception key, which broke on the
    // first rotation.)
    if kel.current_key() != public_key(&signing_seed) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "signing_seed does not match the KEL head",
        ));
    }
    Ok(Identity {
        signing_seed,
        kel,
        channel_seed,
        xwing_secret: envelope_seed.clone(),
        xwing_public: lattice_crypto::xwing_public_key(&envelope_seed),
        retired_xwing,
    })
}

/// Key self-test at startup: the daemon refuses to run with corrupt keys.
pub fn self_test(identity: &Identity) -> io::Result<()> {
    let msg = b"latticed self test";
    let sig = sign(&identity.signing_seed, msg);
    let pk = public_key(&identity.signing_seed);
    if !verify(&pk, msg, &sig) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "signing key failed self-test",
        ));
    }
    let derived = lattice_crypto::xwing_public_key(&identity.xwing_secret);
    if derived != identity.xwing_public {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "envelope key does not match its public half",
        ));
    }
    Ok(())
}

const RETIRED_ENVELOPE_PREFIX: &str = "envelope_seed.retired.";

/// Load retired envelope keys whose grace period has not elapsed; delete the
/// rest. Files are named `envelope_seed.retired.<unix-expiry>`.
fn load_retired_envelope_keys(dir: &Path) -> io::Result<Vec<(XWingSecretKey, u64)>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(exp_str) = name.strip_prefix(RETIRED_ENVELOPE_PREFIX) else {
            continue;
        };
        let Ok(exp) = exp_str.parse::<u64>() else {
            continue;
        };
        if exp <= now {
            let _ = fs::remove_file(entry.path());
            continue;
        }
        let bytes = fs::read(entry.path())?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name}: expected 32 bytes"),
            )
        })?;
        out.push((XWingSecretKey::from_bytes(seed), exp));
    }
    Ok(out)
}

/// Outcome of a signing-key rotation.
pub struct Rotation {
    pub identity: lattice_core::Identity,
    /// Where the new next key was written (for the operator to move offline).
    pub next_key_path: Option<PathBuf>,
}

/// Rotate the signing key. `next_key_file` overrides the default location
/// (`<dir>/next_signing_seed`). `abandon` performs a rotation with no
/// next-key commitment, permanently ending the identity.
pub fn rotate_signing_key(
    dir: &Path,
    next_key_file: Option<&Path>,
    abandon: bool,
) -> io::Result<Rotation> {
    let mut identity = load_identity(dir)?;
    let next_path = match next_key_file {
        Some(p) => {
            // The admin socket is owner-only, but confine the override to the
            // identity directory anyway: the path is used as key material, so
            // it must not become an arbitrary-file-read primitive.
            let canon_dir = dir.canonicalize().map_err(|e| {
                io::Error::new(e.kind(), format!("identity dir {}: {e}", dir.display()))
            })?;
            let canon = p.canonicalize().map_err(|e| {
                io::Error::new(e.kind(), format!("next key file {}: {e}", p.display()))
            })?;
            if !canon.starts_with(&canon_dir) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "next key file {} is outside the identity directory",
                        p.display()
                    ),
                ));
            }
            canon
        }
        None => dir.join("next_signing_seed"),
    };
    let next_seed_bytes = fs::read(&next_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "read next signing key {}: {e}. The next key is created at init and must be supplied for rotation",
                next_path.display()
            ),
        )
    })?;
    let next_seed =
        SigningSeed::from_bytes(next_seed_bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "next signing key must be 32 bytes",
            )
        })?);

    let new_next = if abandon {
        None
    } else {
        Some(lattice_crypto::generate_seed())
    };
    identity
        .rotate(&next_seed, new_next.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Persist: new KEL, new current signing seed, new next seed (or none).
    fs::write(
        dir.join("kel.bin"),
        lattice_proto::kel::encode_kel(&identity.kel),
    )?;
    write_seed(dir, "signing_seed", &identity.signing_seed)?;
    let next_key_path = if abandon {
        let _ = fs::remove_file(&next_path);
        None
    } else {
        let new_next = new_next.expect("non-abandon rotation generates a next key");
        write_seed(dir, "next_signing_seed", &new_next)?;
        Some(dir.join("next_signing_seed"))
    };
    Ok(Rotation {
        identity,
        next_key_path,
    })
}

/// Rotate the envelope (X-Wing) key. The old private key is kept, decrypt-only,
/// for `grace_secs`, then deleted by the next load.
pub fn rotate_envelope_key(dir: &Path, grace_secs: u64) -> io::Result<lattice_core::Identity> {
    let mut identity = load_identity(dir)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let retire_at = now + grace_secs;
    // Persist the retired key before swapping, so a crash mid-rotation does
    // not strand envelopes encrypted to it.
    let retired_name = format!("{RETIRED_ENVELOPE_PREFIX}{retire_at}");
    write_seed(dir, &retired_name, &identity.xwing_secret)?;
    let _ = identity.rotate_envelope(retire_at);
    write_seed(dir, "envelope_seed", &identity.xwing_secret)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_roundtrip_preserves_identity_and_abandons() {
        let dir = std::env::temp_dir().join(format!("latticed-rotate-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_identity(&dir).unwrap();
        let before = load_identity(&dir).unwrap();
        let id_before = before.id();

        // Rotate: identity id is stable, signing key changes, KEL grows.
        let rotation = rotate_signing_key(&dir, None, false).unwrap();
        assert!(rotation.next_key_path.is_some());
        let after = load_identity(&dir).unwrap();
        assert_eq!(after.id(), id_before);
        assert_ne!(after.signing_seed, before.signing_seed);
        assert_eq!(after.kel.len(), before.kel.len() + 1);

        // Abandon: terminal; the node must refuse to start afterwards.
        let rotation = rotate_signing_key(&dir, None, true).unwrap();
        assert!(rotation.next_key_path.is_none());
        let abandoned = load_identity(&dir).unwrap();
        assert!(abandoned.is_abandoned());
        let cfg = lattice_core::Config::default();
        let store = lattice_store::MemStore::new();
        assert!(lattice_core::Node::new(cfg, abandoned, store, 1_000).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn envelope_rotation_roundtrip_keeps_retired_key() {
        let dir =
            std::env::temp_dir().join(format!("latticed-envelope-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init_identity(&dir).unwrap();
        let before = load_identity(&dir).unwrap();
        let old_public = before.xwing_public;

        let after = rotate_envelope_key(&dir, 2 * 24 * 3600).unwrap();
        assert_ne!(after.xwing_public, old_public);
        assert_eq!(after.retired_xwing.len(), 1);

        // Reload: the retired key survives a restart.
        let reloaded = load_identity(&dir).unwrap();
        assert_eq!(reloaded.xwing_public, after.xwing_public);
        assert_eq!(reloaded.retired_xwing.len(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}
