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
use lattice_crypto::{generate_seed, hash, public_key, sign, verify, x25519_public};

fn credentials_dir() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
}

fn read_seed(dir: &Path, name: &str) -> io::Result<[u8; 32]> {
    let cred_path = credentials_dir().map(|d| d.join(name));
    let binding = dir.join(name);
    let path = cred_path.as_deref().unwrap_or(&binding);
    let bytes = fs::read(path)?;
    bytes.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name}: expected 32 bytes"),
        )
    })
}

fn write_seed(dir: &Path, name: &str, seed: &[u8; 32]) -> io::Result<()> {
    let path = dir.join(name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts.open(&path)?;
        use std::io::Write;
        f.write_all(seed)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, seed)?;
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
    let channel_seed = generate_seed();
    let kp = lattice_crypto::generate_keypair();
    write_seed(dir, "signing_seed", &signing_seed)?;
    write_seed(dir, "channel_seed", &channel_seed)?;
    write_seed(dir, "envelope_seed", &kp.secret)?;
    // The next signing key: store the seed (operator should move it offline).
    let next_seed = generate_seed();
    write_seed(dir, "next_signing_seed", &next_seed)?;
    fs::write(dir.join("channel_key.pub"), x25519_public(&channel_seed))?;
    fs::write(dir.join("signing_seed.pub"), public_key(&signing_seed))?;
    // Persist the key event log itself: the node's identity is the hash of
    // this, and it must survive restarts even if next_signing_seed is later
    // moved offline.
    let kel = vec![lattice_proto::kel::KeyEvent::inception(
        &signing_seed,
        hash(&public_key(&next_seed)),
    )];
    let kel_bytes = lattice_proto::kel::encode_kel(&kel);
    fs::write(dir.join("kel.bin"), kel_bytes)?;
    Ok(())
}

pub fn load_identity(dir: &Path) -> io::Result<Identity> {
    let signing_seed = read_seed(dir, "signing_seed")?;
    let channel_seed = read_seed(dir, "channel_seed")?;
    let envelope_seed = read_seed(dir, "envelope_seed")?;

    let kel = if let Ok(bytes) = fs::read(dir.join("kel.bin")) {
        lattice_proto::kel::decode_kel(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    } else {
        // Pre-KEL-file identities: reconstruct from the seeds on disk.
        let next_seed = read_seed(dir, "next_signing_seed")?;
        vec![lattice_proto::kel::KeyEvent::inception(
            &signing_seed,
            hash(&public_key(&next_seed)),
        )]
    };
    // The signing seed must match the KEL's inception key.
    let expected = public_key(&signing_seed);
    if kel.first().map(|e| e.key) != Some(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "signing_seed does not match the KEL",
        ));
    }
    Ok(Identity {
        signing_seed,
        kel,
        channel_seed,
        xwing_secret: envelope_seed,
        xwing_public: lattice_crypto::XWingSecretKey::from_bytes(envelope_seed).public_key(),
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
    let kp = lattice_crypto::XWingSecretKey::from_bytes(identity.xwing_secret);
    let derived = kp.public_key();
    if derived != identity.xwing_public {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "envelope key does not match its public half",
        ));
    }
    Ok(())
}
