//! Key material handling for latticed.
//!
//! Secrets are 32-byte raw files with 0600 permissions, or provided by
//! systemd credentials (when $CREDENTIALS_DIRECTORY is set). The next
//! signing key never lives in the identity directory: `latticed init` writes
//! it to an operator-chosen path outside the identity directory (or prints
//! it once to stdout), and the identity directory stores only its BLAKE3
//! commitment in `next_key_commitment`. Rotation takes the next key's bytes
//! over the admin socket and never writes any future secret key to disk.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use lattice_core::{Identity, RetiredEnvelopeKey};
use lattice_crypto::{channel_public, generate_seed, hash, public_key, sign, verify};
use lattice_types::{ChannelSeed, Commitment, SigningSeed, XWingSecretKey};
use subtle::ConstantTimeEq;

/// File in the identity directory holding the BLAKE3 commitment to the next
/// signing key (32 raw bytes). Written at init and rewritten at each
/// rotation; holds no secret material.
const NEXT_KEY_COMMITMENT_FILE: &str = "next_key_commitment";

/// File name that must never appear in the identity directory. Its presence
/// means an offline key ended up next to the daemon's secrets; refuse to run.
const NEXT_SIGNING_SEED_FILE: &str = "next_signing_seed";

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
    let bytes =
        fs::read(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
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
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts.open(&path)?;
        f.write_all(seed.as_ref())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, seed.as_ref())?;
    }
    Ok(())
}

/// BLAKE3 of the next key's public half — the commitment the KEL carries.
fn next_key_commitment(seed: &SigningSeed) -> Commitment {
    Commitment::from_bytes(hash(public_key(seed).as_ref()).into_bytes())
}

fn write_next_commitment(dir: &Path, commitment: &Commitment) -> io::Result<()> {
    let path = dir.join(NEXT_KEY_COMMITMENT_FILE);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts.open(&path)?;
        f.write_all(commitment.as_bytes())
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, commitment.as_bytes())
    }
}

/// Lexically resolve `.` and `..` without touching the filesystem.
fn normalize_lexically(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve `out` to the absolute path it would be created at, refusing
/// paths inside `dir`. `..` is resolved lexically and the parent directory
/// is canonicalized, so neither traversal nor symlinks can smuggle the
/// target back into the identity directory; if `out` itself exists it is
/// canonicalized as-is (and rejected by the caller's create-new).
fn resolve_outside(dir: &Path, out: &Path) -> io::Result<PathBuf> {
    let canon_dir = dir
        .canonicalize()
        .map_err(|e| io::Error::new(e.kind(), format!("identity dir {}: {e}", dir.display())))?;
    let normalized = normalize_lexically(out);
    let resolved = match normalized.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            let parent = normalized
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let file_name = normalized.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{}: not a file path", out.display()),
                )
            })?;
            parent.canonicalize()?.join(file_name)
        }
    };
    if resolved.starts_with(&canon_dir) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "next key output {} is inside the identity directory {}; the next key must live outside it",
                out.display(),
                dir.display()
            ),
        ));
    }
    Ok(resolved)
}

/// Write the next signing key to an operator-chosen path outside `dir`.
/// Refuses to overwrite an existing file: clobbering an offline key file
/// would destroy the only copy of a key the identity is committed to.
fn write_next_key_out(dir: &Path, out: &Path, seed: &SigningSeed) -> io::Result<PathBuf> {
    let resolved = resolve_outside(dir, out)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        let mut f = opts.open(&resolved).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    e.kind(),
                    format!(
                        "{} already exists; refusing to overwrite the next key",
                        resolved.display()
                    ),
                )
            } else {
                e
            }
        })?;
        f.write_all(seed.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        if resolved.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists; refusing to overwrite the next key",
                    resolved.display()
                ),
            ));
        }
        fs::write(&resolved, seed.as_bytes())?;
    }
    Ok(resolved)
}

/// What [`init_identity`] produced, for the caller to report to the operator.
pub struct InitOutcome {
    /// The generated next signing key. Returned so the caller can print it
    /// once when no `--next-key-out` path was given; the daemon never writes
    /// it to disk in that case.
    pub next_key: SigningSeed,
    /// Where the next key was written, if a path was given.
    pub next_key_path: Option<PathBuf>,
    /// Commitment to the next key; also stored in `next_key_commitment`.
    pub next_key_commitment: Commitment,
}

/// Generate a fresh identity and write it to `dir` (existing files are
/// never overwritten). The next signing key is written to `next_key_out`
/// (which must lie outside `dir`) or, when `None`, returned in the outcome
/// for the caller to print once; the identity directory itself only ever
/// stores its commitment.
pub fn init_identity(dir: &Path, next_key_out: Option<&Path>) -> io::Result<InitOutcome> {
    fs::create_dir_all(dir)?;
    if dir.join("signing_seed").exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "identity already exists; refusing to overwrite",
        ));
    }
    if dir.join(NEXT_KEY_COMMITMENT_FILE).exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists; refusing to overwrite a partial identity",
                dir.join(NEXT_KEY_COMMITMENT_FILE).display()
            ),
        ));
    }
    let signing_seed = generate_seed();
    let channel_seed = ChannelSeed::from_bytes(lattice_crypto::os_bytes::<32>());
    let kp = lattice_crypto::generate_keypair();
    // The next signing key stays with the operator; the identity directory
    // stores only its commitment. Write it out BEFORE any identity file:
    // if this fails, nothing has been written and the operator can fix the
    // path and retry. The reverse order would strand an identity whose next
    // key was never delivered anywhere.
    let next_seed = generate_seed();
    let commitment = next_key_commitment(&next_seed);
    let next_key_path = match next_key_out {
        Some(path) => Some(write_next_key_out(dir, path, &next_seed)?),
        None => None,
    };
    write_seed(dir, "signing_seed", &signing_seed)?;
    write_seed(dir, "channel_seed", &channel_seed)?;
    write_seed(dir, "envelope_seed", &kp.secret)?;
    write_next_commitment(dir, &commitment)?;
    fs::write(
        dir.join("channel_key.pub"),
        channel_public(&channel_seed).as_ref(),
    )?;
    fs::write(
        dir.join("signing_seed.pub"),
        public_key(&signing_seed).as_ref(),
    )?;
    // Persist the key event log itself: the node's identity is the hash of
    // this, and it must survive restarts.
    let kel = vec![lattice_proto::kel::KeyEvent::inception(
        &signing_seed,
        commitment,
    )];
    let kel_bytes = lattice_proto::kel::encode_kel(&kel);
    fs::write(dir.join("kel.bin"), kel_bytes)?;
    Ok(InitOutcome {
        next_key: next_seed,
        next_key_path,
        next_key_commitment: commitment,
    })
}

pub fn load_identity(dir: &Path) -> io::Result<Identity> {
    // Fail closed: a next signing key inside the identity directory means an
    // offline key ended up next to the daemon's secrets. Refuse to run until
    // the operator moves it out (invariant: the next key never lives here).
    let stray = dir.join(NEXT_SIGNING_SEED_FILE);
    if stray.symlink_metadata().is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} exists: the next signing key must not live in the identity directory. \
                 Move it to offline storage and pass it to `latticectl rotate --next-key-file <path>` \
                 when rotating. Refusing to start.",
                stray.display()
            ),
        ));
    }
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
    // Seal a payload to the node's own envelope public key and open it
    // again. This exercises X-Wing encapsulation and decapsulation against
    // the loaded secret, so a secret that does not match the stored public
    // key (or a broken KEM) fails here instead of on the first inbound
    // envelope.
    let sealed = lattice_crypto::seal(
        lattice_crypto::ENVELOPE_CONTEXT,
        &identity.xwing_public,
        b"",
        msg,
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("envelope seal failed: {e}"),
        )
    })?;
    let opened = lattice_crypto::open(
        lattice_crypto::ENVELOPE_CONTEXT,
        &identity.xwing_secret,
        b"",
        &sealed.kem_ciphertext,
        &sealed.ciphertext,
    )
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("envelope open failed: {e}"),
        )
    })?;
    if opened != msg {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "envelope round-trip returned different bytes",
        ));
    }
    Ok(())
}

const RETIRED_ENVELOPE_PREFIX: &str = "envelope_seed.retired.";

/// Load retired envelope keys whose grace period has not elapsed; delete the
/// rest. Files are named `envelope_seed.retired.<unix-expiry>`.
fn load_retired_envelope_keys(dir: &Path) -> io::Result<Vec<RetiredEnvelopeKey>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
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
            if let Err(e) = fs::remove_file(entry.path()) {
                eprintln!(
                    "lattice: failed to remove expired retired envelope key {}: {e}",
                    entry.path().display()
                );
            }
            continue;
        }
        let bytes = fs::read(entry.path())?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name}: expected 32 bytes"),
            )
        })?;
        out.push(RetiredEnvelopeKey {
            secret: XWingSecretKey::from_bytes(seed),
            retire_at: exp,
        });
    }
    Ok(out)
}

/// Outcome of a signing-key rotation.
pub struct Rotation {
    pub identity: lattice_core::Identity,
}

/// The commitment the rotation must verify the next key against.
///
/// The KEL head carries the same commitment and is self-verifying, so it is
/// the source of truth: if the on-disk file is missing, corrupt, or stale
/// (e.g. a crash between writing kel.bin and the file), the file is rebuilt
/// from the KEL head and a warning is printed. The provided key is always
/// checked against this value, never against an unverified file.
fn stored_next_commitment(dir: &Path, identity: &lattice_core::Identity) -> io::Result<Commitment> {
    let kel_commitment = identity.kel.head().next.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "identity is abandoned; rotation is impossible",
        )
    })?;
    let path = dir.join(NEXT_KEY_COMMITMENT_FILE);
    let rebuild = |reason: &str| -> io::Result<Commitment> {
        eprintln!(
            "lattice: {reason}; rewriting {} from the KEL head commitment",
            path.display()
        );
        write_next_commitment(dir, &kel_commitment)?;
        Ok(kel_commitment)
    };
    match fs::read(&path) {
        Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
            Ok(arr) if Commitment::from_bytes(arr) == kel_commitment => Ok(kel_commitment),
            Ok(_) => rebuild("next_key_commitment disagrees with the KEL head"),
            Err(_) => rebuild("next_key_commitment is not 32 bytes"),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => rebuild("next_key_commitment is missing"),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("read {}: {e}", path.display()),
        )),
    }
}

/// Rotate the signing key.
///
/// `next_key` is the offline, pre-committed next key, supplied by the
/// operator over the admin socket; it is verified against the stored
/// commitment (constant-time) and the rotation is refused on mismatch.
/// `next_next_commitment` commits to the following key, generated offline;
/// it is required for [`lattice_core::RotationKind::Rotate`] and forbidden
/// for [`lattice_core::RotationKind::Abandon`]. No secret key is written to
/// disk: the stored commitment is replaced with the one provided.
pub fn rotate_signing_key(
    dir: &Path,
    next_key: &[u8; 32],
    next_next_commitment: Option<&Commitment>,
    kind: lattice_core::RotationKind,
) -> io::Result<Rotation> {
    let mut identity = load_identity(dir)?;
    if identity.is_abandoned() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "identity is abandoned; rotation is impossible",
        ));
    }
    match (kind, next_next_commitment) {
        (lattice_core::RotationKind::Rotate, Some(_))
        | (lattice_core::RotationKind::Abandon, None) => {}
        (lattice_core::RotationKind::Rotate, None) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rotate requires the commitment to the following key",
            ));
        }
        (lattice_core::RotationKind::Abandon, Some(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "abandon takes no next-next commitment",
            ));
        }
    }
    let expected = stored_next_commitment(dir, &identity)?;
    let next_seed = SigningSeed::from_bytes(*next_key);
    let provided = next_key_commitment(&next_seed);
    if expected.as_bytes().ct_eq(provided.as_bytes()).unwrap_u8() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the provided next key does not match the commitment stored in the identity directory; refusing to rotate",
        ));
    }
    identity
        .rotate(&next_seed, next_next_commitment.copied())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Persist: new KEL, new current signing seed, then the commitment file.
    //
    // kel.bin is written BEFORE signing_seed: a crash between the two leaves
    // the KEL head committing to the new key while signing_seed on disk still
    // holds the old one, and load_identity then refuses to start ("signing_seed
    // does not match the KEL head"). Writing the seed first fails the other
    // way and is unrecoverable from on-disk state (the old seed is gone), so
    // the order is not arbitrary — but neither order is atomic; there is no
    // multi-file commit. Recovery from the kel-first crash: the new current
    // seed is the pre-rotation next key, which the operator holds offline.
    // Copy it over signing_seed, then start the daemon; the self-test and the
    // KEL head check will pass. If kel.bin itself is torn, restore it from
    // backup instead — the identity cannot be rebuilt from the seeds alone.
    // The commitment file is written last; if a crash leaves it stale or
    // missing, the next rotation rebuilds it from the KEL head (see
    // `stored_next_commitment`). After an abandon rotation the identity is
    // terminal either way (Node::new refuses abandoned identities), so
    // recovery applies only to ordinary rotations.
    fs::write(
        dir.join("kel.bin"),
        lattice_proto::kel::encode_kel(&identity.kel),
    )?;
    write_seed(dir, "signing_seed", &identity.signing_seed)?;
    match kind {
        lattice_core::RotationKind::Rotate => {
            // `next_next_commitment` is Some here (checked above).
            write_next_commitment(dir, next_next_commitment.expect("checked above"))?;
        }
        lattice_core::RotationKind::Abandon => {
            // The identity is terminal; the commitment is meaningless now.
            // Remove it so a stale file cannot be mistaken for a live one.
            if let Err(e) = fs::remove_file(dir.join(NEXT_KEY_COMMITMENT_FILE)) {
                if e.kind() != io::ErrorKind::NotFound {
                    eprintln!(
                        "lattice: identity abandoned but failed to remove {}: {e}. \
                         Remove it manually; the identity is already terminal.",
                        dir.join(NEXT_KEY_COMMITMENT_FILE).display()
                    );
                }
            }
        }
    }
    Ok(Rotation { identity })
}

/// Rotate the envelope (X-Wing) key. The old private key is kept, decrypt-only,
/// for `grace_secs`, then deleted by the next load.
pub fn rotate_envelope_key(dir: &Path, grace_secs: u64) -> io::Result<lattice_core::Identity> {
    let mut identity = load_identity(dir)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let retire_at = now + grace_secs;
    // Persist the retired key before swapping, so a crash mid-rotation does
    // not strand envelopes encrypted to it.
    let retired_name = format!("{RETIRED_ENVELOPE_PREFIX}{retire_at}");
    write_seed(dir, &retired_name, &identity.xwing_secret)?;
    // The returned public key is re-derivable from the secret just written.
    identity.rotate_envelope(retire_at);
    write_seed(dir, "envelope_seed", &identity.xwing_secret)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_err<T>(r: io::Result<T>) -> io::Error {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("latticed-{tag}-{}-{nanos}", std::process::id()))
    }

    fn commitment_of(seed: &SigningSeed) -> Commitment {
        next_key_commitment(seed)
    }

    #[test]
    fn self_test_passes_on_fresh_identity() {
        let dir = temp_dir("self-test-ok");
        init_identity(&dir, None).unwrap();
        let identity = load_identity(&dir).unwrap();
        self_test(&identity).expect("fresh identity must pass the self-test");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn self_test_fails_when_envelope_public_does_not_match_secret() {
        let dir = temp_dir("self-test-mismatch");
        init_identity(&dir, None).unwrap();
        let mut identity = load_identity(&dir).unwrap();
        // Swap in a different envelope keypair's public half: the secret no
        // longer matches the public key the record would advertise.
        let other = lattice_crypto::generate_keypair();
        identity.xwing_public = other.public;
        let err = expect_err(self_test(&identity));
        assert!(
            err.to_string().contains("envelope"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_writes_commitment_and_never_the_next_key() {
        let dir = temp_dir("init-commitment");
        let outcome = init_identity(&dir, None).unwrap();
        // The identity directory holds the commitment, never the key.
        assert!(!dir.join("next_signing_seed").exists());
        let stored = fs::read(dir.join(NEXT_KEY_COMMITMENT_FILE)).unwrap();
        assert_eq!(stored, commitment_of(&outcome.next_key).as_bytes());
        assert_eq!(
            outcome.next_key_commitment.as_bytes(),
            commitment_of(&outcome.next_key).as_bytes()
        );
        assert!(outcome.next_key_path.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_writes_next_key_out_and_refuses_inside_identity_dir() {
        let base = temp_dir("init-out");
        let dir = base.join("identity");
        let out = base.join("next.key");
        let outcome = init_identity(&dir, Some(&out)).unwrap();
        let written = fs::read(&out).unwrap();
        assert_eq!(written.as_slice(), outcome.next_key.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!dir.join("next_signing_seed").exists());

        // Inside the identity directory: refused, and nothing is written.
        let dir2 = base.join("identity2");
        let err = expect_err(init_identity(&dir2, Some(&dir2.join("next.key"))));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(!dir2.join("signing_seed").exists());
        // Traversal that resolves back inside the identity directory: refused.
        let dir3 = base.join("identity3");
        let err = expect_err(init_identity(&dir3, Some(&dir3.join("sub/../next.key"))));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn init_refuses_to_overwrite_existing_next_key_out() {
        let base = temp_dir("init-overwrite");
        let dir = base.join("identity");
        let out = base.join("next.key");
        fs::create_dir_all(&base).unwrap();
        fs::write(&out, b"do not clobber").unwrap();
        let err = expect_err(init_identity(&dir, Some(&out)));
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&out).unwrap(), b"do not clobber");
        // Nothing was written into the identity directory either.
        assert!(!dir.join("signing_seed").exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn rotate_roundtrip_preserves_identity_and_abandons() {
        let dir = temp_dir("rotate");
        let outcome = init_identity(&dir, None).unwrap();
        let next_key = *outcome.next_key.as_bytes();
        let before = load_identity(&dir).unwrap();
        let id_before = before.id();

        // Rotate to the offline next key, committing to a fresh following key.
        let following = SigningSeed::from_bytes([7u8; 32]);
        let following_commitment = commitment_of(&following);
        let rotation = rotate_signing_key(
            &dir,
            &next_key,
            Some(&following_commitment),
            lattice_core::RotationKind::Rotate,
        )
        .unwrap();
        let _ = rotation;
        let after = load_identity(&dir).unwrap();
        assert_eq!(after.id(), id_before);
        assert_ne!(after.signing_seed, before.signing_seed);
        assert_eq!(after.kel.len(), before.kel.len() + 1);
        // The stored commitment is now the following key's commitment.
        assert_eq!(
            fs::read(dir.join(NEXT_KEY_COMMITMENT_FILE)).unwrap(),
            following_commitment.as_bytes()
        );
        // No secret key material beyond the current one is on disk.
        assert!(!dir.join("next_signing_seed").exists());

        // Abandon: terminal; the node must refuse to start afterwards.
        rotate_signing_key(
            &dir,
            following.as_bytes(),
            None,
            lattice_core::RotationKind::Abandon,
        )
        .unwrap();
        assert!(!dir.join(NEXT_KEY_COMMITMENT_FILE).exists());
        let abandoned = load_identity(&dir).unwrap();
        assert!(abandoned.is_abandoned());
        let cfg = lattice_core::Config::default();
        let store = lattice_store::MemStore::new();
        assert!(lattice_core::Node::new(cfg, abandoned, store, 1_000).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_rejects_wrong_next_key() {
        let dir = temp_dir("rotate-wrong-key");
        let outcome = init_identity(&dir, None).unwrap();
        let before = load_identity(&dir).unwrap();
        let following = SigningSeed::from_bytes([7u8; 32]);
        let following_commitment = commitment_of(&following);
        let err = expect_err(rotate_signing_key(
            &dir,
            &[9u8; 32],
            Some(&following_commitment),
            lattice_core::RotationKind::Rotate,
        ));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        // Identity untouched: same key, same KEL, commitment file unchanged.
        let after = load_identity(&dir).unwrap();
        assert_eq!(after.signing_seed, before.signing_seed);
        assert_eq!(after.kel.len(), before.kel.len());
        assert_eq!(
            fs::read(dir.join(NEXT_KEY_COMMITMENT_FILE)).unwrap(),
            commitment_of(&outcome.next_key).as_bytes()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_and_abandon_argument_rules() {
        let dir = temp_dir("rotate-args");
        let outcome = init_identity(&dir, None).unwrap();
        let next_key = *outcome.next_key.as_bytes();
        let following_commitment = commitment_of(&SigningSeed::from_bytes([7u8; 32]));

        // Rotate without a following-key commitment: rejected.
        let err = expect_err(rotate_signing_key(
            &dir,
            &next_key,
            None,
            lattice_core::RotationKind::Rotate,
        ));
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // Abandon with a following-key commitment: rejected.
        let err = expect_err(rotate_signing_key(
            &dir,
            &next_key,
            Some(&following_commitment),
            lattice_core::RotationKind::Abandon,
        ));
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // Identity still usable afterwards.
        assert!(load_identity(&dir).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_identity_refuses_next_signing_seed_in_identity_dir() {
        let dir = temp_dir("stray-next-key");
        init_identity(&dir, None).unwrap();
        fs::write(dir.join("next_signing_seed"), [1u8; 32]).unwrap();
        let err = expect_err(load_identity(&dir));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("next_signing_seed"));
        // Rotation refuses too, not just startup.
        let err = expect_err(rotate_signing_key(
            &dir,
            &[1u8; 32],
            None,
            lattice_core::RotationKind::Abandon,
        ));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_heals_missing_commitment_file_from_kel() {
        // A crash between kel.bin and the commitment write (or an upgrade
        // from a version that never wrote one) leaves the file missing; the
        // KEL head carries the same commitment and is authoritative.
        let dir = temp_dir("rotate-heal");
        let outcome = init_identity(&dir, None).unwrap();
        let next_key = *outcome.next_key.as_bytes();
        fs::remove_file(dir.join(NEXT_KEY_COMMITMENT_FILE)).unwrap();
        let following = SigningSeed::from_bytes([7u8; 32]);
        let following_commitment = commitment_of(&following);
        rotate_signing_key(
            &dir,
            &next_key,
            Some(&following_commitment),
            lattice_core::RotationKind::Rotate,
        )
        .unwrap();
        assert_eq!(
            fs::read(dir.join(NEXT_KEY_COMMITMENT_FILE)).unwrap(),
            following_commitment.as_bytes()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn envelope_rotation_roundtrip_keeps_retired_key() {
        let dir = temp_dir("envelope");
        init_identity(&dir, None).unwrap();
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
