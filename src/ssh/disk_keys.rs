//! Serving OpenSSH private keys from `~/.ssh` through the agent.
//!
//! Keys are discovered by scanning the directory for files in OpenSSH
//! private key format. The public half of an encrypted key is stored
//! in cleartext, so identities can be listed without prompting -- the
//! passphrase is only needed (and cached) when a sign request arrives.

use std::io::Read;
use std::path::{Path, PathBuf};

use signature::{SignatureEncoding, Signer};
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
use zeroize::Zeroizing;

/// Files larger than this are never key files; skipping them keeps a
/// stray `known_hosts.old` or packet capture from being read fully.
const MAX_KEY_FILE_SIZE: u64 = 64 * 1024;

const OPENSSH_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";

/// An OpenSSH private key discovered on disk.
///
/// Only the public half is kept in memory; the private file is
/// re-read (and decrypted if needed) at sign time.
#[derive(Clone, Debug)]
pub struct DiskKey {
    pub path: PathBuf,
    pub public: KeyData,
    pub comment: String,
    pub encrypted: bool,
}

/// Directory scanned for on-disk SSH keys.
///
/// `TUMPA_SSH_DIR` overrides the default `~/.ssh`; setting it to an
/// empty string disables disk key scanning entirely.
pub fn ssh_dir() -> Option<PathBuf> {
    match std::env::var("TUMPA_SSH_DIR") {
        Ok(dir) if dir.is_empty() => None,
        Ok(dir) => Some(PathBuf::from(dir)),
        Err(_) => dirs::home_dir().map(|home| home.join(".ssh")),
    }
}

/// Scan a directory for OpenSSH private keys.
///
/// Non-key files (pubkeys, known_hosts, config, sockets) are skipped
/// by the PEM-header check; symlinks are skipped entirely; unreadable
/// or unparsable files are logged at debug level and ignored so one
/// bad file never hides the rest.
pub fn scan(dir: &Path) -> Vec<DiskKey> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            log::debug!("Cannot read {}: {}", dir.display(), e);
            return Vec::new();
        }
    };

    let mut keys = Vec::new();
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                log::debug!("Skipping unreadable entry in {}: {}", dir.display(), e);
                continue;
            }
        };
        match load_key(&path) {
            Ok(Some(key)) => {
                log::debug!("Found SSH key {}", path.display());
                keys.push(key);
            }
            Ok(None) => {}
            Err(e) => log::debug!("Skipping {}: {}", path.display(), e),
        }
    }
    keys.sort_by(|a, b| a.path.cmp(&b.path));
    keys
}

fn load_key(path: &Path) -> Result<Option<DiskKey>, String> {
    // Open first, fstat the handle, read from the handle: a stat on
    // the path followed by a fresh open would leave a window to swap
    // in a symlink or FIFO between the two. A symlink in ~/.ssh could
    // point anywhere, including procfs pseudo-files where len() is
    // unreliable and a read can block the agent; it is skipped along
    // with sockets, FIFOs and directories.
    let file = match open_key_file(path) {
        Ok(file) => file,
        Err(e) if is_symlink_error(&e) => return Ok(None),
        // Permission denied or transient I/O could be hiding a real
        // key, so bubble it up for scan() to log.
        Err(e) => return Err(e.to_string()),
    };
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE_SIZE {
        return Ok(None);
    }

    // Zeroizing: an unencrypted file holds private key material, and
    // this buffer must not outlive the parse.
    let mut contents = Zeroizing::new(String::new());
    // take(): the fstat length can go stale if the file grows
    match std::io::Read::take(&file, MAX_KEY_FILE_SIZE).read_to_string(&mut contents) {
        Ok(_) => {}
        // Non-UTF-8 means a binary file (host key blob, etc.), which
        // is genuinely not an OpenSSH key.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !contents.trim_start().starts_with(OPENSSH_HEADER) {
        return Ok(None);
    }

    // Checked only after the header match so a world-readable
    // known_hosts or config never triggers the warning.
    if !permissions_ok(&meta) {
        log::warn!(
            "Ignoring {}: permissions are too open (readable or writable by group/other)",
            path.display()
        );
        return Ok(None);
    }

    let key = PrivateKey::from_openssh(contents.as_str()).map_err(|e| e.to_string())?;
    let public = key.public_key().key_data().clone();

    // Only key types the agent can actually sign with. This excludes
    // FIDO (sk-*) keys, which need the authenticator, and DSA.
    if !matches!(
        public,
        KeyData::Ed25519(_) | KeyData::Ecdsa(_) | KeyData::Rsa(_)
    ) {
        log::debug!(
            "Ignoring {} (unsupported key type {})",
            path.display(),
            public.algorithm()
        );
        return Ok(None);
    }

    // The comment of an encrypted key lives inside the encrypted blob,
    // so fall back to the sibling .pub file, then the path itself.
    let comment = if !key.comment().is_empty() {
        key.comment().to_string()
    } else {
        pub_file_comment(path).unwrap_or_else(|| path.display().to_string())
    };

    Ok(Some(DiskKey {
        path: path.to_path_buf(),
        public,
        comment,
        encrypted: key.is_encrypted(),
    }))
}

/// Read and parse an OpenSSH private key file, enforcing the same
/// regular-file, no-symlink, size and permission guards as scanning.
///
/// Used at sign time as well: the file can change between scan and
/// sign, so a replaced symlink, socket/FIFO or oversized file must be
/// rejected again here, not just during discovery. The file is opened
/// exactly once and every guard runs on that open handle, so nothing
/// can be swapped in between a check and the read.
pub fn read_private_key(path: &Path) -> Result<PrivateKey, String> {
    let file = open_key_file(path).map_err(|e| {
        if is_symlink_error(&e) {
            "symlinks are not followed for key files".to_string()
        } else {
            e.to_string()
        }
    })?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    if meta.len() > MAX_KEY_FILE_SIZE {
        return Err(format!(
            "file is larger than {} bytes, refusing to read as a key",
            MAX_KEY_FILE_SIZE
        ));
    }
    if !permissions_ok(&meta) {
        return Err("permissions are too open (readable or writable by group/other)".to_string());
    }
    let mut contents = Zeroizing::new(String::new());
    std::io::Read::take(&file, MAX_KEY_FILE_SIZE)
        .read_to_string(&mut contents)
        .map_err(|e| e.to_string())?;
    PrivateKey::from_openssh(contents.as_str()).map_err(|e| e.to_string())
}

/// Open a key file for reading without following symlinks.
///
/// Unix: `O_NOFOLLOW` makes the open itself fail (`ELOOP`) when the
/// path is a symlink, and `O_NONBLOCK` keeps a FIFO placed at the
/// path from blocking the open; neither flag affects reads from a
/// regular file. Callers fstat the returned handle, so every guard
/// and the read apply to the same inode -- there is no window between
/// a path-based check and a separate open.
///
/// Non-Unix: std exposes no `O_NOFOLLOW` equivalent, so symlinks are
/// rejected with a check before the open. Best effort only -- the
/// race-free same-inode guarantee is Unix-specific.
fn open_key_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks are not followed for key files",
        ));
    }
    options.open(path)
}

/// Did `open_key_file` refuse the path because it is a symlink?
#[cfg(unix)]
fn is_symlink_error(e: &std::io::Error) -> bool {
    // open(2) with O_NOFOLLOW fails with ELOOP on a symlink
    e.raw_os_error() == Some(libc::ELOOP)
}

/// Did `open_key_file` refuse the path because it is a symlink?
#[cfg(not(unix))]
fn is_symlink_error(e: &std::io::Error) -> bool {
    // The marker kind from open_key_file's pre-open symlink check;
    // a real open never produces Unsupported for a file path.
    e.kind() == std::io::ErrorKind::Unsupported
}

/// OpenSSH-style strict mode check (`sshkey_perm_ok`): a private key
/// readable or writable by group/other is refused. An agent client
/// never sees the file, so this is the last place the check can
/// happen. Unix only -- other platforms have no Unix mode bits, so
/// the check passes there.
#[cfg(unix)]
fn permissions_ok(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn permissions_ok(_meta: &std::fs::Metadata) -> bool {
    true
}

/// Read the comment from the sibling `<key>.pub` file, if any.
fn pub_file_comment(path: &Path) -> Option<String> {
    // Append via OsString: going through `path.display()` is lossy
    // for non-UTF-8 paths and would look up the wrong file.
    let mut pub_os = path.as_os_str().to_os_string();
    pub_os.push(".pub");
    let pub_path = PathBuf::from(pub_os);

    let file = open_key_file(&pub_path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE_SIZE {
        return None;
    }
    let mut line = String::new();
    std::io::Read::take(&file, MAX_KEY_FILE_SIZE)
        .read_to_string(&mut line)
        .ok()?;
    let public = ssh_key::PublicKey::from_openssh(line.trim()).ok()?;
    let comment = public.comment().trim();
    if comment.is_empty() {
        None
    } else {
        Some(comment.to_string())
    }
}

/// Sign `data` with a decrypted private key, honoring the RSA hash
/// flags from the agent protocol.
///
/// ssh-key's built-in `Signer` impl for RSA always uses SHA-512, so
/// RSA goes through the rsa crate directly to respect a client that
/// negotiated rsa-sha2-256. Legacy ssh-rsa (SHA-1) is rejected.
pub fn sign(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Signature, String> {
    use super::{SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

    match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let private = rsa_private_key(keypair)?;
            // SHA-256 checked first when both flags are set, matching
            // prepare_sign_data() in agent.rs and OpenSSH's own
            // agent_decode_alg(), so every key source picks the same
            // algorithm for the same request.
            if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
                let sig = signer.try_sign(data).map_err(|e| e.to_string())?;
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    sig.to_vec(),
                )
                .map_err(|e| e.to_string())
            } else if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private);
                let sig = signer.try_sign(data).map_err(|e| e.to_string())?;
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    sig.to_vec(),
                )
                .map_err(|e| e.to_string())
            } else {
                Err("legacy ssh-rsa (SHA-1) signatures are not supported".to_string())
            }
        }
        _ => key.try_sign(data).map_err(|e| e.to_string()),
    }
}

/// Build an `rsa::RsaPrivateKey` from an ssh-key `RsaKeypair`.
///
/// Not ssh-key's own `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey`:
/// that impl (through 0.6.7) passes `[p, p]` as the prime factors
/// instead of `[p, q]`, so the rsa crate rejects the key with a
/// consistency error.
fn rsa_private_key(keypair: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey, String> {
    let uint = |mpint: &ssh_key::Mpint, what: &str| -> Result<rsa::BigUint, String> {
        mpint
            .as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(|| format!("RSA {what} is not a positive integer"))
    };
    let n = uint(&keypair.public.n, "modulus")?;
    let e = uint(&keypair.public.e, "public exponent")?;
    let d = uint(&keypair.private.d, "private exponent")?;
    let p = uint(&keypair.private.p, "prime p")?;
    let q = uint(&keypair.private.q, "prime q")?;
    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use signature::Verifier;
    use ssh_key::{EcdsaCurve, LineEnding};
    use std::sync::LazyLock;

    const TEST_PASSPHRASE: &str = "test-passphrase";

    // Fixture keys are generated at runtime, not embedded in the
    // source: even throwaway test keys trip secret scanners and risk
    // being copied somewhere real. LazyLock so each is generated once
    // per test binary run (RSA keygen is slow in debug builds).

    /// ed25519 key encrypted with TEST_PASSPHRASE, empty comment.
    static ENC_ED25519: LazyLock<PrivateKey> = LazyLock::new(|| {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        key.encrypt(&mut OsRng, TEST_PASSPHRASE).unwrap()
    });

    /// Unencrypted ecdsa-p256 key with comment "plain-ecdsa".
    static PLAIN_ECDSA: LazyLock<PrivateKey> = LazyLock::new(|| {
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        PrivateKey::new(key.key_data().clone(), "plain-ecdsa").unwrap()
    });

    /// Unencrypted rsa-2048 key with comment "plain-rsa".
    static PLAIN_RSA: LazyLock<PrivateKey> = LazyLock::new(|| {
        let keypair = ssh_key::private::RsaKeypair::random(&mut OsRng, 2048).unwrap();
        PrivateKey::new(KeypairData::Rsa(keypair), "plain-rsa").unwrap()
    });

    /// Write a private key file with 0600, like ssh-keygen does.
    /// A plain fs::write would land on 0644 under the usual umask and
    /// trip the strict permission check.
    fn write_key_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn write_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_key_file(
            &dir.path().join("id_ed25519"),
            ENC_ED25519.to_openssh(LineEnding::LF).unwrap().as_str(),
        );
        // Sibling .pub carries the comment (the encrypted blob hides it)
        let mut public = ENC_ED25519.public_key().clone();
        public.set_comment("pubfile-comment");
        std::fs::write(
            dir.path().join("id_ed25519.pub"),
            format!("{}\n", public.to_openssh().unwrap()),
        )
        .unwrap();
        write_key_file(
            &dir.path().join("id_ecdsa"),
            PLAIN_ECDSA.to_openssh(LineEnding::LF).unwrap().as_str(),
        );
        std::fs::write(
            dir.path().join("known_hosts"),
            "example.com ssh-ed25519 AAAA\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("config"), "Host *\n").unwrap();
        // Binary (non-UTF-8) file: skipped as "not a key", not an error
        std::fs::write(dir.path().join("blob"), [0x80u8, 0xff, 0x00, 0x01]).unwrap();
        dir
    }

    #[test]
    fn scan_finds_keys_and_skips_noise() {
        let dir = write_test_dir();
        let keys = scan(dir.path());
        assert_eq!(keys.len(), 2);

        // Sorted by path: id_ecdsa before id_ed25519
        assert!(!keys[0].encrypted);
        assert_eq!(keys[0].comment, "plain-ecdsa");
        assert!(matches!(keys[0].public, KeyData::Ecdsa(_)));

        // Encrypted key: comment falls back to the sibling .pub file
        assert!(keys[1].encrypted);
        assert_eq!(keys[1].comment, "pubfile-comment");
        assert!(matches!(keys[1].public, KeyData::Ed25519(_)));
    }

    #[test]
    fn scan_missing_dir_is_empty() {
        assert!(scan(Path::new("/nonexistent-tumpa-test-dir")).is_empty());
    }

    #[test]
    fn read_private_key_enforces_guards() {
        let dir = write_test_dir();

        let key = read_private_key(&dir.path().join("id_ecdsa")).unwrap();
        assert_eq!(key.comment(), "plain-ecdsa");

        // Oversized file: rejected even with a valid-looking header
        let big = dir.path().join("id_big");
        let mut contents = OPENSSH_HEADER.to_string();
        contents.push_str(&"A".repeat(MAX_KEY_FILE_SIZE as usize));
        std::fs::write(&big, contents).unwrap();
        assert!(read_private_key(&big).is_err());

        // Directory: not a regular file
        assert!(read_private_key(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn group_other_readable_keys_are_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = write_test_dir();
        let loose = dir.path().join("id_loose");
        write_key_file(
            &loose,
            PLAIN_ECDSA.to_openssh(LineEnding::LF).unwrap().as_str(),
        );
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();

        // scan: the world-readable copy does not add a third identity
        let keys = scan(dir.path());
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|k| k.path != loose));

        // sign-time read: rejected outright
        assert!(read_private_key(&loose).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped() {
        let dir = write_test_dir();
        let link = dir.path().join("id_link");
        std::os::unix::fs::symlink(dir.path().join("id_ecdsa"), &link).unwrap();

        // scan: the symlink does not add a third identity
        let keys = scan(dir.path());
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|k| k.path != link));

        // sign-time read: rejected outright
        assert!(read_private_key(&link).is_err());
    }

    #[test]
    fn decrypt_sign_verify_ed25519() {
        let key = &*ENC_ED25519;
        assert!(key.is_encrypted());
        assert!(key.decrypt(b"wrong-passphrase").is_err());

        let key = key.decrypt(TEST_PASSPHRASE).unwrap();
        let data = b"ssh session data";
        let sig = sign(&key, data, 0).unwrap();
        key.public_key().key_data().verify(data, &sig).unwrap();
    }

    #[test]
    fn sign_verify_ecdsa() {
        let key = &*PLAIN_ECDSA;
        let data = b"ssh session data";
        let sig = sign(key, data, 0).unwrap();
        key.public_key().key_data().verify(data, &sig).unwrap();
    }

    #[test]
    fn sign_rsa_honors_hash_flags() {
        use crate::ssh::{SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

        let key = &*PLAIN_RSA;
        let data = b"ssh session data";

        let sig256 = sign(key, data, SSH_AGENT_RSA_SHA2_256).unwrap();
        assert_eq!(
            sig256.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
        key.public_key().key_data().verify(data, &sig256).unwrap();

        let sig512 = sign(key, data, SSH_AGENT_RSA_SHA2_512).unwrap();
        assert_eq!(
            sig512.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
        key.public_key().key_data().verify(data, &sig512).unwrap();

        // Both flags set: SHA-256 wins, same as prepare_sign_data()
        // and OpenSSH's agent_decode_alg()
        let sig_both = sign(key, data, SSH_AGENT_RSA_SHA2_256 | SSH_AGENT_RSA_SHA2_512).unwrap();
        assert_eq!(
            sig_both.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );

        // flags == 0 would mean legacy ssh-rsa (SHA-1): rejected
        assert!(sign(key, data, 0).is_err());
    }
}
