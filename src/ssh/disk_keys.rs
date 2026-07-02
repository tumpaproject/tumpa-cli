//! Serving OpenSSH private keys from `~/.ssh` through the agent.
//!
//! Keys are discovered by scanning the directory for files in OpenSSH
//! private key format. The public half of an encrypted key is stored
//! in cleartext, so identities can be listed without prompting -- the
//! passphrase is only needed (and cached) when a sign request arrives.

use std::path::{Path, PathBuf};

use signature::{SignatureEncoding, Signer};
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};

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
/// by the PEM-header check; unreadable or unparsable files are logged
/// at debug level and ignored so one bad file never hides the rest.
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
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE_SIZE {
        return Ok(None);
    }

    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        // Non-UTF-8 means a binary file (host key blob, etc.), which
        // is genuinely not an OpenSSH key. Anything else (permission
        // denied, transient I/O) could be hiding a real key, so bubble
        // it up for scan() to log.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !contents.trim_start().starts_with(OPENSSH_HEADER) {
        return Ok(None);
    }

    let key = PrivateKey::from_openssh(&contents).map_err(|e| e.to_string())?;
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

/// Read the comment from the sibling `<key>.pub` file, if any.
fn pub_file_comment(path: &Path) -> Option<String> {
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    let line = std::fs::read_to_string(pub_path).ok()?;
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
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let private = rsa_private_key(keypair)?;
            if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private);
                let sig = signer.try_sign(data).map_err(|e| e.to_string())?;
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    sig.to_vec(),
                )
                .map_err(|e| e.to_string())
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
                let sig = signer.try_sign(data).map_err(|e| e.to_string())?;
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
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
    use signature::Verifier;

    /// ed25519 key encrypted with passphrase "test-passphrase",
    /// generated with `ssh-keygen -t ed25519 -N test-passphrase -C ""`.
    const ENC_ED25519: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD/vf2Qcy
2ywzhpgK7HUBOLAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIO0g1ilex9fUv+3V
5IJtKziUjLrJp2cAXkgybUI1S4CvAAAAkGwL+c/loUJhSLpHmjKHRxRG1Fyo/iY5w8AvMH
qvy7TTYi7uvKPBZtt0UZ6IC4p16rPn2E1qSXlXTNb0B2ui8zxa7cFBL8K160NMyia6RBCx
yjejCqilbgfjEkvTZwzSgy5Spkb2AxpEZ7aq9/u0E/lkdpC0yA6/0J6DJsj5iVJeHCvuew
BI/vU/iZX7UGKihg==
-----END OPENSSH PRIVATE KEY-----
";
    const ENC_ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO0g1ilex9fUv+3V5IJtKziUjLrJp2cAXkgybUI1S4Cv pubfile-comment\n";

    /// Unencrypted ecdsa-p256 key with comment "plain-ecdsa".
    const PLAIN_ECDSA: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRrIAKnfk0833ZKto7RC2hZ9I4Ddyb/
vBWp1xB6PL9j7e41vcA4HlemNn3lkxc1zIVMZOiBoiZ0WTmooynuGeNaAAAAqGxAZzlsQG
c5AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGsgAqd+TTzfdkq2
jtELaFn0jgN3Jv+8FanXEHo8v2Pt7jW9wDgeV6Y2feWTFzXMhUxk6IGiJnRZOaijKe4Z41
oAAAAgJGkvYQB8WKU6gHsnd1aTV8MQ64fww4H22SThKhJDN1cAAAALcGxhaW4tZWNkc2EB
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

    /// Unencrypted rsa-2048 key with comment "plain-rsa".
    const PLAIN_RSA: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAqWlr0nGLEs9eUuhL+Jk4giZJLQ2dKS5BhWHVPLTIt+lovwgiozBx
risoSHD212vDbVyy3K6s6+CPUh+19QTb6Xxg2k2SttDgELg67xv84uyGya9q8qwjjNZgub
qsYDiTtux7C8wUOsLLAQ/mSGluwbIbYwQ3XJWtg1jTGaAf6gphjOGglBgMV46T8UcKLMDH
tGBwaGOlmrg6dUfH7U2t+8QuwS/DldCYTV5DmBk2DD+9hhTnTHX7++8xcQD8N88z8z9Ppt
HAN8PI3rqv8Ml940q+y7WPoIkdIOV95EIq0XmkMr2oF1mHZyeBk8hzP2NZSeoMedW7CDdZ
G4j2Sqmv1QAAA8B3mP+Dd5j/gwAAAAdzc2gtcnNhAAABAQCpaWvScYsSz15S6Ev4mTiCJk
ktDZ0pLkGFYdU8tMi36Wi/CCKjMHGuKyhIcPbXa8NtXLLcrqzr4I9SH7X1BNvpfGDaTZK2
0OAQuDrvG/zi7IbJr2ryrCOM1mC5uqxgOJO27HsLzBQ6wssBD+ZIaW7BshtjBDdcla2DWN
MZoB/qCmGM4aCUGAxXjpPxRwoswMe0YHBoY6WauDp1R8ftTa37xC7BL8OV0JhNXkOYGTYM
P72GFOdMdfv77zFxAPw3zzPzP0+m0cA3w8jeuq/wyX3jSr7LtY+giR0g5X3kQirReaQyva
gXWYdnJ4GTyHM/Y1lJ6gx51bsIN1kbiPZKqa/VAAAAAwEAAQAAAQAHGdceJAo7SJvgh8If
cnSu5+HrVIXA4yJ178rbV4yOQOdWEoY5Jt+s+DwhBTMjhm3TmK4al+vBm1EGlTOwSHrbR4
5buCKtLQYnTUGTIi4waM+hhovKDjMTRS0au9tb0SNH6JOjw/MZH28Y5Uy2vkyZK9kABn43
kEKMnd2DVnXf/mvoI0HUugLrYeK9PtR5/xJt0RUMg244mQUbgE+1vOm0PveTyLXols/FO1
v+0yb9AhXmHahW62CTqsTtyGXG8ixgSBA343h3Rb2gbaLR6xqZx3GvyZDUT9rU+ySmn8rc
W7qjblA/14kvpV3bf7+0QVccu2aABTvd5qOzX8jfCz+hAAAAgQCcTdoCWqxXa/fpsdK6s3
jnalxtJsrOHELB+kRN1rSZp/RyCiObwLLIrdwOYhrGOsAaQKe8td2XLGP46hfFI1R35sDG
9NSveAKtPC4Q9/8hSKxzLZTNTApqX5dxnJ5Ql+l8Tj4pmR8Z+I4z4EywkOBxt7iKcL0NO+
Ujq0xC2T/fcQAAAIEA3c9nM70ZfgGZFboedf6Nh0qKY4S6S+Yh9bpiVI9ZNf8X6nGY5Cz9
oXIeGZP1ViHohsv206GMlTzIDFxrghbttIzV8QMUQIomueiB40ekHELEPUqLAzgqr29z68
yx7+uwEPimCNtC+KIqaRiIfwGIykAcuV48V9Bj9qckAwaDb40AAACBAMOGYtmwtPeDdIDQ
CNN5ctzNCeDA8v9OVQ+nqNsV88ZwunLWUajFTBTEaAeEi7VnlalVyljy+dmmJSHcQ+GiJM
Cvht16q9oxLqJ4S1JXJMYZfDYXFuupclu45r9/nkHHoZiGJFN0ZX07emSKAs0B1WYeuPyt
19ZMX8UNF3v+5WtpAAAACXBsYWluLXJzYQE=
-----END OPENSSH PRIVATE KEY-----
";

    fn write_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519"), ENC_ED25519).unwrap();
        std::fs::write(dir.path().join("id_ed25519.pub"), ENC_ED25519_PUB).unwrap();
        std::fs::write(dir.path().join("id_ecdsa"), PLAIN_ECDSA).unwrap();
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
    fn decrypt_sign_verify_ed25519() {
        let key = PrivateKey::from_openssh(ENC_ED25519).unwrap();
        assert!(key.is_encrypted());
        assert!(key.decrypt(b"wrong-passphrase").is_err());

        let key = key.decrypt(b"test-passphrase").unwrap();
        let data = b"ssh session data";
        let sig = sign(&key, data, 0).unwrap();
        key.public_key().key_data().verify(data, &sig).unwrap();
    }

    #[test]
    fn sign_verify_ecdsa() {
        let key = PrivateKey::from_openssh(PLAIN_ECDSA).unwrap();
        let data = b"ssh session data";
        let sig = sign(&key, data, 0).unwrap();
        key.public_key().key_data().verify(data, &sig).unwrap();
    }

    #[test]
    fn sign_rsa_honors_hash_flags() {
        let key = PrivateKey::from_openssh(PLAIN_RSA).unwrap();
        let data = b"ssh session data";

        let sig256 = sign(&key, data, 2).unwrap();
        assert_eq!(
            sig256.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
        key.public_key().key_data().verify(data, &sig256).unwrap();

        let sig512 = sign(&key, data, 4).unwrap();
        assert_eq!(
            sig512.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
        key.public_key().key_data().verify(data, &sig512).unwrap();

        // flags == 0 would mean legacy ssh-rsa (SHA-1): rejected
        assert!(sign(&key, data, 0).is_err());
    }
}
