//! `tcli --verify` implementation.
//!
//! Human-shape verify command. The GPG-shape verify used by `tclig`
//! lives in `gpg::verify` and stays unchanged.
//!
//! Two flavors:
//! - **Detached**: `--signature SIG_FILE` is set; verify SIG against the
//!   bytes of FILE.
//! - **Inline**: no `--signature`; FILE itself is a cleartext-signed
//!   message (`-----BEGIN PGP SIGNED MESSAGE-----`).
//!
//! `--with-key FILE` (optional) verifies against an external public-key
//! file instead of the keystore.
//!
//! Exit codes (returned via [`VerifyExit`]):
//! - `0` (`Good`) — signature valid.
//! - `1` (`Bad`) — signature invalid for a known key.
//! - `2` (`Unknown`) — signer not in keystore, no `--with-key` supplied.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use libtumpa::verify::{
    sanitize_uid_for_status as sanitize_uid, verify_detached, verify_inline, VerifyOutcome,
};
use wecanencrypt::KeyInfo;

use crate::cli::is_stdio;
use crate::store;

/// Logical exit-code outcome for `tcli --verify`. main.rs maps these to
/// process exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyExit {
    Good,
    Bad,
    Unknown,
}

impl VerifyExit {
    pub fn code(self) -> i32 {
        match self {
            Self::Good => 0,
            Self::Bad => 1,
            Self::Unknown => 2,
        }
    }
}

/// `tcli --verify FILE [--signature SIG] [--with-key PUB_FILE]`.
pub fn cmd_verify(
    input: &Path,
    signature: Option<&PathBuf>,
    with_key_file: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<VerifyExit> {
    let data = read_input(input)?;

    // External public-key path: do not touch the keystore at all.
    if let Some(pub_file) = with_key_file {
        let cert_data = std::fs::read(pub_file)
            .with_context(|| format!("Failed to read public key file {}", pub_file.display()))?;
        let cert_info = wecanencrypt::parse_key_bytes(&cert_data, true)
            .map_err(|e| anyhow!("Failed to parse {}: {e}", pub_file.display()))?;

        return match signature {
            Some(sig_path) => {
                let sig_bytes = std::fs::read(sig_path).with_context(|| {
                    format!("Failed to read signature file {}", sig_path.display())
                })?;
                let valid = wecanencrypt::verify_bytes_detached(&cert_data, &data, &sig_bytes)
                    .map_err(|e| anyhow!("verify_bytes_detached: {e}"))?;
                report_external(&cert_info, valid);
                Ok(if valid {
                    VerifyExit::Good
                } else {
                    VerifyExit::Bad
                })
            }
            None => {
                let valid = wecanencrypt::verify_bytes(&cert_data, &data)
                    .map_err(|e| anyhow!("verify_bytes: {e}"))?;
                report_external(&cert_info, valid);
                Ok(if valid {
                    VerifyExit::Good
                } else {
                    VerifyExit::Bad
                })
            }
        };
    }

    // Keystore lookup path.
    let keystore = store::open_keystore(keystore_path)?;

    let outcome = match signature {
        Some(sig_path) => {
            let sig_bytes = std::fs::read(sig_path)
                .with_context(|| format!("Failed to read signature file {}", sig_path.display()))?;
            verify_detached(&keystore, &data, &sig_bytes).map_err(|e| anyhow!("{e}"))?
        }
        None => verify_inline(&keystore, &data).map_err(|e| anyhow!("{e}"))?,
    };

    Ok(report_outcome(outcome))
}

/// Print human-readable result and pick the exit category.
///
/// `Good`: lists every non-revoked UID (primary first, then `aka …`),
/// then the verifier fingerprint.
fn report_outcome(outcome: VerifyOutcome) -> VerifyExit {
    match outcome {
        VerifyOutcome::Good {
            key_info,
            verifier_fingerprint,
        } => {
            print_uids("Good signature from", &key_info);
            eprintln!(
                "tcli: Primary key fingerprint: {}",
                key_info.fingerprint.to_uppercase()
            );
            if verifier_fingerprint.to_uppercase() != key_info.fingerprint.to_uppercase() {
                eprintln!(
                    "tcli:      Subkey fingerprint: {}",
                    verifier_fingerprint.to_uppercase()
                );
            }
            VerifyExit::Good
        }
        VerifyOutcome::Bad { key_info } => {
            eprintln!(
                "tcli: BAD signature by key {}",
                key_info.fingerprint.to_uppercase()
            );
            print_uids("                       claimed UID:", &key_info);
            VerifyExit::Bad
        }
        VerifyOutcome::UnknownKey { key_id } => {
            eprintln!(
                "tcli: Unknown signer; key ID {} is not in the keystore.",
                key_id
            );
            eprintln!("tcli: Use --with-key <PUB_FILE> to verify against an external public key.");
            VerifyExit::Unknown
        }
    }
}

/// Same human output as the keystore path, but for the external-key
/// branch where we have a `KeyInfo` parsed from the supplied file.
fn report_external(cert_info: &KeyInfo, valid: bool) {
    if valid {
        print_uids("Good signature from", cert_info);
        eprintln!(
            "tcli: Primary key fingerprint: {}  (verified against --with-key)",
            cert_info.fingerprint.to_uppercase()
        );
    } else {
        eprintln!(
            "tcli: BAD signature against --with-key (fingerprint {})",
            cert_info.fingerprint.to_uppercase()
        );
        print_uids("                       claimed UID:", cert_info);
    }
}

/// Render every non-revoked UID, primary first; first one prefixed with
/// `lead`, the rest as `aka`.
fn print_uids(lead: &str, key_info: &KeyInfo) {
    let mut uids: Vec<_> = key_info.user_ids.iter().filter(|u| !u.revoked).collect();
    uids.sort_by_key(|u| std::cmp::Reverse(u.is_primary));

    if uids.is_empty() {
        eprintln!("tcli: {} key {}", lead, key_info.fingerprint.to_uppercase());
        return;
    }

    for (i, uid) in uids.iter().enumerate() {
        if i == 0 {
            eprintln!("tcli: {} \"{}\"", lead, sanitize_uid(&uid.value));
        } else {
            eprintln!("tcli:                 aka \"{}\"", sanitize_uid(&uid.value));
        }
    }
}

fn read_input(input: &Path) -> Result<Vec<u8>> {
    if is_stdio(input) {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read from stdin")?;
        Ok(buf)
    } else {
        std::fs::read(input).with_context(|| format!("Failed to read {}", input.display()))
    }
}
