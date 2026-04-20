//! GPG-shape verify wrapper.
//!
//! Reads stdin + signature file, delegates the parse/lookup/verify to
//! `libtumpa::verify::verify_detached`, then formats the result as the
//! `[GNUPG:]` status lines git/pass expect.

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use libtumpa::verify::{sanitize_uid_for_status as sanitize_uid, verify_detached, VerifyOutcome};

use crate::store;

/// Verify a detached signature.
///
/// Reads signed data from stdin, reads signature from file,
/// looks up the signer in the tumpa keystore, and outputs
/// GNUPG-compatible status lines for git.
pub fn verify(
    mut data: impl Read,
    mut out: impl Write,
    mut err: impl Write,
    sig_path: &PathBuf,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    log::info!("verify called for signature file: {:?}", sig_path);

    let mut buffer = Vec::new();
    data.read_to_end(&mut buffer)
        .context("Failed to read data from stdin")?;

    let sig_bytes = std::fs::read(sig_path)
        .context(format!("Failed to read signature file {:?}", sig_path))?;

    let keystore = store::open_keystore(keystore_path)?;
    let outcome = verify_detached(&keystore, &buffer, &sig_bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    match outcome {
        VerifyOutcome::UnknownKey { key_id } => {
            // Tools like bump-tag capture stderr and treat any output as a
            // verification warning, so silence is safest here. Git reads the
            // status lines on stdout to determine the signature is from an
            // unknown key.
            log::info!("Certificate not found for key ID {}", key_id);
            writeln!(out, "\n[GNUPG:] ERRSIG {}", key_id)?;
            write!(out, "[GNUPG:] NO_PUBKEY {}", key_id)?;
            Ok(())
        }
        VerifyOutcome::Good {
            key_info,
            verifier_fingerprint,
        } => {
            let verifier_key_id = if verifier_fingerprint.len() == 40 {
                verifier_fingerprint[24..].to_uppercase()
            } else {
                verifier_fingerprint.to_uppercase()
            };

            // Collect non-revoked UIDs, primary first (matching gpg output order)
            let mut uids: Vec<_> = key_info.user_ids.iter().filter(|u| !u.revoked).collect();
            uids.sort_by_key(|u| std::cmp::Reverse(u.is_primary));

            for (i, uid) in uids.iter().enumerate() {
                if i == 0 {
                    writeln!(
                        err,
                        "tcli: Good signature from \"{}\"",
                        sanitize_uid(&uid.value)
                    )?;
                } else {
                    writeln!(
                        err,
                        "tcli:                 aka \"{}\"",
                        sanitize_uid(&uid.value)
                    )?;
                }
            }

            // Git-parseable status output.
            // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
            if let Some(uid) = uids.first() {
                writeln!(
                    out,
                    "\n[GNUPG:] GOODSIG {} {}",
                    verifier_key_id,
                    sanitize_uid(&uid.value)
                )?;
            } else {
                writeln!(out, "\n[GNUPG:] GOODSIG {}", verifier_key_id)?;
            }
            writeln!(out, "[GNUPG:] VALIDSIG {}", verifier_fingerprint.to_uppercase())?;
            // %G? = "G" requires TRUST_FULLY or TRUST_ULTIMATE; without it
            // git's %G? would be "U" (untrusted) and bump-tag rejects that.
            write!(out, "[GNUPG:] TRUST_FULLY 0 pgp")?;
            Ok(())
        }
        VerifyOutcome::Bad { key_info } => {
            writeln!(err, "tcli: BAD signature by key {}", key_info.fingerprint)?;
            let bad_uid = key_info
                .user_ids
                .iter()
                .filter(|u| !u.revoked)
                .max_by_key(|u| u.is_primary)
                .map(|u| sanitize_uid(&u.value))
                .unwrap_or_default();
            writeln!(
                out,
                "\n[GNUPG:] BADSIG {} {}",
                key_info.key_id.to_uppercase(),
                bad_uid
            )?;
            anyhow::bail!("Signature verification failed");
        }
    }
}
