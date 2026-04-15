use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use pgp::composed::{Deserializable, DetachedSignature};

use crate::store;

/// Sanitize a UID string for use in [GNUPG:] status lines.
/// Strips control characters (including newlines) that could inject
/// additional status lines parsed by git.
fn sanitize_uid(uid: &str) -> String {
    uid.chars().filter(|c| !c.is_control()).collect()
}

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

    // Read data from stdin
    let mut buffer = Vec::new();
    data.read_to_end(&mut buffer)
        .context("Failed to read data from stdin")?;

    // Read signature file
    let sig_bytes = std::fs::read(sig_path)
        .context(format!("Failed to read signature file {:?}", sig_path))?;

    // Parse the detached signature to extract issuer info.
    //
    // Note: wecanencrypt::verify_bytes_detached (called below at L70) re-parses
    // sig_bytes internally using the same pgp crate (v0.19) and the same
    // DetachedSignature type, so both parses are guaranteed to agree.
    // The issuer IDs extracted here correspond to the key that verification
    // will actually check against.
    let detached_sig = parse_detached_signature(&sig_bytes)?;
    let sig_config = detached_sig
        .signature
        .config()
        .context("Signature has no config")?;

    let issuer_ids = store::extract_issuer_ids(sig_config);

    if issuer_ids.is_empty() {
        writeln!(err, "tcli: No issuer information in signature")?;
        anyhow::bail!("Cannot determine signature issuer");
    }

    log::info!("Signature issuer IDs: {:?}", issuer_ids);

    // Open keystore and look up the signer
    let keystore = store::open_keystore(keystore_path)?;
    let lookup = store::resolve_from_issuer_ids(&keystore, &issuer_ids)?;

    let Some((cert_data, cert_info)) = lookup else {
        // Certificate not in keystore. Emit ERRSIG + NO_PUBKEY status lines
        // on stdout for git, but nothing on stderr. Tools like bump-tag
        // capture stderr and treat any output as a verification warning,
        // so silence is safest here. Git reads the status lines to determine
        // the signature is from an unknown key.
        let key_id = if let Some(kid) = issuer_ids.iter().find(|id| id.len() == 16) {
            kid.to_uppercase()
        } else if let Some(fp) = issuer_ids.iter().find(|id| id.len() == 40) {
            fp[24..].to_uppercase()
        } else {
            issuer_ids.first().map(|s| s.to_uppercase()).unwrap_or_default()
        };
        log::info!("Certificate not found for key ID {}", key_id);
        writeln!(out, "\n[GNUPG:] ERRSIG {}", key_id)?;
        write!(out, "[GNUPG:] NO_PUBKEY {}", key_id)?;
        return Ok(());
    };

    // Verify the signature
    let valid = wecanencrypt::verify_bytes_detached(&cert_data, &buffer, &sig_bytes)
        .unwrap_or(false);

    if valid {
        // Get the issuer fingerprint from the signature for status output
        let verifier_fp = issuer_ids
            .iter()
            .find(|id| id.len() == 40)
            .cloned()
            .unwrap_or_else(|| cert_info.fingerprint.clone());

        let verifier_key_id = if verifier_fp.len() == 40 {
            verifier_fp[24..].to_uppercase()
        } else {
            verifier_fp.to_uppercase()
        };

        // Collect non-revoked UIDs, primary first (matching gpg output order)
        let mut uids: Vec<_> = cert_info.user_ids.iter().filter(|u| !u.revoked).collect();
        uids.sort_by(|a, b| b.is_primary.cmp(&a.is_primary));

        // Human-readable output to stderr (matching gpg output style)
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

        // Git-parseable status output to stdout
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

        writeln!(out, "[GNUPG:] VALIDSIG {}", verifier_fp.to_uppercase())?;
        // Trust level - git checks for TRUST_FULLY or TRUST_ULTIMATE to produce %G? = "G"
        // Without this, %G? would be "U" (untrusted), which bump-tag rejects
        write!(out, "[GNUPG:] TRUST_FULLY 0 pgp")?;
    } else {
        writeln!(err, "tcli: BAD signature by key {}", cert_info.fingerprint)?;
        // Use primary UID for BADSIG line
        let bad_uid = cert_info
            .user_ids
            .iter()
            .filter(|u| !u.revoked)
            .max_by_key(|u| u.is_primary)
            .map(|u| sanitize_uid(&u.value))
            .unwrap_or_default();
        writeln!(
            out,
            "\n[GNUPG:] BADSIG {} {}",
            cert_info.key_id.to_uppercase(),
            bad_uid
        )?;
        anyhow::bail!("Signature verification failed");
    }

    Ok(())
}

/// Parse a detached signature from bytes (armored or binary).
fn parse_detached_signature(sig_bytes: &[u8]) -> Result<DetachedSignature> {
    // Try armored first
    if let Ok((sig, _)) = DetachedSignature::from_armor_single(Cursor::new(sig_bytes)) {
        return Ok(sig);
    }

    // Try binary
    DetachedSignature::from_bytes(Cursor::new(sig_bytes))
        .context("Failed to parse detached signature (tried both armored and binary formats)")
}
