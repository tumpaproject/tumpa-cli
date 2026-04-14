use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use pgp::composed::{Deserializable, DetachedSignature};

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

    // Read data from stdin
    let mut buffer = Vec::new();
    data.read_to_end(&mut buffer)
        .context("Failed to read data from stdin")?;

    // Read signature file
    let sig_bytes =
        std::fs::read(sig_path).context(format!("Failed to read signature file {:?}", sig_path))?;

    // Parse the detached signature to extract issuer info
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
        writeln!(
            err,
            "tcli: Can't check signature: Certificate not found for {:?}",
            issuer_ids
        )?;
        // Don't fail hard - git will interpret absence of GOODSIG as unverified
        return Ok(());
    };

    // Verify the signature
    let valid =
        wecanencrypt::verify_bytes_detached(&cert_data, &buffer, &sig_bytes).unwrap_or(false);

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

        // Human-readable output to stderr
        writeln!(err, "tcli: Good signature by key {}", verifier_fp)?;
        if let Some(uid) = cert_info.user_ids.first() {
            writeln!(err, "tcli: Signer: \"{}\"", uid.value)?;
        }

        // Git-parseable status output to stdout
        // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L371
        if let Some(uid) = cert_info.user_ids.first() {
            writeln!(out, "\n[GNUPG:] GOODSIG {} {}", verifier_key_id, uid.value)?;
        } else {
            writeln!(out, "\n[GNUPG:] GOODSIG {}", verifier_key_id)?;
        }

        writeln!(out, "[GNUPG:] VALIDSIG {}", verifier_fp.to_uppercase())?;
        // Trust level - git checks for TRUST_FULLY or TRUST_ULTIMATE to produce %G? = "G"
        // Without this, %G? would be "U" (untrusted), which bump-tag rejects
        write!(out, "[GNUPG:] TRUST_FULLY 0 pgp")?;
    } else {
        writeln!(err, "tcli: BAD signature by key {}", cert_info.fingerprint)?;
        writeln!(
            out,
            "\n[GNUPG:] BADSIG {} {}",
            cert_info.key_id.to_uppercase(),
            cert_info
                .user_ids
                .first()
                .map(|u| u.value.as_str())
                .unwrap_or("")
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
