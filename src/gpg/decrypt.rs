//! GPG-shape decrypt wrapper.
//!
//! All key resolution + card / software decrypt primitives live in
//! `libtumpa::decrypt`. This module owns the file/stdin I/O, the pinentry
//! prompts, the card-first dispatch glue, and the `gpg --decrypt
//! --list-only` shape that `pass` greps for.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libtumpa::decrypt as ltd;
use libtumpa::decrypt::DecryptVerifyOutcome;
use libtumpa::verify::sanitize_uid_for_status;
use libtumpa::{Passphrase, Pin};
use zeroize::Zeroizing;

use crate::pinentry;
use crate::store;

/// Read ciphertext from a file, or from stdin if `input` is `-`.
fn read_ciphertext(input: &Path) -> Result<Vec<u8>> {
    if input.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read encrypted data from stdin")?;
        Ok(buf)
    } else {
        std::fs::read(input).with_context(|| format!("Failed to read encrypted file {:?}", input))
    }
}

/// Decrypt a file.
///
/// Reads ciphertext from `input`, determines which secret key can decrypt
/// it, prompts for the passphrase, and writes plaintext to `output`
/// (or stdout if None).
pub fn decrypt(
    input: &Path,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let ciphertext = read_ciphertext(input)?;

    let key_ids = ltd::recipients_of(&ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to inspect encrypted message")?;

    if key_ids.is_empty() {
        anyhow::bail!("Cannot determine recipient key IDs from encrypted message");
    }
    log::debug!("Message encrypted for key IDs: {:?}", key_ids);

    // Try card first, then software (matches signing priority)
    let plaintext = match try_decrypt_on_card(&ciphertext, &keystore) {
        Ok(pt) => pt,
        Err(card_err) => {
            log::info!(
                "Card decryption not available ({}), trying software key",
                card_err
            );
            decrypt_with_software(&ciphertext, &keystore, &key_ids, &card_err)?
        }
    };

    match output {
        Some(path) => {
            std::fs::write(path, plaintext.as_slice())
                .context(format!("Failed to write output file {:?}", path))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(path, perms).ok();
            }
        }
        None => {
            std::io::stdout()
                .write_all(plaintext.as_slice())
                .context("Failed to write to stdout")?;
        }
    }

    Ok(())
}

/// Try to decrypt using a connected OpenPGP card via libtumpa, prompting
/// for the PIN here in tumpa-cli.
fn try_decrypt_on_card(
    ciphertext: &[u8],
    keystore: &wecanencrypt::KeyStore,
) -> Result<Zeroizing<Vec<u8>>> {
    let card = ltd::find_decryption_card(keystore, ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("No card with matching decryption key found"))?;

    let uid = card
        .key_info
        .user_ids
        .first()
        .map(|u| u.value.as_str())
        .unwrap_or(&card.key_info.fingerprint);

    let mut desc = format!(
        "Please unlock the card\n\nNumber: {}",
        card.card.serial_number
    );
    if let Ok(info) = wecanencrypt::card::get_card_details(Some(&card.card.ident)) {
        if let Some(ref raw) = info.cardholder_name {
            let name = pinentry::format_cardholder_name(raw);
            if !name.is_empty() {
                desc.push_str(&format!("\nHolder: {}", name));
            }
        }
    }
    desc.push_str(&format!("\n\nDecrypting for: {}", uid));

    let pin = pinentry::get_passphrase(&desc, "PIN", Some(&card.key_info.fingerprint))?;
    let pin_obj = Pin::new(pin.as_bytes().to_vec());

    match ltd::decrypt_on_card(&card.key_data, ciphertext, &pin_obj, Some(&card.card.ident)) {
        Ok(z) => {
            pinentry::cache_pin(&card.key_info.fingerprint, &pin);
            Ok(Zeroizing::new(z.to_vec()))
        }
        Err(e) => {
            pinentry::clear_cached_pin(&card.key_info.fingerprint);
            Err(anyhow::anyhow!("{e}")).context("Card decryption failed")
        }
    }
}

/// Software fallback: find a secret key in the keystore for one of the
/// recipient key IDs, prompt for its passphrase, and decrypt.
fn decrypt_with_software(
    ciphertext: &[u8],
    keystore: &wecanencrypt::KeyStore,
    key_ids: &[String],
    card_err: &anyhow::Error,
) -> Result<Zeroizing<Vec<u8>>> {
    let (key_data, key_info) = ltd::find_software_decryption_key(keystore, ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Card decryption failed: {}\nNo software secret key found for key IDs: {}",
                card_err,
                key_ids.join(", ")
            )
        })?;

    let desc = format!(
        "Enter passphrase to decrypt with key {}",
        key_info
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or(&key_info.fingerprint)
    );
    // `Passphrase` is `Zeroizing<String>`; pass the value libtumpa
    // expects directly without a plaintext `to_string()` copy.
    let passphrase: Passphrase =
        pinentry::get_passphrase(&desc, "Passphrase", Some(&key_info.fingerprint))?;

    match ltd::decrypt_with_key(&key_data, ciphertext, &passphrase) {
        Ok(z) => {
            pinentry::cache_passphrase(&key_info.fingerprint, &passphrase);
            Ok(Zeroizing::new(z.to_vec()))
        }
        Err(e) => {
            pinentry::clear_cached_passphrase(&key_info.fingerprint);
            Err(anyhow::anyhow!("{e}")).context("Decryption failed")
        }
    }
}

/// Decrypt + verify in one pass, emitting GnuPG-shape `[GNUPG:]` status
/// lines for the inner signature so PGP/MIME callers (Mail extension)
/// can render lock + signed-by chrome correctly.
///
/// Card-first dispatch: when the decryption subkey lives on a connected
/// card, the card decrypts the session key; otherwise we fall back to a
/// software secret key with passphrase. In both cases the inner
/// signature classification (Good / Bad / Unsigned / UnknownKey) is
/// shape-identical and surfaces through the same `[GNUPG:]` status lines
/// downstream.
///
/// Status lines on `status_out` (stderr-shaped fd):
/// - `[GNUPG:] DECRYPTION_OKAY` — decryption succeeded
/// - `[GNUPG:] GOODSIG <fpr> <uid>` — inner sig verified by `<fpr>`
/// - `[GNUPG:] BADSIG <fpr> <uid>` — inner sig present, did not verify
/// - `[GNUPG:] NO_PUBKEY <key_id>` — inner sig present, signer absent
/// - (no signature lines) — encrypt-only payload
///
/// The fingerprint and UID are sanitized for line-based output before
/// emission (no embedded `\n` per the `verify` module's status-stream
/// injection guidance).
pub fn decrypt_and_verify(
    input: &Path,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
    mut status_out: impl Write,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let ciphertext = read_ciphertext(input)?;

    let key_ids = ltd::recipients_of(&ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to inspect encrypted message")?;
    if key_ids.is_empty() {
        anyhow::bail!("Cannot determine recipient key IDs from encrypted message");
    }

    let result = match try_decrypt_and_verify_on_card(&ciphertext, &keystore) {
        Ok(r) => r,
        Err(card_err) => {
            log::info!(
                "Card decrypt+verify not available ({}), trying software key",
                card_err
            );
            decrypt_and_verify_with_software(&ciphertext, &keystore, &key_ids, &card_err)?
        }
    };

    // Write plaintext first, then status lines — that way a downstream
    // pipe consumer that closes early on signature status doesn't lose
    // data. (PGP/MIME callers buffer both anyway.)
    match output {
        Some(path) => {
            std::fs::write(path, result.plaintext.as_slice())
                .context(format!("Failed to write output file {:?}", path))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(path, perms).ok();
            }
        }
        None => {
            std::io::stdout()
                .write_all(result.plaintext.as_slice())
                .context("Failed to write to stdout")?;
        }
    }

    writeln!(status_out, "[GNUPG:] DECRYPTION_OKAY")?;
    emit_signature_status(&mut status_out, &result.outcome)?;

    Ok(())
}

/// Try to decrypt + verify on a connected card. Mirrors `try_decrypt_on_card`
/// but threads the inner-signature outcome through libtumpa's
/// `decrypt_and_verify_on_card`.
fn try_decrypt_and_verify_on_card(
    ciphertext: &[u8],
    keystore: &wecanencrypt::KeyStore,
) -> Result<libtumpa::decrypt::DecryptVerifyResult> {
    let card = ltd::find_decryption_card(keystore, ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("No card with matching decryption key found"))?;

    let uid = card
        .key_info
        .user_ids
        .first()
        .map(|u| u.value.as_str())
        .unwrap_or(&card.key_info.fingerprint);

    let mut desc = format!(
        "Please unlock the card\n\nNumber: {}",
        card.card.serial_number
    );
    if let Ok(info) = wecanencrypt::card::get_card_details(Some(&card.card.ident)) {
        if let Some(ref raw) = info.cardholder_name {
            let name = pinentry::format_cardholder_name(raw);
            if !name.is_empty() {
                desc.push_str(&format!("\nHolder: {}", name));
            }
        }
    }
    desc.push_str(&format!("\n\nDecrypting for: {}", uid));

    let pin = pinentry::get_passphrase(&desc, "PIN", Some(&card.key_info.fingerprint))?;
    let pin_obj = Pin::new(pin.as_bytes().to_vec());

    match ltd::decrypt_and_verify_on_card(
        keystore,
        &card.key_data,
        ciphertext,
        &pin_obj,
        Some(&card.card.ident),
    ) {
        Ok(r) => {
            pinentry::cache_pin(&card.key_info.fingerprint, &pin);
            Ok(r)
        }
        Err(e) => {
            pinentry::clear_cached_pin(&card.key_info.fingerprint);
            Err(anyhow::anyhow!("{e}")).context("Card decrypt+verify failed")
        }
    }
}

/// Software fallback for `decrypt_and_verify`: find a software secret key,
/// prompt for the passphrase, decrypt, and verify the inner signature.
fn decrypt_and_verify_with_software(
    ciphertext: &[u8],
    keystore: &wecanencrypt::KeyStore,
    key_ids: &[String],
    card_err: &anyhow::Error,
) -> Result<libtumpa::decrypt::DecryptVerifyResult> {
    let (key_data, key_info) = ltd::find_software_decryption_key(keystore, ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Card decrypt+verify failed: {}\n\
                 No software secret key found for key IDs: {}",
                card_err,
                key_ids.join(", ")
            )
        })?;

    let desc = format!(
        "Enter passphrase to decrypt with key {}",
        key_info
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or(&key_info.fingerprint)
    );
    let passphrase: Passphrase =
        pinentry::get_passphrase(&desc, "Passphrase", Some(&key_info.fingerprint))?;

    match ltd::decrypt_and_verify_with_key(keystore, &key_data, ciphertext, &passphrase) {
        Ok(r) => {
            pinentry::cache_passphrase(&key_info.fingerprint, &passphrase);
            Ok(r)
        }
        Err(e) => {
            pinentry::clear_cached_passphrase(&key_info.fingerprint);
            Err(anyhow::anyhow!("{e}")).context("Decryption failed")
        }
    }
}

fn emit_signature_status(
    status_out: &mut impl Write,
    outcome: &DecryptVerifyOutcome,
) -> Result<()> {
    match outcome {
        DecryptVerifyOutcome::Unsigned => {
            // Encrypt-only — no signature line emitted, matching gpg.
        }
        DecryptVerifyOutcome::Good {
            key_info,
            verifier_fingerprint,
        } => {
            let uid = key_info
                .user_ids
                .iter()
                .find(|u| u.is_primary && !u.revoked)
                .or_else(|| key_info.user_ids.iter().find(|u| !u.revoked))
                .map(|u| sanitize_uid_for_status(&u.value))
                .unwrap_or_else(|| key_info.fingerprint.clone());
            writeln!(status_out, "[GNUPG:] GOODSIG {verifier_fingerprint} {uid}")?;
        }
        DecryptVerifyOutcome::Bad { key_info } => {
            let uid = key_info
                .user_ids
                .iter()
                .find(|u| !u.revoked)
                .map(|u| sanitize_uid_for_status(&u.value))
                .unwrap_or_else(|| key_info.fingerprint.clone());
            writeln!(status_out, "[GNUPG:] BADSIG {} {uid}", key_info.fingerprint)?;
        }
        DecryptVerifyOutcome::UnknownKey { issuer_ids } => {
            // GnuPG emits NO_PUBKEY with a 16-char key ID. Pick the
            // shortest issuer-id form available (16-char preferred,
            // else suffix of a 40-char fingerprint).
            let key_id = issuer_ids
                .iter()
                .find(|id| id.len() == 16)
                .cloned()
                .or_else(|| {
                    issuer_ids
                        .iter()
                        .find(|id| id.len() == 40)
                        .map(|fp| fp[24..].to_string())
                })
                .unwrap_or_default();
            writeln!(status_out, "[GNUPG:] NO_PUBKEY {key_id}")?;
        }
    }
    Ok(())
}

/// Inspect an encrypted file and print which key IDs it is encrypted for.
///
/// Produces output similar to `gpg --decrypt --list-only --keyid-format long`.
/// Used by `pass` to detect whether reencryption is needed.
pub fn decrypt_list_only(input: &Path, _keystore_path: Option<&PathBuf>) -> Result<()> {
    let ciphertext = read_ciphertext(input)?;
    let key_ids = ltd::recipients_of(&ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to inspect encrypted message")?;

    for kid in &key_ids {
        // pass parses: gpg: public key is ([A-F0-9]+)
        // (password-store.sh line 132, sed pattern)
        eprintln!("gpg: public key is {}", kid.to_uppercase());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libtumpa::{KeyInfo, UserIDInfo};

    /// Build a minimal `KeyInfo` for status-line tests. Real
    /// `parse_key_bytes` is heavy; we only exercise field-shaped output
    /// here so a hand-rolled struct is appropriate.
    fn key_info_with_uid(fpr: &str, uid: &str) -> KeyInfo {
        KeyInfo {
            fingerprint: fpr.to_string(),
            key_id: fpr[fpr.len().saturating_sub(16)..].to_string(),
            user_ids: vec![UserIDInfo {
                value: uid.to_string(),
                revoked: false,
                is_primary: true,
                revocation_time: None,
                certifications: Vec::new(),
            }],
            subkeys: Vec::new(),
            creation_time: chrono::Utc::now(),
            expiration_time: None,
            is_secret: true,
            is_revoked: false,
            can_primary_sign: true,
            revocation_time: None,
            key_version: wecanencrypt::KeyVersion::V4,
            primary_algorithm_detail: wecanencrypt::KeyAlgorithm::Ed25519,
        }
    }

    #[test]
    fn unsigned_emits_no_signature_line() {
        let mut buf: Vec<u8> = Vec::new();
        emit_signature_status(&mut buf, &DecryptVerifyOutcome::Unsigned).unwrap();
        assert!(buf.is_empty(), "got: {:?}", String::from_utf8_lossy(&buf));
    }

    #[test]
    fn good_emits_goodsig_with_fingerprint_and_uid() {
        let key_info = key_info_with_uid(
            "F70FFB3049DD18E3421D89D022B2407D1311646C",
            "Alice <alice@example.com>",
        );
        let outcome = DecryptVerifyOutcome::Good {
            key_info,
            verifier_fingerprint: "B2D4FACE0123456789ABCDEF0123456789ABCDEF".to_string(),
        };
        let mut buf: Vec<u8> = Vec::new();
        emit_signature_status(&mut buf, &outcome).unwrap();
        let line = String::from_utf8(buf).unwrap();
        assert_eq!(
            line.trim_end(),
            "[GNUPG:] GOODSIG B2D4FACE0123456789ABCDEF0123456789ABCDEF Alice <alice@example.com>"
        );
    }

    #[test]
    fn bad_emits_badsig() {
        let key_info = key_info_with_uid(
            "F70FFB3049DD18E3421D89D022B2407D1311646C",
            "Alice <alice@example.com>",
        );
        let outcome = DecryptVerifyOutcome::Bad { key_info };
        let mut buf: Vec<u8> = Vec::new();
        emit_signature_status(&mut buf, &outcome).unwrap();
        let line = String::from_utf8(buf).unwrap();
        assert!(line.starts_with("[GNUPG:] BADSIG F70FFB3049DD18E3421D89D022B2407D1311646C"));
        assert!(line.contains("Alice <alice@example.com>"));
    }

    #[test]
    fn unknown_emits_no_pubkey_with_short_keyid() {
        let outcome = DecryptVerifyOutcome::UnknownKey {
            issuer_ids: vec!["1234567890ABCDEF".to_string()],
        };
        let mut buf: Vec<u8> = Vec::new();
        emit_signature_status(&mut buf, &outcome).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap().trim_end(),
            "[GNUPG:] NO_PUBKEY 1234567890ABCDEF"
        );
    }

    #[test]
    fn unknown_falls_back_to_fingerprint_suffix() {
        // No 16-char key id present, only a 40-char fingerprint — must
        // emit the trailing 16 chars (GnuPG long key ID convention).
        let outcome = DecryptVerifyOutcome::UnknownKey {
            issuer_ids: vec!["F70FFB3049DD18E3421D89D022B2407D1311646C".to_string()],
        };
        let mut buf: Vec<u8> = Vec::new();
        emit_signature_status(&mut buf, &outcome).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap().trim_end(),
            "[GNUPG:] NO_PUBKEY 22B2407D1311646C"
        );
    }

    /// UID with embedded newline / control characters must not break
    /// the line-based status protocol — sanitize_uid_for_status strips
    /// them. Regression guard for the `[GNUPG:] VALIDSIG` injection
    /// attack the libtumpa::verify module documents.
    ///
    /// The threat is a parser seeing a *separate* `[GNUPG:] VALIDSIG`
    /// line forged by the UID. After sanitization the malicious text
    /// stays on the same physical line as GOODSIG, so any line-based
    /// reader treats it as opaque UID content rather than a fresh
    /// status line. We assert exactly that property.
    #[test]
    fn good_strips_control_chars_in_uid() {
        let key_info = key_info_with_uid(
            "AAAA111111111111111111111111111111111111",
            "Evil <x@y>\n[GNUPG:] VALIDSIG forged",
        );
        let outcome = DecryptVerifyOutcome::Good {
            key_info,
            verifier_fingerprint: "AAAA111111111111111111111111111111111111".to_string(),
        };
        let mut buf: Vec<u8> = Vec::new();
        emit_signature_status(&mut buf, &outcome).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Exactly one trailing newline = exactly one logical status line.
        assert_eq!(out.matches('\n').count(), 1, "got: {out:?}");
        // The first (and only) line must start with GOODSIG, not VALIDSIG.
        assert!(out.starts_with("[GNUPG:] GOODSIG"));
        // No line break splits the embedded "[GNUPG:] VALIDSIG" away
        // from the GOODSIG prefix it's pinned to.
        for line in out.lines() {
            if line.contains("VALIDSIG") {
                assert!(
                    line.starts_with("[GNUPG:] GOODSIG"),
                    "VALIDSIG must remain on the GOODSIG line, not be promoted to its own line: {line}"
                );
            }
        }
    }
}
