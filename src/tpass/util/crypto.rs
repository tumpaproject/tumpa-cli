//! tpass crypto helpers.
//!
//! All crypto operations delegate to libtumpa; this module owns the
//! file I/O, pinentry prompts, and the pass-shape glue (signed `.gpg-id`,
//! reencrypt comparison key-id list).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libtumpa::decrypt as ltd;
use libtumpa::{Passphrase, Pin};
use zeroize::Zeroizing;

use tumpa_cli::{pinentry, store};

/// Encrypt plaintext bytes to multiple recipients, writing to output file.
/// Recipients are GPG IDs from .gpg-id files.
pub fn encrypt_to_recipients(
    plaintext: &[u8],
    recipient_ids: &[String],
    output: &Path,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let recip_refs: Vec<&str> = recipient_ids.iter().map(|s| s.as_str()).collect();

    let ciphertext =
        libtumpa::encrypt::encrypt_to_recipients(&keystore, &recip_refs, plaintext, false)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .context("Encryption failed")?;

    std::fs::write(output, &ciphertext)
        .context(format!("Failed to write output file {:?}", output))?;
    Ok(())
}

/// Decrypt a .gpg file, returning plaintext bytes.
/// Auto-detects which secret key to use, card-first.
pub fn decrypt_file(
    passfile: &Path,
    keystore_path: Option<&PathBuf>,
) -> Result<Zeroizing<Vec<u8>>> {
    let keystore = store::open_keystore(keystore_path)?;
    let ciphertext =
        std::fs::read(passfile).context(format!("Failed to read encrypted file {:?}", passfile))?;

    let key_ids = ltd::recipients_of(&ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to inspect encrypted message")?;
    if key_ids.is_empty() {
        anyhow::bail!("Cannot determine recipient key IDs from encrypted message");
    }

    match try_decrypt_on_card(&ciphertext, &keystore) {
        Ok(pt) => Ok(pt),
        Err(card_err) => {
            log::info!(
                "Card decryption not available ({}), trying software key",
                card_err
            );
            decrypt_with_software(&ciphertext, &keystore, &key_ids, &card_err)
        }
    }
}

/// Card-side decrypt using libtumpa primitives, with pinentry here.
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

    match ltd::decrypt_on_card(&card.key_data, ciphertext, &pin_obj) {
        Ok(z) => {
            pinentry::cache_passphrase(&card.key_info.fingerprint, &pin);
            Ok(Zeroizing::new(z.to_vec()))
        }
        Err(e) => {
            pinentry::clear_cached_passphrase(&card.key_info.fingerprint);
            Err(anyhow::anyhow!("{e}")).context("Card decryption failed")
        }
    }
}

/// Software-side decrypt using libtumpa primitives, with pinentry here.
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

/// Get key IDs a file is encrypted to (for reencrypt comparison).
pub fn file_encrypted_for(passfile: &Path) -> Result<Vec<String>> {
    let ciphertext =
        std::fs::read(passfile).context(format!("Failed to read encrypted file {:?}", passfile))?;
    let key_ids = ltd::recipients_of(&ciphertext)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to inspect encrypted message")?;
    Ok(key_ids.iter().map(|k| k.to_uppercase()).collect())
}

/// Get encryption subkey key IDs for a list of recipient GPG IDs.
/// This matches what pass does: resolve recipients via --list-keys --with-colons
/// and grep for sub:...:e: lines.
pub fn recipient_encryption_key_ids(
    recipient_ids: &[String],
    keystore_path: Option<&PathBuf>,
) -> Result<Vec<String>> {
    let keystore = store::open_keystore(keystore_path)?;
    let mut key_ids = Vec::new();

    for recipient_id in recipient_ids {
        let (_key_data, key_info) = store::resolve_signer(&keystore, recipient_id)?;
        store::ensure_key_usable_for_encryption(&key_info)?;

        for sk in &key_info.subkeys {
            if sk.is_revoked || libtumpa::store::subkey_is_expired(sk) {
                continue;
            }
            if matches!(sk.key_type, wecanencrypt::KeyType::Encryption) {
                key_ids.push(sk.key_id.to_uppercase());
            }
        }
    }

    key_ids.sort();
    key_ids.dedup();
    Ok(key_ids)
}

/// Sign a file with detached signature (for .gpg-id signing).
pub fn sign_file_detached(
    file: &Path,
    signer_ids: &[String],
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let data = std::fs::read(file).context(format!("Failed to read {:?}", file))?;

    let sig_file = file.with_extension(
        file.extension()
            .map(|e| format!("{}.sig", e.to_string_lossy()))
            .unwrap_or_else(|| "sig".to_string()),
    );

    for signer_id in signer_ids {
        let Ok((key_data, key_info)) = store::resolve_signer(&keystore, signer_id) else {
            continue;
        };
        if libtumpa::store::ensure_key_usable_for_signing(&key_info).is_err() {
            continue;
        }
        if !key_info.is_secret {
            continue;
        }

        let desc = format!(
            "Enter passphrase to sign with key {}",
            key_info
                .user_ids
                .first()
                .map(|u| u.value.as_str())
                .unwrap_or(&key_info.fingerprint)
        );
        // `Passphrase` is `Zeroizing<String>`; pass it directly to
        // libtumpa to avoid an extra plaintext `to_string()` copy.
        let passphrase: Passphrase =
            pinentry::get_passphrase(&desc, "Passphrase", Some(&key_info.fingerprint))?;

        let signature = match libtumpa::sign::sign_detached_with_key(&key_data, &data, &passphrase)
        {
            Ok(sig) => {
                pinentry::cache_passphrase(&key_info.fingerprint, &passphrase);
                sig
            }
            Err(e) => {
                pinentry::clear_cached_passphrase(&key_info.fingerprint);
                return Err(anyhow::anyhow!("{e}")).context("Signing failed");
            }
        };

        std::fs::write(&sig_file, signature.as_bytes())
            .context(format!("Failed to write signature file {:?}", sig_file))?;
        return Ok(());
    }

    anyhow::bail!("No signing key available from provided key IDs")
}

/// Verify a detached signature against signing keys.
pub fn verify_file_signature(
    file: &Path,
    signing_keys: &[String],
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let sig_file = file.with_extension(
        file.extension()
            .map(|e| format!("{}.sig", e.to_string_lossy()))
            .unwrap_or_else(|| "sig".to_string()),
    );
    if !sig_file.exists() {
        anyhow::bail!("Signature for {:?} does not exist.", file);
    }

    let keystore = store::open_keystore(keystore_path)?;
    let data = std::fs::read(file)?;
    let sig_bytes = std::fs::read(&sig_file)?;

    // pass semantics: succeed if ANY of the configured signing keys verifies.
    // We verify per-key by importing each into a transient lookup keystore
    // is overkill; instead use libtumpa::verify_detached against the existing
    // store and accept Good outcomes whose verifier_fingerprint matches one of
    // the requested signers (40-char fp), or whose key_info.fingerprint or
    // any subkey fingerprint matches.
    let outcome = libtumpa::verify::verify_detached(&keystore, &data, &sig_bytes)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    use libtumpa::verify::VerifyOutcome;
    match outcome {
        VerifyOutcome::Good {
            key_info,
            verifier_fingerprint,
        } => {
            let verifier_upper = verifier_fingerprint.to_uppercase();
            let primary_upper = key_info.fingerprint.to_uppercase();
            let subkey_fps: Vec<String> = key_info
                .subkeys
                .iter()
                .map(|s| s.fingerprint.to_uppercase())
                .collect();
            let key_ids: Vec<String> = std::iter::once(key_info.key_id.to_uppercase())
                .chain(key_info.subkeys.iter().map(|s| s.key_id.to_uppercase()))
                .collect();

            for want in signing_keys {
                let w = want.trim_start_matches("0x").to_uppercase();
                if w == verifier_upper
                    || w == primary_upper
                    || subkey_fps.contains(&w)
                    || key_ids.contains(&w)
                {
                    return Ok(());
                }
            }
            anyhow::bail!(
                "Signature for {:?} is valid but signer {} is not in allowed list.",
                file,
                primary_upper
            )
        }
        VerifyOutcome::Bad { .. } | VerifyOutcome::UnknownKey { .. } => {
            anyhow::bail!("Signature for {:?} is invalid.", file)
        }
    }
}
