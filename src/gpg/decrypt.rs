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
        std::fs::read(input)
            .with_context(|| format!("Failed to read encrypted file {:?}", input))
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
            log::info!("Card decryption not available ({}), trying software key", card_err);
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
    let passphrase =
        pinentry::get_passphrase(&desc, "Passphrase", Some(&key_info.fingerprint))?;
    let pass = Passphrase::new(passphrase.to_string());

    match ltd::decrypt_with_key(&key_data, ciphertext, &pass) {
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
