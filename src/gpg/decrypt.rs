use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
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
        std::fs::read(input).context(format!("Failed to read encrypted file {:?}", input))
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

    // Find which key IDs this message is encrypted for
    let key_ids = wecanencrypt::bytes_encrypted_for(&ciphertext)
        .context("Failed to inspect encrypted message")?;

    if key_ids.is_empty() {
        anyhow::bail!("Cannot determine recipient key IDs from encrypted message");
    }

    log::debug!("Message encrypted for key IDs: {:?}", key_ids);

    // Try card first, then software key (matches signing priority)
    let plaintext = match try_decrypt_on_card(&ciphertext, &key_ids, &keystore) {
        Ok(pt) => pt,
        Err(card_err) => {
            log::info!("Card decryption not available ({}), trying software key", card_err);

            // Find software secret key
            let mut key_data = None;
            let mut matched_info = None;

            for kid in &key_ids {
                if let Ok(Some(data)) = keystore.find_by_key_id(kid) {
                    let info = wecanencrypt::parse_key_bytes(&data, true)?;
                    if info.is_secret {
                        key_data = Some(data);
                        matched_info = Some(info);
                        break;
                    }
                }
            }

            let key_data = key_data.ok_or_else(|| {
                anyhow::anyhow!(
                    "Card decryption failed: {}\nNo software secret key found for key IDs: {}",
                    card_err,
                    key_ids.join(", ")
                )
            })?;
            let key_info = matched_info.unwrap();

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

            Zeroizing::new(
                wecanencrypt::decrypt_bytes(&key_data, &ciphertext, &passphrase)
                    .context("Decryption failed")?,
            )
        }
    };

    // Write output
    match output {
        Some(path) => {
            std::fs::write(path, plaintext.as_slice())
                .context(format!("Failed to write output file {:?}", path))?;
            // Restrict permissions on decrypted output file
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

/// Try to decrypt using a connected OpenPGP card.
fn try_decrypt_on_card(
    ciphertext: &[u8],
    key_ids: &[String],
    keystore: &wecanencrypt::KeyStore,
) -> Result<Zeroizing<Vec<u8>>> {
    let cards = wecanencrypt::card::list_all_cards()
        .context("Failed to enumerate cards")?;

    for card_summary in &cards {
        if let Ok(card_info) =
            wecanencrypt::card::get_card_details(Some(&card_summary.ident))
        {
            if let Some(ref enc_fp) = card_info.encryption_fingerprint {
                let enc_fp_upper = enc_fp.to_uppercase();
                let enc_kid = if enc_fp_upper.len() >= 16 {
                    &enc_fp_upper[enc_fp_upper.len() - 16..]
                } else {
                    &enc_fp_upper
                };

                let matches = key_ids.iter().any(|kid| kid.to_uppercase() == enc_kid);
                if !matches {
                    continue;
                }

                if let Ok(Some(key_data)) =
                    keystore.find_by_subkey_fingerprint(&enc_fp_upper)
                {
                    let key_info = wecanencrypt::parse_key_bytes(&key_data, false)?;
                    let uid = key_info
                        .user_ids
                        .first()
                        .map(|u| u.value.as_str())
                        .unwrap_or(&key_info.fingerprint);

                    let mut desc = format!("Please unlock the card\n\nNumber: {}", card_summary.serial_number);
                    if let Some(ref raw) = card_info.cardholder_name {
                        let name = pinentry::format_cardholder_name(raw);
                        if !name.is_empty() {
                            desc.push_str(&format!("\nHolder: {}", name));
                        }
                    }
                    desc.push_str(&format!("\n\nDecrypting for: {}", uid));

                    let pin = pinentry::get_passphrase(
                        &desc,
                        "PIN",
                        Some(&key_info.fingerprint),
                    )?;

                    let plaintext = wecanencrypt::card::decrypt_bytes_on_card(
                        ciphertext,
                        &key_data,
                        pin.as_bytes(),
                    )
                    .context("Card decryption failed")?;

                    return Ok(Zeroizing::new(plaintext));
                }
            }
        }
    }

    anyhow::bail!("No card with matching decryption key found")
}

/// Inspect an encrypted file and print which key IDs it is encrypted for.
///
/// Produces output similar to `gpg --decrypt --list-only --keyid-format long`.
/// Used by `pass` to detect whether reencryption is needed.
pub fn decrypt_list_only(
    input: &Path,
    _keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let ciphertext = read_ciphertext(input)?;

    let key_ids = wecanencrypt::bytes_encrypted_for(&ciphertext)
        .context("Failed to inspect encrypted message")?;

    for kid in &key_ids {
        // pass parses: gpg: public key is ([A-F0-9]+)
        // (password-store.sh line 132, sed pattern)
        eprintln!("gpg: public key is {}", kid.to_uppercase());
    }

    Ok(())
}
