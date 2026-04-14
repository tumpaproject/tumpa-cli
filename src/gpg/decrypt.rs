use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::pinentry;
use crate::store;

/// Decrypt a file.
///
/// Reads ciphertext from `input`, determines which secret key can decrypt
/// it, prompts for the passphrase, and writes plaintext to `output`
/// (or stdout if None).
pub fn decrypt(
    input: &PathBuf,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    let ciphertext =
        std::fs::read(input).context(format!("Failed to read encrypted file {:?}", input))?;

    // Find which key IDs this message is encrypted for
    let key_ids = wecanencrypt::bytes_encrypted_for(&ciphertext)
        .context("Failed to inspect encrypted message")?;

    if key_ids.is_empty() {
        anyhow::bail!("Cannot determine recipient key IDs from encrypted message");
    }

    log::debug!("Message encrypted for key IDs: {:?}", key_ids);

    // Find our secret key that can decrypt
    let mut cert_data = None;
    let mut matched_info = None;

    for kid in &key_ids {
        // Try to find this key ID in our keystore
        if let Ok(Some(data)) = keystore.find_by_key_id(kid) {
            let info = wecanencrypt::parse_cert_bytes(&data, true)?;
            if info.is_secret {
                cert_data = Some(data);
                matched_info = Some(info);
                break;
            }
        }
    }

    let cert_data = cert_data.ok_or_else(|| {
        anyhow::anyhow!("No secret key found for key IDs: {}", key_ids.join(", "))
    })?;
    let cert_info = matched_info.unwrap();

    // Get passphrase
    let desc = format!(
        "Enter passphrase to decrypt with key {}",
        cert_info
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or(&cert_info.fingerprint)
    );
    let passphrase = pinentry::get_passphrase(&desc, "Passphrase")?;

    // Decrypt (wrap in Zeroizing so plaintext is zeroed on drop)
    let plaintext = Zeroizing::new(
        wecanencrypt::decrypt_bytes(&cert_data, &ciphertext, &passphrase)
            .context("Decryption failed")?,
    );

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

/// Inspect an encrypted file and print which key IDs it is encrypted for.
///
/// Produces output similar to `gpg --decrypt --list-only --keyid-format long`.
/// Used by `pass` to detect whether reencryption is needed.
pub fn decrypt_list_only(input: &PathBuf, _keystore_path: Option<&PathBuf>) -> Result<()> {
    let ciphertext =
        std::fs::read(input).context(format!("Failed to read encrypted file {:?}", input))?;

    let key_ids = wecanencrypt::bytes_encrypted_for(&ciphertext)
        .context("Failed to inspect encrypted message")?;

    for kid in &key_ids {
        // pass parses: gpg: public key is ([A-F0-9]+)
        // (password-store.sh line 132, sed pattern)
        eprintln!("gpg: public key is {}", kid.to_uppercase());
    }

    Ok(())
}
