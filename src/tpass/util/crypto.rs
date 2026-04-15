use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
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

    let mut cert_data_list: Vec<Vec<u8>> = Vec::new();
    for recipient_id in recipient_ids {
        let (cert_data, _info) = store::resolve_signer(&keystore, recipient_id)?;
        cert_data_list.push(cert_data);
    }
    let cert_refs: Vec<&[u8]> = cert_data_list.iter().map(|c| c.as_slice()).collect();

    let ciphertext = wecanencrypt::encrypt_bytes_to_multiple(&cert_refs, plaintext, false)
        .context("Encryption failed")?;

    std::fs::write(output, &ciphertext)
        .context(format!("Failed to write output file {:?}", output))?;

    Ok(())
}

/// Decrypt a .gpg file, returning plaintext bytes.
/// Auto-detects which secret key to use.
pub fn decrypt_file(
    passfile: &Path,
    keystore_path: Option<&PathBuf>,
) -> Result<Zeroizing<Vec<u8>>> {
    let keystore = store::open_keystore(keystore_path)?;

    let ciphertext = std::fs::read(passfile)
        .context(format!("Failed to read encrypted file {:?}", passfile))?;

    let key_ids = wecanencrypt::bytes_encrypted_for(&ciphertext)
        .context("Failed to inspect encrypted message")?;

    if key_ids.is_empty() {
        anyhow::bail!("Cannot determine recipient key IDs from encrypted message");
    }

    // Find our secret key
    let mut cert_data = None;
    let mut matched_info = None;

    for kid in &key_ids {
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
        anyhow::anyhow!(
            "No secret key found for key IDs: {}",
            key_ids.join(", ")
        )
    })?;
    let cert_info = matched_info.unwrap();

    let desc = format!(
        "Enter passphrase to decrypt with key {}",
        cert_info
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or(&cert_info.fingerprint)
    );
    let passphrase = pinentry::get_passphrase(&desc, "Passphrase")?;

    let plaintext = Zeroizing::new(
        wecanencrypt::decrypt_bytes(&cert_data, &ciphertext, &passphrase)
            .context("Decryption failed")?,
    );

    Ok(plaintext)
}

/// Get key IDs a file is encrypted to (for reencrypt comparison).
pub fn file_encrypted_for(passfile: &Path) -> Result<Vec<String>> {
    let ciphertext = std::fs::read(passfile)
        .context(format!("Failed to read encrypted file {:?}", passfile))?;

    let key_ids = wecanencrypt::bytes_encrypted_for(&ciphertext)
        .context("Failed to inspect encrypted message")?;

    // Return uppercased key IDs to match pass behavior
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
        let (cert_data, _info) = store::resolve_signer(&keystore, recipient_id)?;
        let cert_info = wecanencrypt::parse_cert_bytes(&cert_data, true)?;

        for sk in &cert_info.subkeys {
            if sk.is_revoked {
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

    // Sign with the first available key
    for signer_id in signer_ids {
        if let Ok((cert_data, cert_info)) = store::resolve_signer(&keystore, signer_id) {
            if !cert_info.is_secret {
                continue;
            }
            let desc = format!(
                "Enter passphrase to sign with key {}",
                cert_info
                    .user_ids
                    .first()
                    .map(|u| u.value.as_str())
                    .unwrap_or(&cert_info.fingerprint)
            );
            let passphrase = pinentry::get_passphrase(&desc, "Passphrase")?;

            let signature = wecanencrypt::sign_bytes_detached(&cert_data, &data, &passphrase)
                .context("Signing failed")?;

            std::fs::write(&sig_file, signature.as_bytes())
                .context(format!("Failed to write signature file {:?}", sig_file))?;
            return Ok(());
        }
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

    for key_id in signing_keys {
        if let Ok((cert_data, _info)) = store::resolve_signer(&keystore, key_id) {
            if matches!(
                wecanencrypt::verify_bytes_detached(&cert_data, &data, &sig_bytes),
                Ok(true)
            ) {
                return Ok(());
            }
        }
    }

    anyhow::bail!("Signature for {:?} is invalid.", file)
}
