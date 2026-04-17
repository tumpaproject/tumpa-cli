use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::store;

/// Encrypt data to one or more recipients.
///
/// Reads plaintext from `input` (file path or stdin if None), encrypts
/// to all recipients, and writes ciphertext to `output`.
pub fn encrypt(
    input: Option<&PathBuf>,
    output: &PathBuf,
    recipients: &[String],
    armor: bool,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    // Resolve each recipient to key data
    let mut key_data_list: Vec<Vec<u8>> = Vec::new();
    for recipient_id in recipients {
        let (key_data, key_info) = store::resolve_signer(&keystore, recipient_id)?;
        store::ensure_key_usable_for_encryption(&key_info)?;
        key_data_list.push(key_data);
    }
    let key_refs: Vec<&[u8]> = key_data_list.iter().map(|c| c.as_slice()).collect();

    // Read plaintext
    let plaintext = match input {
        Some(path) => {
            std::fs::read(path).context(format!("Failed to read input file {:?}", path))?
        }
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("Failed to read from stdin")?;
            buf
        }
    };

    // Encrypt
    let ciphertext = wecanencrypt::encrypt_bytes_to_multiple(&key_refs, &plaintext, armor)
        .context("Encryption failed")?;

    // Write output
    std::fs::write(output, &ciphertext)
        .context(format!("Failed to write output file {:?}", output))?;

    Ok(())
}
