//! GPG-shape encrypt: read input file/stdin, delegate the actual encryption
//! to libtumpa, write output to a file path. The recipient resolution +
//! `encrypt_bytes_to_multiple` call lives in `libtumpa::encrypt`.
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

    let recip_refs: Vec<&str> = recipients.iter().map(|s| s.as_str()).collect();
    let ciphertext = libtumpa::encrypt::encrypt_to_recipients(&keystore, &recip_refs, &plaintext, armor)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Encryption failed")?;

    std::fs::write(output, &ciphertext)
        .context(format!("Failed to write output file {:?}", output))?;

    Ok(())
}
