//! `tcli decrypt` implementation.
//!
//! Human-shape decrypt command. The GPG-shape decrypt used by `tclig`
//! lives in `gpg::decrypt` and stays unchanged; this module reuses its
//! `decrypt` core (recipient inspection, card-first then software
//! dispatch, pinentry prompts, output `0600` permissions) and adds a
//! human-facing status message.
//!
//! ## Output rules
//!
//! - `tcli decrypt FILE`: plaintext goes to stdout by default.
//! - `-o`/`--output` writes to a file (mode `0600` on Unix).
//! - `FILE = -` reads ciphertext from stdin.
//!
//! Card priority matches signing: a connected OpenPGP card holding the
//! decryption subkey is tried first, then a software secret key from the
//! keystore (with passphrase).

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::cli::is_stdio;
use crate::gpg;

/// `tcli decrypt FILE [-o OUT]`.
pub fn cmd_decrypt(
    input: &Path,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let output = decrypt_output_destination(output);

    // gpg::decrypt::decrypt owns the card-first / software-fallback
    // dispatch, the pinentry prompts, and the output write (including the
    // 0600 permission tightening when writing to a file).
    gpg::decrypt::decrypt(input, output, keystore_path)?;

    if let Some(path) = output {
        eprintln!("tcli: Wrote plaintext to {}", path.display());
    }
    Ok(())
}

fn decrypt_output_destination(output: Option<&PathBuf>) -> Option<&PathBuf> {
    output.filter(|path| !is_stdio(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dash_output_means_stdout() {
        let dash = PathBuf::from("-");
        assert!(decrypt_output_destination(Some(&dash)).is_none());
    }

    #[test]
    fn explicit_output_path_is_preserved() {
        let path = PathBuf::from("plain.txt");
        assert_eq!(decrypt_output_destination(Some(&path)), Some(&path));
    }
}
