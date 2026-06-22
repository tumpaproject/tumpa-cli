//! `tcli encrypt` implementation.
//!
//! Human-shape encrypt command. The GPG-shape encrypt used by `tclig`
//! lives in `gpg::encrypt`; this module reuses its
//! `prepare_recipients` + `encrypt_bytes_prepared` core (recipient
//! resolution and the card-first sign-then-encrypt dispatch) and adds
//! the human-facing destination handling and status messages. The
//! machine-shape `INV_RECP` status lines are suppressed here.
//!
//! ## Output rules
//!
//! - `tcli encrypt FILE -r REC`: default output is `<FILE>.asc`
//!   (ASCII armored). `--binary` switches the default to `<FILE>.gpg`
//!   (binary OpenPGP).
//! - `-o`/`--output` overrides the destination. `-` writes to stdout.
//! - `FILE = -` reads from stdin (caller must also pass `-o`).
//! - `--sign-with ID` produces a single sign-then-encrypt message; the
//!   signing leg is card-first (YubiKey/Nitrokey), software fallback.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::cli::is_stdio;
use crate::gpg;

/// `tcli encrypt FILE -r REC... [--sign-with ID] [--binary] [-o OUT]`.
pub fn cmd_encrypt(
    input: &Path,
    recipients: &[String],
    sign_with: Option<&str>,
    binary: bool,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let armor = !binary;

    // Validate the output destination first, then resolve recipients —
    // both before reading plaintext. So a stdin-without-`-o` mistake or
    // an unknown recipient fails fast, without consuming stdin or doing
    // any encryption work that would then be thrown away. INV_RECP status
    // lines are a machine protocol for `tclig`/PGP-MIME callers; the
    // human path discards them (sink) and relies on the returned error,
    // which names every unusable recipient. The card-first sign+encrypt
    // dispatch stays in the shared GPG encryption core.
    let dest = encrypt_destination(input, output, binary)?;
    let prepared = gpg::encrypt::prepare_recipients(recipients, keystore_path, std::io::sink())?;
    let plaintext = read_input(input)?;
    let ciphertext = gpg::encrypt::encrypt_bytes_prepared(&plaintext, &prepared, armor, sign_with)?;

    let dest_label = write_payload(&dest, &ciphertext)?;

    match sign_with {
        Some(id) => eprintln!(
            "tcli: Encrypted to {} recipient(s), signed with {}",
            recipients.len(),
            id
        ),
        None => eprintln!("tcli: Encrypted to {} recipient(s)", recipients.len()),
    }
    eprintln!("tcli: Wrote ciphertext to {}", dest_label);
    Ok(())
}

/// Resolve the output destination.
///
/// - `-o -` → stdout.
/// - `-o PATH` → that path.
/// - absent → sibling `<input>.asc` (armored) or `<input>.gpg` (binary).
///   Reading from stdin with no `-o` is rejected at parse time, but a
///   hard safety net stays here.
fn encrypt_destination(
    input: &Path,
    output: Option<&PathBuf>,
    binary: bool,
) -> Result<Destination> {
    if let Some(out) = output {
        if is_stdio(out) {
            return Ok(Destination::Stdout);
        }
        return Ok(Destination::Path(out.clone()));
    }

    if is_stdio(input) {
        bail!("reading from stdin requires -o/--output");
    }

    // Armored encrypted output uses `.asc`, binary uses `.gpg` — matching
    // GnuPG's own sibling-file conventions.
    let ext = if binary { "gpg" } else { "asc" };
    let mut path = input.to_path_buf();
    let new_name = match path.file_name() {
        Some(name) => {
            let mut n = name.to_os_string();
            n.push(".");
            n.push(ext);
            n
        }
        None => bail!("input path has no filename: {}", input.display()),
    };
    path.set_file_name(new_name);
    Ok(Destination::Path(path))
}

#[derive(Debug)]
enum Destination {
    Path(PathBuf),
    Stdout,
}

fn write_payload(dest: &Destination, bytes: &[u8]) -> Result<String> {
    match dest {
        Destination::Path(p) => {
            std::fs::write(p, bytes).with_context(|| format!("Failed to write {}", p.display()))?;
            Ok(p.display().to_string())
        }
        Destination::Stdout => {
            std::io::stdout()
                .write_all(bytes)
                .context("Failed to write to stdout")?;
            Ok("stdout".to_string())
        }
    }
}

fn read_input(input: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    if is_stdio(input) {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read from stdin")?;
        Ok(buf)
    } else {
        std::fs::read(input).with_context(|| format!("Failed to read {}", input.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wecanencrypt::create_key_simple;

    /// Default sibling path for armored output is `<input>.asc`.
    #[test]
    fn default_destination_armored_is_asc() {
        let dest = encrypt_destination(Path::new("msg.txt"), None, false).unwrap();
        match dest {
            Destination::Path(p) => assert_eq!(p, PathBuf::from("msg.txt.asc")),
            Destination::Stdout => panic!("expected a file path, got stdout"),
        }
    }

    /// Default sibling path for binary output is `<input>.gpg`.
    #[test]
    fn default_destination_binary_is_gpg() {
        let dest = encrypt_destination(Path::new("msg.txt"), None, true).unwrap();
        match dest {
            Destination::Path(p) => assert_eq!(p, PathBuf::from("msg.txt.gpg")),
            Destination::Stdout => panic!("expected a file path, got stdout"),
        }
    }

    /// `-o -` selects stdout regardless of armor.
    #[test]
    fn dash_output_selects_stdout() {
        let dash = PathBuf::from("-");
        let dest = encrypt_destination(Path::new("msg.txt"), Some(&dash), false).unwrap();
        assert!(matches!(dest, Destination::Stdout));
    }

    /// Explicit `-o PATH` overrides the sibling default.
    #[test]
    fn explicit_output_overrides_default() {
        let out = PathBuf::from("/tmp/ct.bin");
        let dest = encrypt_destination(Path::new("msg.txt"), Some(&out), true).unwrap();
        match dest {
            Destination::Path(p) => assert_eq!(p, out),
            Destination::Stdout => panic!("expected a file path, got stdout"),
        }
    }

    /// Reading from stdin with no `-o` is a hard error here (the parser
    /// also rejects it, but the safety net must hold).
    #[test]
    fn stdin_without_output_errors() {
        let err = encrypt_destination(Path::new("-"), None, false).unwrap_err();
        assert!(err.to_string().contains("requires -o/--output"));
    }

    /// End-to-end: encrypt a file to a known recipient, then decrypt it
    /// back with that recipient's software secret key. Pins the
    /// human-facing `cmd_encrypt` happy path through the shared
    /// `prepare_recipients` + `encrypt_bytes_prepared` core to a real
    /// round-trip.
    #[test]
    fn encrypt_round_trips_to_recipient() {
        let dir = TempDir::new().unwrap();
        let ks_path = dir.path().join("keys.db");
        let pt_path = dir.path().join("plain.txt");
        let ct_path = dir.path().join("plain.txt.asc");
        std::fs::write(&pt_path, b"round trip me").unwrap();

        // Recipient (Bob) with a secret so we can decrypt to verify.
        let bob = create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
        let keystore = wecanencrypt::KeyStore::open(&ks_path).unwrap();
        keystore.import_key(&bob.secret_key).unwrap();
        drop(keystore);

        cmd_encrypt(
            &pt_path,
            &["bob@example.com".to_string()],
            None,
            false, // armored
            None,  // default sibling path => plain.txt.asc
            Some(&ks_path),
        )
        .unwrap();

        assert!(ct_path.exists(), "ciphertext sibling file must be written");
        let ciphertext = std::fs::read(&ct_path).unwrap();
        // Armored output starts with the OpenPGP message header.
        assert!(
            ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"),
            "default output should be ASCII-armored"
        );

        let passphrase: libtumpa::Passphrase = zeroize::Zeroizing::new("pw".to_string());
        let plaintext =
            libtumpa::decrypt::decrypt_with_key(&bob.secret_key, &ciphertext, &passphrase)
                .expect("decrypt should succeed");
        assert_eq!(&*plaintext, b"round trip me");
    }

    /// Unknown recipient aborts and writes no output file.
    #[test]
    fn unknown_recipient_writes_no_output() {
        let dir = TempDir::new().unwrap();
        let ks_path = dir.path().join("keys.db");
        let pt_path = dir.path().join("plain.txt");
        let ct_path = dir.path().join("plain.txt.asc");
        std::fs::write(&pt_path, b"secret").unwrap();
        // Empty keystore so the recipient cannot resolve.
        wecanencrypt::KeyStore::open(&ks_path).unwrap();

        let err = cmd_encrypt(
            &pt_path,
            &["nobody@example.com".to_string()],
            None,
            false,
            None,
            Some(&ks_path),
        )
        .unwrap_err();

        assert!(err.to_string().contains("nobody@example.com"));
        assert!(
            !ct_path.exists(),
            "no output should be written when a recipient is invalid"
        );
    }

    /// Invalid recipients are reported before reading plaintext, so a
    /// bad recipient on stdin cannot hang waiting for input.
    #[test]
    fn unknown_recipient_fails_before_reading_input() {
        let dir = TempDir::new().unwrap();
        let ks_path = dir.path().join("keys.db");
        let missing_input = dir.path().join("missing.txt");
        wecanencrypt::KeyStore::open(&ks_path).unwrap();

        let err = cmd_encrypt(
            &missing_input,
            &["nobody@example.com".to_string()],
            None,
            false,
            None,
            Some(&ks_path),
        )
        .unwrap_err();

        let err = err.to_string();
        assert!(err.contains("nobody@example.com"), "got: {err}");
        assert!(!err.contains("Failed to read"), "got: {err}");
    }
}
