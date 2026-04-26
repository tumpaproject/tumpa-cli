//! `tcli --sign` and `tcli --sign-inline` implementations.
//!
//! Human-shape sign commands. The GPG-shape sign used by `tclig` lives
//! in `gpg::sign` and stays unchanged.
//!
//! ## Output rules
//!
//! - `--sign FILE`: default output is `<FILE>.asc` (ASCII armored).
//!   `--binary` switches the default to `<FILE>.sig` (binary).
//! - `--sign-inline FILE`: default output is `<FILE>.asc` (cleartext
//!   `-----BEGIN PGP SIGNED MESSAGE-----` form).
//! - `-o`/`--output` overrides the destination. `-` writes to stdout.
//! - `FILE = -` reads from stdin (caller must also pass `-o`).
//!
//! Card-first dispatch (for detached) is handled by `libtumpa::sign`.
//! Cleartext signing is software-only — card-only keys are rejected.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;

use libtumpa::sign::{
    dearmor_detached_signature, sign_cleartext as libtumpa_sign_cleartext,
    sign_detached as libtumpa_sign_detached, Secret, SecretRequest, SignBackend,
};
use libtumpa::{Passphrase, Pin};

use crate::cli::is_stdio;
use crate::gpg::sign::{prompt_card_pin, prompt_key_passphrase};
use crate::pinentry;
use crate::store;

/// `tcli --sign FILE --with-key VALUE [--binary] [-o OUT]`.
pub fn cmd_sign(
    input: &Path,
    with_key: &str,
    binary: bool,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let data = read_input(input)?;
    let keystore = store::open_keystore(keystore_path)?;
    let (key_data, key_info) = store::resolve_signer(&keystore, with_key)?;
    store::ensure_key_usable_for_signing(&key_info)?;

    let card_ident_used: RefCell<Option<String>> = RefCell::new(None);
    let last_secret: RefCell<Option<Zeroizing<String>>> = RefCell::new(None);

    let result = libtumpa_sign_detached(&key_data, &key_info, &data, |req| match req {
        SecretRequest::CardPin {
            card_ident,
            key_info,
        } => {
            *card_ident_used.borrow_mut() = Some(card_ident.to_string());
            let pin: Zeroizing<String> = prompt_card_pin(card_ident, key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            let pin_bytes: Pin = Zeroizing::new(pin.as_bytes().to_vec());
            *last_secret.borrow_mut() = Some(pin);
            Ok(Secret::Pin(pin_bytes))
        }
        SecretRequest::KeyPassphrase { key_info } => {
            let pass: Passphrase = prompt_key_passphrase(key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            *last_secret.borrow_mut() = Some(pass.clone());
            Ok(Secret::Passphrase(pass))
        }
    });

    let (armored_signature, backend) = match result {
        Ok(ok) => {
            if let Some(secret) = last_secret.borrow().as_ref() {
                match backend_secret_kind(&ok.1) {
                    SecretKind::Pin => pinentry::cache_pin(&key_info.fingerprint, secret),
                    SecretKind::Passphrase => {
                        pinentry::cache_passphrase(&key_info.fingerprint, secret)
                    }
                }
            }
            ok
        }
        Err(e) => {
            pinentry::clear_all_cached_secrets(&key_info.fingerprint);
            return Err(anyhow!("{e}"));
        }
    };

    let payload: Vec<u8> = if binary {
        dearmor_detached_signature(armored_signature.as_bytes()).map_err(|e| anyhow!("{e}"))?
    } else {
        armored_signature.into_bytes()
    };

    let dest = sign_destination(input, output, binary, /* inline */ false)?;
    let dest_label = write_payload(&dest, &payload)?;

    match backend {
        SignBackend::Card => {
            let ident = card_ident_used
                .borrow()
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string());
            eprintln!(
                "tcli: Signed with card {} key {}",
                ident, key_info.fingerprint
            );
        }
        SignBackend::Software => {
            eprintln!("tcli: Signed with software key {}", key_info.fingerprint);
        }
    }
    eprintln!("tcli: Wrote signature to {}", dest_label);
    Ok(())
}

/// `tcli --sign-inline FILE --with-key VALUE [-o OUT]`. Software-only.
pub fn cmd_sign_inline(
    input: &Path,
    with_key: &str,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let data = read_input(input)?;
    let keystore = store::open_keystore(keystore_path)?;
    let (key_data, key_info) = store::resolve_signer(&keystore, with_key)?;
    store::ensure_key_usable_for_signing(&key_info)?;

    let last_secret: RefCell<Option<Zeroizing<String>>> = RefCell::new(None);

    let result = libtumpa_sign_cleartext(&key_data, &key_info, &data, |req| match req {
        SecretRequest::KeyPassphrase { key_info } => {
            let pass: Passphrase = prompt_key_passphrase(key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            *last_secret.borrow_mut() = Some(pass.clone());
            Ok(Secret::Passphrase(pass))
        }
        SecretRequest::CardPin { .. } => Err(libtumpa::Error::Sign(
            "cleartext (inline) signing is software-only and never requests a card PIN".into(),
        )),
    });

    let signed = match result {
        Ok(bytes) => {
            if let Some(secret) = last_secret.borrow().as_ref() {
                pinentry::cache_passphrase(&key_info.fingerprint, secret);
            }
            bytes
        }
        Err(e) => {
            pinentry::clear_all_cached_secrets(&key_info.fingerprint);
            return Err(anyhow!("{e}"));
        }
    };

    let dest = sign_destination(
        input, output, /* binary */ false, /* inline */ true,
    )?;
    let dest_label = write_payload(&dest, &signed)?;
    eprintln!(
        "tcli: Signed inline with software key {}",
        key_info.fingerprint
    );
    eprintln!("tcli: Wrote signed message to {}", dest_label);
    Ok(())
}

/// Resolve the output destination.
///
/// Returns one of:
/// - `Destination::Stdout` if `-o -` (or absent and input is stdin — but
///   that case is rejected at parse time so we only see the `-o -` form).
/// - `Destination::Path(p)` otherwise. If `output` is `None`, derives
///   `<input>.<ext>` based on `binary`/`inline`.
fn sign_destination(
    input: &Path,
    output: Option<&PathBuf>,
    binary: bool,
    inline: bool,
) -> Result<Destination> {
    if let Some(out) = output {
        if is_stdio(out) {
            return Ok(Destination::Stdout);
        }
        return Ok(Destination::Path(out.clone()));
    }

    if is_stdio(input) {
        // CLI parser should already have rejected this, but keep a hard
        // safety net.
        bail!("reading from stdin requires -o/--output");
    }

    // Derive sibling default. Inline always = .asc. Detached: .asc unless --binary.
    let ext = if inline || !binary { "asc" } else { "sig" };
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

enum SecretKind {
    Pin,
    Passphrase,
}

fn backend_secret_kind(backend: &SignBackend) -> SecretKind {
    match backend {
        SignBackend::Card => SecretKind::Pin,
        SignBackend::Software => SecretKind::Passphrase,
    }
}
