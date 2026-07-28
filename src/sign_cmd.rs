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
//! Card-first dispatch for detached and cleartext signing is handled by
//! `libtumpa::sign`; a matching card is tried before the software-key
//! fallback.

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
use crate::gpg::sign::{
    prompt_card_pin, prompt_key_passphrase, verify_card_pin, verify_software_passphrase,
    CardPinError,
};
use crate::pinentry;
use crate::store;

/// Shared pinentry / pre-verify / secret-capture logic for `cmd_sign`
/// and `cmd_sign_inline`, so the card-fallback rules (rejected PIN
/// blocks fallback, transport errors do not) cannot diverge between
/// the two commands.
struct SignSecrets {
    /// Card that was asked for a PIN, for the post-sign messages.
    card_ident_used: RefCell<Option<String>>,
    /// Set when the card rejected the PIN; the KeyPassphrase arm then
    /// refuses the software-key fallback.
    card_pin_rejected: RefCell<Option<String>>,
    /// Secret from the latest callback call, cached only after the
    /// overall sign succeeds.
    last_secret: RefCell<Option<Zeroizing<String>>>,
}

impl SignSecrets {
    fn new() -> Self {
        Self {
            card_ident_used: RefCell::new(None),
            card_pin_rejected: RefCell::new(None),
            last_secret: RefCell::new(None),
        }
    }

    fn handle(
        &self,
        key_data: &[u8],
        req: SecretRequest<'_>,
    ) -> std::result::Result<Secret, libtumpa::Error> {
        match req {
            SecretRequest::CardPin {
                card_ident,
                key_info,
            } => {
                *self.card_ident_used.borrow_mut() = Some(card_ident.to_string());
                let pin: Zeroizing<String> = prompt_card_pin(card_ident, key_info)
                    .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
                if let Err(e) = verify_card_pin(card_ident, &pin, &key_info.fingerprint) {
                    let msg = format!("{e}");
                    if matches!(e, CardPinError::Rejected(_)) {
                        // The card judged the PIN and spent a retry; do NOT
                        // let libtumpa silently fall back to the software key,
                        // or repeated runs would keep burning retries while
                        // appearing to succeed.
                        *self.card_pin_rejected.borrow_mut() = Some(msg.clone());
                    }
                    // CardPinError::Other (I/O, card pulled, applet error):
                    // the PIN was never evaluated, so software-key fallback
                    // is safe -- libtumpa will request the passphrase next.
                    return Err(libtumpa::Error::Sign(msg));
                }
                let pin_bytes: Pin = Zeroizing::new(pin.as_bytes().to_vec());
                *self.last_secret.borrow_mut() = Some(pin);
                Ok(Secret::Pin(pin_bytes))
            }
            SecretRequest::KeyPassphrase { key_info } => {
                if let Some(msg) = self.card_pin_rejected.borrow().as_ref() {
                    return Err(libtumpa::Error::Sign(format!(
                        "card PIN was rejected; refusing software-key fallback ({msg})"
                    )));
                }
                let pass: Passphrase = prompt_key_passphrase(key_info)
                    .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
                verify_software_passphrase(key_data, &pass, &key_info.fingerprint)
                    .map_err(|e| libtumpa::Error::Sign(format!("{e}")))?;
                *self.last_secret.borrow_mut() = Some(pass.clone());
                Ok(Secret::Passphrase(pass))
            }
        }
    }
}

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

    let secrets = SignSecrets::new();

    let result = libtumpa_sign_detached(&key_data, &key_info, &data, |req| {
        secrets.handle(&key_data, req)
    });

    let (armored_signature, backend) = match result {
        Ok(ok) => {
            if let Some(secret) = secrets.last_secret.borrow().as_ref() {
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
            let ident = secrets
                .card_ident_used
                .borrow()
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string());
            eprintln!(
                "tcli: Signed with card {} key {}",
                ident, key_info.fingerprint
            );
        }
        SignBackend::Software => {
            if let Some(ident) = secrets.card_ident_used.borrow().as_ref() {
                eprintln!(
                    "tcli: warning: signing with card {ident} failed; \
                     fell back to the software key",
                );
            }
            eprintln!("tcli: Signed with software key {}", key_info.fingerprint);
        }
    }
    eprintln!("tcli: Wrote signature to {}", dest_label);
    Ok(())
}

/// `tcli --sign-inline FILE --with-key VALUE [-o OUT]`.
///
/// Card-first dispatch via `libtumpa::sign::sign_cleartext`: a connected
/// card is tried before falling back to a software secret key.
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

    let secrets = SignSecrets::new();

    let result = libtumpa_sign_cleartext(&key_data, &key_info, &data, |req| {
        secrets.handle(&key_data, req)
    });

    let (signed, backend) = match result {
        Ok((bytes, backend)) => {
            if let Some(secret) = secrets.last_secret.borrow().as_ref() {
                match backend_secret_kind(&backend) {
                    SecretKind::Pin => pinentry::cache_pin(&key_info.fingerprint, secret),
                    SecretKind::Passphrase => {
                        pinentry::cache_passphrase(&key_info.fingerprint, secret)
                    }
                }
            }
            (bytes, backend)
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
    match backend {
        SignBackend::Card => {
            let ident = secrets
                .card_ident_used
                .borrow()
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string());
            eprintln!(
                "tcli: Signed inline with card {} key {}",
                ident, key_info.fingerprint
            );
        }
        SignBackend::Software => {
            if let Some(ident) = secrets.card_ident_used.borrow().as_ref() {
                eprintln!(
                    "tcli: warning: signing with card {ident} failed; \
                     fell back to the software key",
                );
            }
            eprintln!(
                "tcli: Signed inline with software key {}",
                key_info.fingerprint
            );
        }
    }
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
