use std::cell::RefCell;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use zeroize::Zeroizing;

use libtumpa::sign::{
    sign_detached as libtumpa_sign_detached, Secret, SecretRequest, SignBackend,
};
use libtumpa::{Passphrase, Pin};

use crate::pinentry;
use crate::store;

/// Sign data from stdin and write detached signature to stdout.
///
/// Delegates the card-first / software-fallback dispatch to
/// `libtumpa::sign::sign_detached`. Pinentry / passphrase / PIN acquisition
/// stays here; libtumpa never prompts.
pub fn sign(
    mut data: impl Read,
    mut out: impl Write,
    mut err: impl Write,
    signer_id: &str,
    _armor: bool,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    log::info!("sign called for signer_id: {}", signer_id);

    // Read all data from stdin
    let mut buffer = Vec::new();
    data.read_to_end(&mut buffer)
        .context("Failed to read data from stdin")?;

    // Open keystore and resolve the signer key
    let keystore = store::open_keystore(keystore_path)?;
    let (key_data, key_info) = store::resolve_signer(&keystore, signer_id)?;
    // libtumpa::sign_detached also calls ensure_key_usable_for_signing, but
    // we keep this early to surface the same error message git users have
    // seen historically.
    store::ensure_key_usable_for_signing(&key_info)?;

    // Track which card was used so we can emit the historical
    // `tcli: Signed with card <ident> ...` message after libtumpa returns.
    let card_ident_used: RefCell<Option<String>> = RefCell::new(None);

    // Capture the secret value produced by the latest closure call so
    // we can write it into the agent cache only after libtumpa
    // confirms the sign succeeded. libtumpa may call the closure twice
    // (CardPin then KeyPassphrase fallback); the final value is the
    // one that actually drove the successful op. The secret stays in
    // `Zeroizing<String>` end-to-end so transient copies are wiped on
    // drop.
    let last_secret: RefCell<Option<Zeroizing<String>>> = RefCell::new(None);

    let result = libtumpa_sign_detached(&key_data, &key_info, &buffer, |req| match req {
        SecretRequest::CardPin {
            card_ident,
            key_info,
        } => {
            *card_ident_used.borrow_mut() = Some(card_ident.to_string());
            let pin: Zeroizing<String> = prompt_card_pin(card_ident, key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            // Pin is `Zeroizing<Vec<u8>>`; the source bytes get copied
            // into a zeroizing Vec, then `pin` (the `Zeroizing<String>`)
            // moves into `last_secret`.
            let pin_bytes: Pin = Zeroizing::new(pin.as_bytes().to_vec());
            *last_secret.borrow_mut() = Some(pin);
            Ok(Secret::Pin(pin_bytes))
        }
        SecretRequest::KeyPassphrase { key_info } => {
            let pass: Passphrase = prompt_key_passphrase(key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            // `Passphrase` is `Zeroizing<String>`; cloning produces
            // another zeroizing copy (no plaintext leak).
            *last_secret.borrow_mut() = Some(pass.clone());
            Ok(Secret::Passphrase(pass))
        }
    });

    let (signature, backend) = match result {
        Ok(ok) => {
            if let Some(secret) = last_secret.borrow().as_ref() {
                pinentry::cache_passphrase(&key_info.fingerprint, secret);
            }
            ok
        }
        Err(e) => {
            pinentry::clear_cached_passphrase(&key_info.fingerprint);
            return Err(anyhow!("{e}"));
        }
    };

    match backend {
        SignBackend::Card => {
            let ident = card_ident_used
                .borrow()
                .clone()
                .unwrap_or_else(|| "<unknown>".to_string());
            writeln!(
                err,
                "tcli: Signed with card {} key {}",
                ident, key_info.fingerprint
            )?;
        }
        SignBackend::Software => {
            writeln!(
                err,
                "tcli: Signed with software key {}",
                key_info.fingerprint
            )?;
        }
    }

    // Write signature to stdout
    out.write_all(signature.as_bytes())
        .context("Failed to write signature to stdout")?;

    // Git checks for this status line on stderr
    // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
    writeln!(err, "\n[GNUPG:] SIG_CREATED ")?;

    Ok(())
}

/// Prompt the user for the card PIN via pinentry, including card-status
/// context (cardholder, signature counter) when available.
///
/// Returns `Zeroizing<String>` so the secret is wiped from memory when
/// the value is dropped — never converted to a plain `String`.
fn prompt_card_pin(
    card_ident: &str,
    key_info: &wecanencrypt::KeyInfo,
) -> Result<Zeroizing<String>> {
    let card_info = wecanencrypt::card::get_card_details(Some(card_ident)).ok();
    let uid = primary_uid(key_info);

    // Card serial: derive from ident, fall back to ident itself.
    let serial = card_ident.split(':').nth(1).unwrap_or(card_ident);

    let mut desc = format!("Please unlock the card\n\nNumber: {}", serial);
    if let Some(ref info) = card_info {
        if let Some(ref raw) = info.cardholder_name {
            let name = pinentry::format_cardholder_name(raw);
            if !name.is_empty() {
                desc.push_str(&format!("\nHolder: {}", name));
            }
        }
        desc.push_str(&format!("\nCounter: {}", info.signature_counter));
    }
    desc.push_str(&format!("\n\nSigning as: {}", uid));

    pinentry::get_passphrase(&desc, "PIN", Some(&key_info.fingerprint))
}

/// Prompt the user for the secret-key passphrase via pinentry.
///
/// Returns `Zeroizing<String>` so the secret is wiped from memory when
/// the value is dropped — never converted to a plain `String`.
fn prompt_key_passphrase(key_info: &wecanencrypt::KeyInfo) -> Result<Zeroizing<String>> {
    let desc = format!("Enter passphrase for key {}", primary_uid(key_info));
    pinentry::get_passphrase(&desc, "Passphrase", Some(&key_info.fingerprint))
}

/// Get the primary UID string from a certificate, falling back to the first
/// UID or the fingerprint.
///
/// Prefers the UID marked `is_primary` (RFC 9580 primary UID flag), then
/// the first non-revoked UID, then the fingerprint.
fn primary_uid(key_info: &wecanencrypt::KeyInfo) -> &str {
    key_info
        .user_ids
        .iter()
        .find(|u| u.is_primary && !u.revoked)
        .or_else(|| key_info.user_ids.iter().find(|u| !u.revoked))
        .map(|u| u.value.as_str())
        .unwrap_or(&key_info.fingerprint)
}
