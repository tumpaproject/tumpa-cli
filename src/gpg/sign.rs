use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::pinentry;
use crate::store;

/// Sign data from stdin and write detached signature to stdout.
///
/// Tries hardware OpenPGP cards first, falls back to software keys
/// from the tumpa keystore.
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
    store::ensure_key_usable_for_signing(&key_info)?;

    let signature = try_sign_on_card(&buffer, &key_data, &key_info, &mut err)
        .or_else(|card_err| {
            log::info!("Card signing failed ({}), trying software key", card_err);
            sign_with_software_key(&buffer, &key_data, &key_info, &mut err)
                .map_err(|sw_err| {
                    // If the software fallback also fails, include the card error
                    // so the user knows why the card path failed too
                    anyhow::anyhow!(
                        "Card signing failed: {}\nSoftware key fallback failed: {}",
                        card_err,
                        sw_err
                    )
                })
        })?;

    // Write signature to stdout
    out.write_all(signature.as_bytes())
        .context("Failed to write signature to stdout")?;

    // Git checks for this status line on stderr
    // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
    writeln!(err, "\n[GNUPG:] SIG_CREATED ")?;

    Ok(())
}

/// Try to sign using a connected OpenPGP card.
fn try_sign_on_card(
    data: &[u8],
    key_data: &[u8],
    key_info: &wecanencrypt::KeyInfo,
    err: &mut impl Write,
) -> Result<String> {
    // Check if any connected card has the signing key for this cert
    let matches = wecanencrypt::card::find_cards_for_key(key_data)
        .context("Failed to enumerate cards")?;

    // Find a card with a signing slot match
    for card_match in &matches {
        let has_signing = card_match
            .matching_slots
            .iter()
            .any(|s| matches!(s.slot, wecanencrypt::card::KeySlot::Signature));

        if has_signing {
            let card_ident = &card_match.card.ident;
            log::info!("Found card {} with signing key", card_ident);

            // Fetch card details for the pinentry prompt
            let card_info = wecanencrypt::card::get_card_details(Some(card_ident)).ok();

            let uid = primary_uid(key_info);

            let mut desc = format!("Please unlock the card\n\nNumber: {}", card_match.card.serial_number);
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

            let pin = pinentry::get_passphrase(&desc, "PIN", Some(&key_info.fingerprint))?;

            let signature = wecanencrypt::card::sign_bytes_detached_on_card(
                data,
                key_data,
                pin.as_bytes(),
            )
            .context("Card signing failed")?;

            writeln!(
                err,
                "tcli: Signed with card {} key {}",
                card_ident, key_info.fingerprint
            )?;

            return Ok(signature);
        }
    }

    anyhow::bail!("No card found with signing key for {}", key_info.fingerprint)
}

/// Sign using a software key from the tumpa keystore.
fn sign_with_software_key(
    data: &[u8],
    key_data: &[u8],
    key_info: &wecanencrypt::KeyInfo,
    err: &mut impl Write,
) -> Result<String> {
    if !key_info.is_secret {
        anyhow::bail!(
            "No secret key available for {}. Import a secret key into tumpa first.",
            key_info.fingerprint
        );
    }

    let desc = format!("Enter passphrase for key {}", primary_uid(key_info));

    let passphrase = pinentry::get_passphrase(&desc, "Passphrase", Some(&key_info.fingerprint))?;

    let signature = wecanencrypt::sign_bytes_detached(key_data, data, &passphrase)
        .context("Software key signing failed")?;

    writeln!(
        err,
        "tcli: Signed with software key {}",
        key_info.fingerprint
    )?;

    Ok(signature)
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
