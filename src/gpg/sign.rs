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
    let (cert_data, cert_info) = store::resolve_signer(&keystore, signer_id)?;
    store::ensure_cert_usable_for_signing(&cert_info)?;

    let signature = try_sign_on_card(&buffer, &cert_data, &cert_info, &mut err)
        .or_else(|card_err| {
            log::info!("Card signing failed ({}), trying software key", card_err);
            sign_with_software_key(&buffer, &cert_data, &cert_info, &mut err)
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
    cert_data: &[u8],
    cert_info: &wecanencrypt::CertificateInfo,
    err: &mut impl Write,
) -> Result<String> {
    // Check if any connected card has the signing key for this cert
    let matches = wecanencrypt::card::find_cards_for_key(cert_data)
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

            let desc = format!(
                "Enter PIN for card {} to sign with key {}",
                card_ident,
                cert_info
                    .user_ids
                    .first()
                    .map(|u| u.value.as_str())
                    .unwrap_or(&cert_info.fingerprint)
            );

            let pin = pinentry::get_passphrase(&desc, "Card PIN", Some(&cert_info.fingerprint))?;

            let signature = wecanencrypt::card::sign_bytes_detached_on_card(
                data,
                cert_data,
                pin.as_bytes(),
            )
            .context("Card signing failed")?;

            writeln!(
                err,
                "tcli: Signed with card {} key {}",
                card_ident, cert_info.fingerprint
            )?;

            return Ok(signature);
        }
    }

    anyhow::bail!("No card found with signing key for {}", cert_info.fingerprint)
}

/// Sign using a software key from the tumpa keystore.
fn sign_with_software_key(
    data: &[u8],
    cert_data: &[u8],
    cert_info: &wecanencrypt::CertificateInfo,
    err: &mut impl Write,
) -> Result<String> {
    if !cert_info.is_secret {
        anyhow::bail!(
            "No secret key available for {}. Import a secret key into tumpa first.",
            cert_info.fingerprint
        );
    }

    let desc = format!(
        "Enter passphrase for key {}",
        cert_info
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or(&cert_info.fingerprint)
    );

    let passphrase = pinentry::get_passphrase(&desc, "Passphrase", Some(&cert_info.fingerprint))?;

    let signature = wecanencrypt::sign_bytes_detached(cert_data, data, &passphrase)
        .context("Software key signing failed")?;

    writeln!(
        err,
        "tcli: Signed with software key {}",
        cert_info.fingerprint
    )?;

    Ok(signature)
}
