//! **Experimental.** Enumerate connected OpenPGP smart cards.
//!
//! Gated behind `tcli --experimental --list-cards`. Prints a table of
//! the ident, manufacturer, serial, and cardholder name of every card
//! visible to wecanencrypt's PCSC enumeration. The IDENT column is the
//! value callers pass to `--card-ident` on `--upload-to-card` or
//! `--reset-card`.
//!
//! Read-only: no PIN prompts, no APDU writes. One ATR-level read per
//! card (via `list_all_cards`) to populate `CardSummary`.

use anyhow::{Context, Result};

pub fn cmd_list_cards() -> Result<()> {
    let cards = wecanencrypt::card::list_all_cards()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("failed to enumerate OpenPGP cards")?;

    if cards.is_empty() {
        eprintln!("No OpenPGP cards connected.");
        return Ok(());
    }

    // Compute column widths so long manufacturer names (e.g.
    // "Nitrokey GmbH") don't break alignment on Yubikey rows.
    let ident_w = cards
        .iter()
        .map(|c| c.ident.len())
        .max()
        .unwrap_or(0)
        .max("IDENT".len());
    let mfg_w = cards
        .iter()
        .map(|c| c.manufacturer_name.len())
        .max()
        .unwrap_or(0)
        .max("MANUFACTURER".len());
    let serial_w = cards
        .iter()
        .map(|c| c.serial_number.len())
        .max()
        .unwrap_or(0)
        .max("SERIAL".len());

    println!(
        "{:<iw$}  {:<mw$}  {:<sw$}  HOLDER",
        "IDENT",
        "MANUFACTURER",
        "SERIAL",
        iw = ident_w,
        mw = mfg_w,
        sw = serial_w,
    );
    for c in &cards {
        let holder = c.cardholder_name.as_deref().unwrap_or("(unset)");
        println!(
            "{:<iw$}  {:<mw$}  {:<sw$}  {}",
            c.ident,
            c.manufacturer_name,
            c.serial_number,
            holder,
            iw = ident_w,
            mw = mfg_w,
            sw = serial_w,
        );
    }
    Ok(())
}
