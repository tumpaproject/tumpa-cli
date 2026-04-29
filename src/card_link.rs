//! `tcli card link` subcommand handler.
//!
//! Walks every connected OpenPGP card via `libtumpa::card::link::auto_detect`
//! and writes a row in the keystore's `card_keys` table for each slot
//! whose fingerprint matches a primary or subkey of any stored cert.
//!
//! Read-write on the keystore. Read-only on the cards (no PIN prompts,
//! no APDU writes). The ssh-agent + GPG dispatch logic uses these rows
//! to find the card holding a given key, so without them `ssh-add -L`
//! returns no card-backed identities even when the card is plugged in.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use libtumpa::card::link::{self, CardKeyDetection};
use wecanencrypt::card::{get_card_details, CardInfo, KeySlot};

use crate::store;

/// Map a `KeySlot` to the textual name `link::link` expects.
///
/// The `card_keys.slot` column is documented as one of these three
/// strings; the SSH agent's enumerator filters on `slot = "authentication"`,
/// so any drift here silently breaks ssh-add / git ssh-signing.
fn slot_str(slot: KeySlot) -> &'static str {
    match slot {
        KeySlot::Signature => "signature",
        KeySlot::Encryption => "encryption",
        KeySlot::Authentication => "authentication",
    }
}

pub fn cmd_card_link(
    dry_run: bool,
    filter_card_ident: Option<&str>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    let detections = link::auto_detect(&keystore)
        .map_err(|e| anyhow!("{e}"))
        .context("failed to auto-detect card↔key matches")?;

    let detections = filter_detections(detections, filter_card_ident)?;

    if detections.is_empty() {
        if filter_card_ident.is_some() {
            bail!(
                "No card slots on the requested card match any key in the keystore. \
                 Run `tcli card list` to confirm the ident, and `tcli list` to confirm \
                 the keystore has the matching cert."
            );
        }
        eprintln!("No card slots match any key in the keystore.");
        return Ok(());
    }

    print_detections(&detections, dry_run);

    if dry_run {
        return Ok(());
    }

    apply_links(&keystore, &detections)?;
    eprintln!(
        "Wrote {} card↔key link{} to the keystore.",
        detections.len(),
        if detections.len() == 1 { "" } else { "s" }
    );
    Ok(())
}

/// Trim the auto-detect output to the requested card. Pure so it can
/// be unit-tested without a card or keystore.
fn filter_detections(
    detections: Vec<CardKeyDetection>,
    filter_card_ident: Option<&str>,
) -> Result<Vec<CardKeyDetection>> {
    let Some(ident) = filter_card_ident else {
        return Ok(detections);
    };
    let trimmed: Vec<_> = detections
        .into_iter()
        .filter(|d| d.card_ident == ident)
        .collect();
    Ok(trimmed)
}

fn print_detections(detections: &[CardKeyDetection], dry_run: bool) {
    let prefix = if dry_run { "Would link" } else { "Linked" };
    for d in detections {
        eprintln!(
            "{prefix}: card {} slot {} ({}) -> key {}",
            d.card_ident,
            slot_str(d.slot),
            d.slot_fingerprint,
            d.key_fingerprint,
        );
    }
}

fn apply_links(
    keystore: &wecanencrypt::KeyStore,
    detections: &[CardKeyDetection],
) -> Result<()> {
    // `link::link` wants `&CardInfo`; `auto_detect` only attached the
    // lighter `CardSummary` to each row. Re-fetch CardInfo once per
    // unique ident — typically one PCSC round-trip in practice.
    let mut info_cache: HashMap<String, CardInfo> = HashMap::new();
    for d in detections {
        if !info_cache.contains_key(&d.card_ident) {
            let info = get_card_details(Some(&d.card_ident))
                .map_err(|e| anyhow!("{e}"))
                .with_context(|| format!("failed to read card {}", d.card_ident))?;
            info_cache.insert(d.card_ident.clone(), info);
        }
        let info = &info_cache[&d.card_ident];
        link::link(
            keystore,
            &d.key_fingerprint,
            info,
            slot_str(d.slot),
            &d.slot_fingerprint,
        )
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| {
            format!(
                "failed to write link for card {} slot {} → key {}",
                d.card_ident,
                slot_str(d.slot),
                d.key_fingerprint
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{filter_detections, slot_str};
    use libtumpa::card::link::CardKeyDetection;
    use wecanencrypt::card::{CardSummary, KeySlot};

    fn detection(card_ident: &str, slot: KeySlot, key_fp: &str) -> CardKeyDetection {
        CardKeyDetection {
            key_fingerprint: key_fp.to_string(),
            card_ident: card_ident.to_string(),
            card_summary: CardSummary {
                ident: card_ident.to_string(),
                manufacturer_name: "Test".to_string(),
                serial_number: card_ident
                    .split(':')
                    .nth(1)
                    .unwrap_or(card_ident)
                    .to_string(),
                cardholder_name: None,
            },
            slot,
            slot_fingerprint: format!("SLOTFP:{key_fp}"),
        }
    }

    #[test]
    fn slot_str_maps_every_variant() {
        assert_eq!(slot_str(KeySlot::Signature), "signature");
        assert_eq!(slot_str(KeySlot::Encryption), "encryption");
        assert_eq!(slot_str(KeySlot::Authentication), "authentication");
    }

    #[test]
    fn filter_none_passes_everything_through() {
        let xs = vec![
            detection("000F:AAA", KeySlot::Authentication, "FP1"),
            detection("0006:BBB", KeySlot::Signature, "FP2"),
        ];
        let out = filter_detections(xs.clone(), None).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].card_ident, "000F:AAA");
        assert_eq!(out[1].card_ident, "0006:BBB");
    }

    #[test]
    fn filter_matches_card_ident_exactly() {
        let xs = vec![
            detection("000F:AAA", KeySlot::Authentication, "FP1"),
            detection("0006:BBB", KeySlot::Signature, "FP2"),
            detection("000F:AAA", KeySlot::Encryption, "FP3"),
        ];
        let out = filter_detections(xs, Some("000F:AAA")).unwrap();
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|d| d.card_ident == "000F:AAA"));
    }

    #[test]
    fn filter_returns_empty_when_no_card_matches() {
        let xs = vec![detection("000F:AAA", KeySlot::Authentication, "FP1")];
        let out = filter_detections(xs, Some("DEAD:BEEF")).unwrap();
        assert!(out.is_empty());
    }
}
