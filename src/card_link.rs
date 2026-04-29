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

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use libtumpa::card::link::{self, CardKeyDetection};
use wecanencrypt::card::{get_card_details, CardInfo, KeySlot};
use wecanencrypt::keystore::StoredCardKey;

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

/// Canonical print order for slot labels: signature, encryption,
/// authentication. Matches `tcli card status` and the OpenPGP card
/// data-object order.
fn slot_rank(slot: &str) -> u8 {
    match slot {
        "signature" => 0,
        "encryption" => 1,
        "authentication" => 2,
        _ => 99,
    }
}

/// Single-letter slot tag used in the `[S E A]` summary on `tcli describe`.
fn slot_tag(slot: &str) -> &'static str {
    match slot {
        "signature" => "S",
        "encryption" => "E",
        "authentication" => "A",
        _ => "?",
    }
}

/// Render the "Cards holding this key" footer for `tcli describe`.
///
/// Returns an empty Vec if `assocs` is empty (callers shouldn't print a
/// header in that case). One key may live on multiple cards (e.g.
/// signing on YubiKey, auth on Nitrokey, or the same key replicated
/// across two backups), so cards are grouped per `card_ident` and the
/// slot tags compressed into a single bracketed list per card.
///
/// Indentation matches `print_key_info`'s 5-space label gutter.
pub fn render_card_links_for_key(assocs: &[StoredCardKey]) -> Vec<String> {
    if assocs.is_empty() {
        return Vec::new();
    }

    // Group by card_ident, preserving the manufacturer/serial of the
    // first row seen for each card (these are identical across rows
    // for the same ident — the same card row gets the same metadata
    // every time `auto_link_after_upload` writes it).
    let mut by_card: BTreeMap<String, (Option<String>, String, Vec<String>)> = BTreeMap::new();
    for a in assocs {
        let entry = by_card.entry(a.card_ident.clone()).or_insert_with(|| {
            (
                a.card_manufacturer.clone(),
                a.card_serial.clone(),
                Vec::new(),
            )
        });
        if !entry.2.contains(&a.slot) {
            entry.2.push(a.slot.clone());
        }
    }

    let mut out = Vec::with_capacity(by_card.len() + 1);
    out.push("     Cards:".to_string());
    for (ident, (mfg, serial, mut slots)) in by_card {
        slots.sort_by_key(|s| slot_rank(s));
        let tags = slots
            .iter()
            .map(|s| slot_tag(s))
            .collect::<Vec<_>>()
            .join(" ");
        let mfg_str = mfg.as_deref().unwrap_or("Unknown");
        out.push(format!(
            "       {}  {} ({})  [{}]",
            ident, mfg_str, serial, tags
        ));
    }
    out
}

pub fn cmd_card_link(
    dry_run: bool,
    filter_card_ident: Option<&str>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    let detections = link::auto_detect(&keystore)
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

    if dry_run {
        // Dry-run prints "Would link: ..." up front and writes nothing.
        print_detections(&detections, true);
        return Ok(());
    }

    // Write first, then announce. Printing "Linked: ..." up front and
    // failing partway through `apply_links` would tell the user every
    // row was written when only a prefix actually was; the post-write
    // print + summary are honest about what's persisted.
    apply_links(&keystore, &detections)?;
    print_detections(&detections, false);
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

fn apply_links(keystore: &wecanencrypt::KeyStore, detections: &[CardKeyDetection]) -> Result<()> {
    // `link::link` wants `&CardInfo`; `auto_detect` only attached the
    // lighter `CardSummary` to each row. Re-fetch CardInfo once per
    // unique ident — typically one PCSC round-trip in practice.
    let mut info_cache: HashMap<String, CardInfo> = HashMap::new();
    for d in detections {
        if !info_cache.contains_key(&d.card_ident) {
            let info = get_card_details(Some(&d.card_ident))
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
    use super::{filter_detections, render_card_links_for_key, slot_str};
    use libtumpa::card::link::CardKeyDetection;
    use wecanencrypt::card::{CardSummary, KeySlot};
    use wecanencrypt::keystore::StoredCardKey;

    fn assoc(card_ident: &str, mfg: Option<&str>, serial: &str, slot: &str) -> StoredCardKey {
        StoredCardKey {
            card_ident: card_ident.to_string(),
            card_serial: serial.to_string(),
            card_manufacturer: mfg.map(str::to_string),
            slot: slot.to_string(),
            slot_fingerprint: format!("SLOTFP:{card_ident}:{slot}"),
            last_seen: "2026-04-29T00:00:00Z".to_string(),
        }
    }

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

    // ---- render_card_links_for_key ----

    #[test]
    fn render_empty_assocs_returns_empty() {
        assert!(render_card_links_for_key(&[]).is_empty());
    }

    #[test]
    fn render_single_card_single_slot() {
        let xs = vec![assoc(
            "000F:CB9A5355",
            Some("Nitrokey GmbH"),
            "CB9A5355",
            "authentication",
        )];
        let out = render_card_links_for_key(&xs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "     Cards:");
        assert_eq!(
            out[1],
            "       000F:CB9A5355  Nitrokey GmbH (CB9A5355)  [A]"
        );
    }

    #[test]
    fn render_single_card_three_slots_sorted_canonical() {
        // Input order is reversed; render must reorder to S E A.
        let xs = vec![
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "encryption",
            ),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "signature",
            ),
        ];
        let out = render_card_links_for_key(&xs);
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[1],
            "       000F:CB9A5355  Nitrokey GmbH (CB9A5355)  [S E A]"
        );
    }

    // Pins option-2 motivation from the design discussion: one key
    // can live on multiple cards (e.g. signing on YubiKey, auth on
    // Nitrokey, or the same key replicated across two backups).
    // Render must group per-card and emit one line per `card_ident`.
    #[test]
    fn render_multiple_cards_grouped_by_ident() {
        let xs = vec![
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
            assoc("0006:00000001", Some("Yubico"), "00000001", "signature"),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "encryption",
            ),
        ];
        let out = render_card_links_for_key(&xs);
        // header + 2 card lines (Yubico sorts before Nitrokey by
        // BTreeMap on the card_ident key string).
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], "     Cards:");
        assert!(
            out[1].contains("0006:00000001") && out[1].ends_with("[S]"),
            "got: {}",
            out[1]
        );
        assert!(
            out[2].contains("000F:CB9A5355") && out[2].ends_with("[E A]"),
            "got: {}",
            out[2]
        );
    }

    #[test]
    fn render_unknown_manufacturer_falls_back_to_unknown() {
        let xs = vec![assoc("FFFF:DEADBEEF", None, "DEADBEEF", "signature")];
        let out = render_card_links_for_key(&xs);
        assert_eq!(out[1], "       FFFF:DEADBEEF  Unknown (DEADBEEF)  [S]");
    }

    #[test]
    fn render_dedupes_duplicate_slot_rows_per_card() {
        // Defensive: if two rows ever share (card_ident, slot) the
        // tag list still has each letter once.
        let xs = vec![
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
            assoc(
                "000F:CB9A5355",
                Some("Nitrokey GmbH"),
                "CB9A5355",
                "authentication",
            ),
        ];
        let out = render_card_links_for_key(&xs);
        // Check the bracketed tag specifically, not the whole line —
        // serial "CB9A5355" already contains 'A'.
        assert!(out[1].ends_with("[A]"), "got: {}", out[1]);
        assert!(!out[1].contains("[A A]"));
    }
}
