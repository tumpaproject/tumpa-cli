//! Decide whether a card op is going to block on a physical touch, and (on
//! macOS) post a Notification Center banner if so.
//!
//! Called from each card-aware dispatch site (sign / decrypt / sign+encrypt
//! sign-leg / SSH auth) right after the card has been identified and before
//! the libtumpa primitive is invoked. The libtumpa primitive opens its own
//! PCSC transaction; we open a transient one here, query the User Interaction
//! Flag, then drop it — there is no overlap, so no PCSC contention.

use crate::notify::{self, TouchOp};

pub use crate::notify::TouchOp as Op;

/// Touch-policy decision. Crate-visible so the unit tests in this
/// module (and other tumpa-cli internals) can match on it without
/// going through the full `maybe_notify_touch` side-effect path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// Slot is `On` or `Fixed`: card will refuse the op until the user
    /// touches the contact.
    Required,
    /// Slot is `Cached` or `CachedFixed`: first op in a ~15s window
    /// requires touch, subsequent ones inside the window don't. We can't
    /// tell which we are without doing the op, so notify defensively.
    MaybeCached,
    /// Slot is `Off` or the card doesn't expose UIF for this slot.
    NotRequired,
}

impl Decision {
    pub(crate) fn should_notify(self) -> bool {
        matches!(self, Decision::Required | Decision::MaybeCached)
    }
}

/// Read the UIF for `op` on `card_ident` and decide whether the user is
/// likely to be asked to touch.
///
/// Bias is toward notifying when we're uncertain. Earlier behavior
/// returned `NotRequired` whenever the UIF read errored OR a single
/// slot returned `None`; that silently dropped the banner on cards
/// where (e.g.) the encryption-slot UIF read failed transiently while
/// the others succeeded — the exact path users hit when only the
/// decryption slot has touch enabled. Now:
///   - `get_touch_modes` Err → `MaybeCached`, with a warn-level log.
///   - `get_touch_modes` Ok((None, None, None)) → try a direct
///     `GET DATA 0xD6/0xD7/0xD8` via talktosc; some YubiKey firmware
///     (4.3.x) supports UIF but doesn't embed the tags in ARD, so
///     openpgp-card-rs's ARD-only path returns None for every slot
///     even when `ykman openpgp info` reports a real policy. The
///     fallback uses the policy bytes the card actually has.
///   - requested slot `None` AND any other slot reported Some →
///     `MaybeCached` (the card supports UIF; this slot's read likely
///     failed). With a warn-level log.
///   - all three slots `None` (after fallback) → `NotRequired`
///     (older card with no UIF support — silent skip is correct).
/// macOS-only: the only caller is the macOS-gated
/// `maybe_notify_touch`, and the talktosc fallback path it depends on
/// would otherwise force the PCSC stack to build on Linux/BSD for
/// dead code.
#[cfg(target_os = "macos")]
pub(crate) fn decide(op: TouchOp, card_ident: Option<&str>) -> Decision {
    let modes = match wecanencrypt::card::get_touch_modes(card_ident) {
        Ok((None, None, None)) => {
            // ARD didn't carry UIF tags. Try the direct-APDU fallback
            // before giving up — see read_uif_via_talktosc for the
            // YubiKey 4 firmware quirk that makes this necessary.
            match card_ident.and_then(read_uif_via_talktosc) {
                Some(fallback) => {
                    log::info!(
                        "ARD lacked UIF tags; talktosc fallback for {card_ident:?} returned: \
                         sig={:?} enc={:?} auth={:?}",
                        fallback.0,
                        fallback.1,
                        fallback.2
                    );
                    fallback
                }
                None => (None, None, None),
            }
        }
        Ok(m) => m,
        Err(e) => {
            log::warn!("could not read card UIF ({e}); notifying defensively for {op:?}");
            return Decision::MaybeCached;
        }
    };

    log::info!(
        "card UIF for op={op:?} card={card_ident:?}: sig={:?} enc={:?} auth={:?}",
        modes.0,
        modes.1,
        modes.2
    );

    decide_from_modes(op, modes)
}

/// Map the OpenPGP card's UIF policy byte to wecanencrypt's
/// `TouchMode`. Pure function, factored out for unit testing — the
/// rest of the talktosc path needs real hardware.
fn touch_mode_from_policy_byte(byte: u8) -> Option<wecanencrypt::card::TouchMode> {
    use wecanencrypt::card::TouchMode;
    match byte {
        0x00 => Some(TouchMode::Off),
        0x01 => Some(TouchMode::On),
        0x02 => Some(TouchMode::Fixed),
        0x03 => Some(TouchMode::Cached),
        0x04 => Some(TouchMode::CachedFixed),
        _ => None,
    }
}

/// Direct `GET DATA 0xD6/0xD7/0xD8` via talktosc, used as a fallback
/// when wecanencrypt's ARD-cached UIF read returns all-None.
///
/// Why this exists: the OpenPGP card spec 3.4 documents per-slot UIF
/// data objects (`Tags::UifSig` = 0xD6, `UifDec` = 0xD7, `UifAuth` =
/// 0xD8). The 3.4 spec also embeds those tags inside Application
/// Related Data (DO 0x6E) so a single ARD read sees them. YubiKey
/// applet 2.1 (firmware 4.3.x and earlier) supports the UIF DOs but
/// doesn't embed them in ARD; the cards work fine with ykman because
/// ykman issues the per-slot GET DATA directly. openpgp-card-rs's
/// `user_interaction_flag` only walks ARD, so on those firmware
/// versions every slot reads as None even though the actual touch
/// policy is set.
///
/// We connect via talktosc, SELECT the OpenPGP applet, and send a
/// `00 CA 00 <tag> 00` for each slot; success replies are
/// `<policy_byte> <button_byte> 90 00`. Any failure (no card
/// matching the ident, SELECT failed, status word non-9000) returns
/// None — same-shape as wecanencrypt's reader so the existing
/// `decide_from_modes` logic plugs in unchanged.
///
/// Best-effort by design: errors are logged at warn / debug level
/// and the caller falls through to its own None-handling.
///
/// macOS-only: gated alongside `decide` and the `talktosc` Cargo
/// dependency.
#[cfg(target_os = "macos")]
fn read_uif_via_talktosc(
    card_ident: &str,
) -> Option<(
    Option<wecanencrypt::card::TouchMode>,
    Option<wecanencrypt::card::TouchMode>,
    Option<wecanencrypt::card::TouchMode>,
)> {
    use talktosc::apdus::{create_apdu_select_openpgp, APDU};

    let card = match talktosc::create_connection_by_ident(card_ident) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("talktosc connect_by_ident({card_ident}) failed: {e:?}");
            return None;
        }
    };

    // SELECT the OpenPGP applet so subsequent GET DATA calls hit the
    // OpenPGP DO namespace. talktosc::send_and_parse already returns
    // an Err if the card declines.
    if let Err(e) = talktosc::send_and_parse(&card, create_apdu_select_openpgp()) {
        log::warn!("talktosc SELECT OpenPGP applet failed for {card_ident}: {e:?}");
        talktosc::disconnect(card);
        return None;
    }

    // Issue `GET DATA 00 CA 00 <tag> 00` per slot. The expected reply
    // is two data bytes (touch policy, button feature) plus the 9000
    // status word; talktosc::Response::is_okay() guards the latter.
    let read_slot = |tag: u8| -> Option<wecanencrypt::card::TouchMode> {
        let apdu = APDU::new(0x00, 0xCA, 0x00, tag, None);
        match talktosc::send_and_parse(&card, apdu) {
            Ok(resp) if resp.is_okay() => {
                let data = resp.get_data();
                if data.is_empty() {
                    log::debug!("UIF GET DATA tag=0x{tag:02X} returned empty data");
                    return None;
                }
                touch_mode_from_policy_byte(data[0])
            }
            Ok(resp) => {
                log::debug!(
                    "UIF GET DATA tag=0x{tag:02X} non-9000: sw1=0x{:02X} sw2=0x{:02X}",
                    resp.sw1,
                    resp.sw2
                );
                None
            }
            Err(e) => {
                log::warn!("UIF GET DATA tag=0x{tag:02X} send failed: {e:?}");
                None
            }
        }
    };

    let sig = read_slot(0xD6);
    let enc = read_slot(0xD7);
    let auth = read_slot(0xD8);

    talktosc::disconnect(card);

    Some((sig, enc, auth))
}

/// Pure decision logic, factored out for unit testing without
/// hitting real card hardware. Takes the raw `(sig, enc, auth)` tuple
/// from `wecanencrypt::card::get_touch_modes`.
pub(crate) fn decide_from_modes(
    op: TouchOp,
    modes: (
        Option<wecanencrypt::card::TouchMode>,
        Option<wecanencrypt::card::TouchMode>,
        Option<wecanencrypt::card::TouchMode>,
    ),
) -> Decision {
    use wecanencrypt::card::TouchMode;

    let (sig, enc, auth) = modes;
    // Compute "any slot reported a policy" before moving the chosen
    // slot out of the tuple. If even one slot reported, the card
    // supports UIF — a None on a different slot is far more likely
    // to be a transient read failure than a real "no policy here".
    let any_known = sig.is_some() || enc.is_some() || auth.is_some();

    let slot = match op {
        TouchOp::Sign => sig,
        TouchOp::Decrypt => enc,
        TouchOp::Auth => auth,
    };

    match (slot, any_known) {
        (Some(TouchMode::On) | Some(TouchMode::Fixed), _) => Decision::Required,
        (Some(TouchMode::Cached) | Some(TouchMode::CachedFixed), _) => Decision::MaybeCached,
        (Some(TouchMode::Off), _) => Decision::NotRequired,
        (None, true) => {
            log::warn!(
                "card returned no UIF for {op:?} slot but reported others; notifying defensively"
            );
            Decision::MaybeCached
        }
        (None, false) => Decision::NotRequired,
    }
}

/// Combined "decide + post notification" entry point.
///
/// Pass the OpenPGP card ident (e.g. `"0006:01234567"`) when known so the
/// touch policy is queried for the exact card; pass `None` to fall back to
/// the first enumerated card. On any failure, this is a silent no-op —
/// notifications are best-effort UX.
///
/// macOS-only: the underlying `notify::touch_prompt` is itself a
/// no-op on every other platform, and the UIF / card-detail queries
/// would cost extra PCSC traffic with no user-visible benefit.
#[cfg(target_os = "macos")]
pub fn maybe_notify_touch(op: Op, card_ident: Option<&str>) {
    if !decide(op, card_ident).should_notify() {
        return;
    }

    // Try to put a card serial in the notification body. Failure here
    // just means the body falls back to a generic message.
    let serial = match wecanencrypt::card::get_card_details(card_ident) {
        Ok(info) => Some(info.serial_number),
        Err(_) => card_ident
            .and_then(|s| s.split(':').nth(1))
            .map(|s| s.to_string()),
    };

    notify::touch_prompt(op, serial.as_deref());
}

/// Non-macOS stub. See the macOS variant for rationale.
#[cfg(not(target_os = "macos"))]
pub fn maybe_notify_touch(_op: Op, _card_ident: Option<&str>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use wecanencrypt::card::TouchMode;

    #[test]
    fn required_modes_notify() {
        assert!(Decision::Required.should_notify());
        assert!(Decision::MaybeCached.should_notify());
    }

    #[test]
    fn off_does_not_notify() {
        assert!(!Decision::NotRequired.should_notify());
    }

    /// On a card that has touch ON only for the decryption slot — the
    /// shape the bug repro has — Decrypt must come back as Required.
    #[test]
    fn decrypt_only_touch_picks_enc_slot() {
        let modes = (
            Some(TouchMode::Off),
            Some(TouchMode::On),
            Some(TouchMode::Off),
        );
        assert_eq!(
            decide_from_modes(TouchOp::Decrypt, modes),
            Decision::Required
        );
        // The other slots must NOT borrow the enc setting.
        assert_eq!(
            decide_from_modes(TouchOp::Sign, modes),
            Decision::NotRequired
        );
        assert_eq!(
            decide_from_modes(TouchOp::Auth, modes),
            Decision::NotRequired
        );
    }

    /// Per-slot None on the requested op, but other slots reported a
    /// policy: the card does support UIF, this slot's read likely
    /// failed transiently. Bias toward notifying.
    #[test]
    fn requested_slot_none_with_others_known_notifies_defensively() {
        let modes = (
            Some(TouchMode::Off),
            None, // encryption read failed silently
            Some(TouchMode::Off),
        );
        assert_eq!(
            decide_from_modes(TouchOp::Decrypt, modes),
            Decision::MaybeCached
        );
    }

    /// All three slots None: card doesn't support UIF at all (older /
    /// non-YubiKey card). Stay quiet — notifying every op would be
    /// noisy, and these cards genuinely don't ask for touch.
    #[test]
    fn all_slots_none_does_not_notify() {
        let modes = (None, None, None);
        assert_eq!(
            decide_from_modes(TouchOp::Decrypt, modes),
            Decision::NotRequired
        );
        assert_eq!(decide_from_modes(TouchOp::Sign, modes), Decision::NotRequired);
        assert_eq!(decide_from_modes(TouchOp::Auth, modes), Decision::NotRequired);
    }

    /// Pin the OpenPGP card UIF policy byte → wecanencrypt::TouchMode
    /// mapping used by the talktosc fallback. The byte values come
    /// straight from the OpenPGP card spec (Off=0x00, On=0x01,
    /// Fixed=0x02, Cached=0x03, CachedFixed=0x04). If wecanencrypt's
    /// enum ever grows a variant or shifts byte assignments, this
    /// breaks loudly instead of silently misclassifying.
    #[test]
    fn touch_mode_from_policy_byte_pins_spec_values() {
        assert_eq!(
            touch_mode_from_policy_byte(0x00),
            Some(TouchMode::Off)
        );
        assert_eq!(touch_mode_from_policy_byte(0x01), Some(TouchMode::On));
        assert_eq!(
            touch_mode_from_policy_byte(0x02),
            Some(TouchMode::Fixed)
        );
        assert_eq!(
            touch_mode_from_policy_byte(0x03),
            Some(TouchMode::Cached)
        );
        assert_eq!(
            touch_mode_from_policy_byte(0x04),
            Some(TouchMode::CachedFixed)
        );
        // Unknown / future-spec values become None — caller treats as
        // "card returned UIF data we don't recognize", which the
        // partial-None branch already handles defensively.
        assert_eq!(touch_mode_from_policy_byte(0x05), None);
        assert_eq!(touch_mode_from_policy_byte(0xFF), None);
    }

    /// Cached / CachedFixed surface as MaybeCached so the banner shows
    /// at least once per ~15s window — we can't tell from outside
    /// whether we're inside the cached window or about to start a new
    /// one.
    #[test]
    fn cached_modes_are_maybe_cached() {
        let cached_modes = (
            Some(TouchMode::Off),
            Some(TouchMode::Cached),
            Some(TouchMode::Off),
        );
        assert_eq!(
            decide_from_modes(TouchOp::Decrypt, cached_modes),
            Decision::MaybeCached
        );

        let cached_fixed_modes = (
            Some(TouchMode::Off),
            Some(TouchMode::CachedFixed),
            Some(TouchMode::Off),
        );
        assert_eq!(
            decide_from_modes(TouchOp::Decrypt, cached_fixed_modes),
            Decision::MaybeCached
        );
    }
}
