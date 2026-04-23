//! **Experimental.** Upload a secret key from the keystore to an
//! OpenPGP smart card's signing slot.
//!
//! Gated behind `tcli --experimental --upload-to-card`. If the
//! certificate carries both a sign-capable primary key and a
//! sign-capable signing subkey, the caller must pass `--which
//! primary|sub` to disambiguate.
//!
//! Upload goes through `libtumpa::card::upload::upload`, which runs a
//! preflight algorithm check (e.g. rejects legacy `Cv25519` on Nitrokey
//! before any destructive I/O) and then **factory-resets** the card
//! before writing the selected slot. Cardholder name, URL, user PIN,
//! and admin PIN are cleared back to factory defaults. Only the key
//! passphrase is prompted — the admin PIN is managed internally by
//! libtumpa (it uses the factory default after reset).

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use libtumpa::card::upload::{flags, upload};
use wecanencrypt::KeyType;

use crate::{pinentry, store};

/// Which sign-capable component of a certificate the caller is asking
/// to upload. Mirrors `cli::WhichKey` but lives in the library side so
/// callers outside the `tcli` binary can use it too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhichKey {
    Primary,
    Sub,
}

/// Component of a certificate that is eligible to sit in the card's
/// signing slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignTarget {
    Primary,
    /// Signing subkey (exactly one).
    Sub,
}

pub fn cmd_upload_to_card(
    key_id: &str,
    which: Option<WhichKey>,
    keystore_path: Option<&PathBuf>,
    card_ident: Option<&str>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let (_raw, key_info) = store::resolve_signer(&keystore, key_id)?;

    if !key_info.is_secret {
        bail!(
            "key {} has no secret material in the keystore — nothing to upload",
            key_info.fingerprint
        );
    }

    // Decide which component of the cert we should upload.
    let target = select_sign_target(&key_info, which)?;

    let uid = key_info
        .user_ids
        .iter()
        .find(|u| u.is_primary && !u.revoked)
        .or_else(|| key_info.user_ids.iter().find(|u| !u.revoked))
        .map(|u| u.value.as_str())
        .unwrap_or("<no UID>");

    // --- Prompt for key passphrase ---

    let key_desc = format!(
        "Enter passphrase to unlock secret key\n{}\n{}",
        key_info.fingerprint, uid
    );
    let key_pass = pinentry::get_passphrase(&key_desc, "Passphrase", None)
        .context("failed to read key passphrase")?;

    // --- Warn about destructive reset ---

    let target_label = match target {
        SignTarget::Primary => "primary key",
        SignTarget::Sub => "signing subkey",
    };
    eprintln!(
        "Warning: --upload-to-card factory-resets the card first \
         (cardholder name, URL, user PIN, and admin PIN are cleared \
         to defaults) before writing the {} of {}.\n\
         Press Ctrl-C within 3 seconds to abort.",
        target_label, key_info.fingerprint
    );
    std::thread::sleep(std::time::Duration::from_secs(3));

    // --- Upload ---

    let which_flags = match target {
        SignTarget::Primary => flags::PRIMARY_TO_SIGNING,
        SignTarget::Sub => flags::SIGNING_SUBKEY,
    };

    upload(
        &keystore,
        &key_info.fingerprint,
        &key_pass,
        which_flags,
        card_ident,
    )
    .with_context(|| {
        format!(
            "failed to upload {} of {} to card",
            target_label, key_info.fingerprint
        )
    })?;

    eprintln!(
        "OK. Signing slot now holds the {} of {}.",
        target_label, key_info.fingerprint
    );

    Ok(())
}

/// Decide which component of the certificate is allowed to land in the
/// card's signing slot, honoring `--which` where present.
fn select_sign_target(
    key_info: &wecanencrypt::KeyInfo,
    which: Option<WhichKey>,
) -> Result<SignTarget> {
    let primary_can_sign = key_info.can_primary_sign && !key_info.is_revoked;
    let signing_subkeys: Vec<_> = key_info
        .subkeys
        .iter()
        .filter(|sk| sk.key_type == KeyType::Signing && !sk.is_revoked && !store::subkey_is_expired(sk))
        .collect();

    match (primary_can_sign, signing_subkeys.len(), which) {
        (false, 0, _) => bail!(
            "certificate {} has no sign-capable primary or subkey — nothing to upload",
            key_info.fingerprint
        ),

        (true, 0, None | Some(WhichKey::Primary)) => Ok(SignTarget::Primary),
        (true, 0, Some(WhichKey::Sub)) => bail!(
            "certificate {} has no signing subkey — pass `--which primary` or drop `--which`",
            key_info.fingerprint
        ),

        (false, 1, None | Some(WhichKey::Sub)) => Ok(SignTarget::Sub),
        (false, _, Some(WhichKey::Primary)) => bail!(
            "primary key of {} is not sign-capable — pass `--which sub` or drop `--which`",
            key_info.fingerprint
        ),

        // Ambiguous: both sides are sign-capable and the user has not picked.
        (true, n, None) if n >= 1 => bail!(
            "certificate {} has a sign-capable primary AND {} sign-capable subkey(s). \
             Pass `--which primary` or `--which sub` to disambiguate.",
            key_info.fingerprint,
            n
        ),

        (true, _, Some(WhichKey::Primary)) => Ok(SignTarget::Primary),
        (true, _, Some(WhichKey::Sub)) => Ok(SignTarget::Sub),

        (false, n, None | Some(WhichKey::Sub)) if n > 1 => bail!(
            "certificate {} has {} sign-capable subkeys — --upload-to-card cannot choose for you. \
             Resolve by deleting/revoking the unwanted subkey or uploading via another tool.",
            key_info.fingerprint,
            n
        ),

        // Fallback — should not hit, but keeps the match exhaustive.
        _ => bail!(
            "unable to determine which component of {} to upload; pass `--which primary|sub`",
            key_info.fingerprint
        ),
    }
}

/// **Experimental.** Factory-reset the connected OpenPGP card.
///
/// `TERMINATE DF` on an OpenPGP card requires the admin PIN to be in
/// the blocked state (retry counter == 0). To make `--reset-card`
/// idempotent regardless of the current PIN, we first exhaust the
/// admin-PIN retry counter with three known-wrong verifies, then issue
/// the factory reset. Same recipe wecanencrypt's own `card_tests.rs`
/// uses between test cases.
///
/// After the reset the card is back to defaults: user PIN `123456`,
/// admin PIN `12345678`, all key slots empty.
pub fn cmd_reset_card(card_ident: Option<&str>) -> Result<()> {
    eprintln!("Blocking admin PIN (3 wrong verifies) and resetting card...");

    // Force the admin PIN into the blocked state. We don't care about the
    // outcome of each verify — each one consumes a retry regardless of
    // whether the real admin PIN matches.
    for _ in 0..3 {
        let _ = wecanencrypt::card::verify_admin_pin(b"00000000", card_ident);
    }

    wecanencrypt::card::reset_card(card_ident)
        .with_context(|| "factory reset failed after blocking admin PIN")?;

    eprintln!("Card reset. User PIN=123456, admin PIN=12345678, all slots cleared.");
    Ok(())
}
