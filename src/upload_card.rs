//! Upload a secret key from the keystore to an OpenPGP smart card.
//!
//! Available when `tcli` is built with the `experimental` Cargo
//! feature (`cargo build --features experimental`). Invoked as
//! `tcli --upload-to-card <FP> [--card-ident <IDENT>]
//!  [--which primary|sub] [--include-signing]
//!  [--include-encryption] [--include-authentication]`.
//!
//! By default the certificate's primary key (or its signing subkey,
//! when the primary is not sign-capable) is written to the card's
//! signing slot. Pass `--which primary|sub` to disambiguate when the
//! cert has both a sign-capable primary and a signing subkey;
//! `--include-signing` is the discoverable alias for "use the signing
//! subkey, leave the primary off-card", composing with the
//! `--include-*` flags below.
//!
//! `--include-encryption` and `--include-authentication` extend the
//! same call to fill the card's decryption / authentication slots
//! from the cert's encryption / authentication subkeys. Slots not
//! mentioned are left empty after the factory reset.
//!
//! With multiple cards attached, `--card-ident` selects the target
//! (see `--list-cards` for valid idents); with a single card it can
//! be omitted. libtumpa's multi-card guard rejects an implicit
//! target when more than one card is connected.
//!
//! Upload goes through `libtumpa::card::upload::upload`, which runs a
//! preflight algorithm check (e.g. rejects legacy `Cv25519` on Nitrokey
//! before any destructive I/O) and then **factory-resets** the card
//! before writing the selected slots. Cardholder name, URL, user PIN,
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
    include_signing: bool,
    include_encryption: bool,
    include_authentication: bool,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let (_raw, key_info) = store::resolve_signer(&keystore, key_id)?;

    if !key_info.is_secret {
        bail!(
            "key {} has no secret material in the keystore — nothing to upload",
            key_info.fingerprint
        );
    }

    // `--include-signing` is the discoverable spelling of "use the
    // signing subkey, not the primary"; folding it into `which` here
    // lets `select_sign_target` reuse the same decision matrix it has
    // for the older `--which sub` form. Contradiction with
    // `--which primary` is rejected at parse time.
    //
    // Pre-check the "no signing subkey" case here before the synthesis
    // so the user gets an error that names `--include-signing`. If we
    // let the synthesized `Some(Sub)` flow into `select_sign_target`,
    // its generic message would say "drop `--which`" -- but the user
    // never passed `--which`.
    let effective_which = if include_signing && which.is_none() {
        let has_signing_subkey = key_info.subkeys.iter().any(|sk| {
            sk.key_type == KeyType::Signing
                && !sk.is_revoked
                && !store::subkey_is_expired(sk)
        });
        if !has_signing_subkey {
            bail!(
                "certificate {} has no signing subkey — drop `--include-signing` \
                 (the primary will be used as the signing-slot occupant) or \
                 generate a signing subkey first",
                key_info.fingerprint
            );
        }
        Some(WhichKey::Sub)
    } else {
        which
    };

    // Decide which component of the cert we should upload.
    let target = select_sign_target(&key_info, effective_which)?;

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

    // --- Build the slot bitmask ---

    let mut which_flags = match target {
        SignTarget::Primary => flags::PRIMARY_TO_SIGNING,
        SignTarget::Sub => flags::SIGNING_SUBKEY,
    };
    if include_encryption {
        which_flags |= flags::ENCRYPTION;
    }
    if include_authentication {
        which_flags |= flags::AUTHENTICATION;
    }

    let target_label = match target {
        SignTarget::Primary => "primary key",
        SignTarget::Sub => "signing subkey",
    };

    // Human-readable list of slots about to be filled, for the warning
    // and the success message.
    let mut slots_label = vec![format!("signing slot ({})", target_label)];
    if include_encryption {
        slots_label.push("decryption slot (encryption subkey)".into());
    }
    if include_authentication {
        slots_label.push("authentication slot (authentication subkey)".into());
    }
    let slots_human = slots_label.join(", ");

    // --- Warn about destructive reset ---
    //
    // Worded conditionally: libtumpa's preflight guard may still
    // reject this upload (e.g. unsupported algorithm on the target
    // card, or a missing encryption/authentication subkey when those
    // were requested), in which case no reset actually runs.
    eprintln!(
        "Warning: if this upload proceeds, the card will be \
         factory-reset (cardholder name, URL, user PIN, and admin PIN \
         cleared to defaults) before writing {} of {}.\n\
         Press Ctrl-C within 3 seconds to abort.",
        slots_human, key_info.fingerprint
    );
    std::thread::sleep(std::time::Duration::from_secs(3));

    // --- Upload ---

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
            slots_human, key_info.fingerprint
        )
    })?;

    eprintln!(
        "OK. Card now holds {} of {}.",
        slots_human, key_info.fingerprint
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
/// Delegates to `libtumpa::card::admin::factory_reset_card`, which
/// drives the admin-PIN retry counter to zero (with rotating
/// known-wrong candidates so a coincidental real-PIN match doesn't
/// stall the loop) and then issues `TERMINATE DF` + factory reset.
/// Multi-card targeting is enforced by libtumpa: passing
/// `card_ident = None` while multiple cards are connected is
/// rejected so the destructive reset can't silently land on the
/// wrong card.
///
/// After the reset the card is back to defaults: user PIN `123456`,
/// admin PIN `12345678`, all key slots empty.
pub fn cmd_reset_card(card_ident: Option<&str>) -> Result<()> {
    eprintln!("Resetting card to factory defaults...");

    libtumpa::card::admin::factory_reset_card(card_ident)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("factory reset failed")?;

    eprintln!("Card reset. User PIN=123456, admin PIN=12345678, all slots cleared.");
    Ok(())
}
