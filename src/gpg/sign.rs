use std::cell::RefCell;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use zeroize::Zeroizing;

use libtumpa::sign::{
    parse_digest_algo, sign_cleartext as libtumpa_sign_cleartext,
    sign_detached_with_hash as libtumpa_sign_detached_with_hash, Secret, SecretRequest,
    SignBackend,
};
use libtumpa::{HashAlgorithm, Passphrase, Pin};

use super::primary_uid;
use crate::card_touch::{self, Op as TouchOp};
use crate::pinentry;
use crate::store;

/// Map a `HashAlgorithm` to the OpenPGP numeric hash ID used in
/// `[GNUPG:] SIG_CREATED` status lines. Covers RFC 4880 §9.4 values
/// plus newer OpenPGP crypto-refresh / 4880bis assignments such as
/// SHA-3 (IDs 12 / 14).
///
/// Returns `None` for algorithms not in the OpenPGP-registered set
/// (e.g. a future libtumpa addition we haven't taught this mapping):
/// the caller emits no `SIG_CREATED` line in that case rather than
/// lying with `hash_algo=0`, which PGP/MIME `micalg` parsers would
/// reject. The caller logs a warning so the gap is visible at runtime.
fn gpg_hash_algo_id(alg: HashAlgorithm) -> Option<u8> {
    match alg {
        HashAlgorithm::Sha256 => Some(8),
        HashAlgorithm::Sha384 => Some(9),
        HashAlgorithm::Sha512 => Some(10),
        HashAlgorithm::Sha224 => Some(11),
        HashAlgorithm::Sha3_256 => Some(12),
        HashAlgorithm::Sha3_512 => Some(14),
        HashAlgorithm::Md5 => Some(1),
        HashAlgorithm::Sha1 => Some(2),
        HashAlgorithm::Ripemd160 => Some(3),
        _ => None,
    }
}

/// Sign data from stdin and write detached signature to stdout.
///
/// Delegates the card-first / software-fallback dispatch to
/// `libtumpa::sign::sign_detached_with_hash`. Pinentry / passphrase / PIN
/// acquisition stays here; libtumpa never prompts.
pub fn sign(
    mut data: impl Read,
    mut out: impl Write,
    mut err: impl Write,
    signer_id: &str,
    _armor: bool,
    digest_algo: Option<&str>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    log::info!(
        "sign called for signer_id: {} digest_algo: {:?}",
        signer_id,
        digest_algo
    );

    // Parse --digest-algo up front so an invalid value fails before we
    // consume stdin / prompt for a passphrase.
    let hash_preference = match digest_algo {
        Some(s) => Some(parse_digest_algo(s).map_err(|e| anyhow!("{e}"))?),
        None => None,
    };

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

    let result =
        libtumpa_sign_detached_with_hash(&key_data, &key_info, &buffer, hash_preference, |req| {
            match req {
                SecretRequest::CardPin {
                    card_ident,
                    key_info,
                } => {
                    *card_ident_used.borrow_mut() = Some(card_ident.to_string());
                    card_touch::maybe_notify_touch(TouchOp::Sign, Some(card_ident));
                    let pin: Zeroizing<String> = prompt_card_pin(card_ident, key_info)
                        .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
                    // Pre-op verify: a single VERIFY APDU validates the
                    // PIN against the card before libtumpa starts the
                    // signing transaction. Costs one round-trip but
                    // surfaces "wrong PIN" cleanly without conflating
                    // it with PCSC / signing-key errors.
                    verify_card_pin(card_ident, &pin, &key_info.fingerprint)
                        .map_err(|e| libtumpa::Error::Sign(format!("{e}")))?;
                    let pin_bytes: Pin = Zeroizing::new(pin.as_bytes().to_vec());
                    *last_secret.borrow_mut() = Some(pin);
                    Ok(Secret::Pin(pin_bytes))
                }
                SecretRequest::KeyPassphrase { key_info } => {
                    let pass: Passphrase = prompt_key_passphrase(key_info)
                        .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
                    // Pre-op verify for software keys: try to unlock
                    // the secret-key packet with the passphrase. Same
                    // motivation as the card-PIN case above.
                    verify_software_passphrase(&key_data, &pass, &key_info.fingerprint)
                        .map_err(|e| libtumpa::Error::Sign(format!("{e}")))?;
                    *last_secret.borrow_mut() = Some(pass.clone());
                    Ok(Secret::Passphrase(pass))
                }
            }
        });

    let sign_result = match result {
        Ok(ok) => {
            if let Some(secret) = last_secret.borrow().as_ref() {
                match backend_secret_kind(&ok.backend) {
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

    match sign_result.backend {
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
    out.write_all(sign_result.armored.as_bytes())
        .context("Failed to write signature to stdout")?;

    // Git checks the SIG_CREATED line prefix on stderr; the historic
    // tclig form was `[GNUPG:] SIG_CREATED ` (no fields).
    // https://github.com/git/git/blob/11c821f2f2a31e70fb5cc449f9a29401c333aad2/gpg-interface.c#L994
    //
    // GnuPG's documented field layout is:
    //   SIG_CREATED <type> <pk_algo> <hash_algo> <class> <timestamp> <fpr>
    // We fill <hash_algo> from libtumpa so PGP/MIME callers can read the
    // line on status-fd to learn what hash to put in `micalg`. Other
    // fields stay empty/zero — git only requires the prefix.
    //
    // If libtumpa returns a hash we don't have an OpenPGP-registered ID
    // for (future variant), we deliberately suppress SIG_CREATED rather
    // than emitting `hash_algo=0`: PGP/MIME `micalg` parsers reject 0,
    // and a missing line tells the caller to fall back rather than
    // hard-fail on a fabricated value. Git users on such a key would
    // need to add the mapping; the warning makes the gap visible.
    match gpg_hash_algo_id(sign_result.hash_algorithm) {
        Some(hash_id) => {
            writeln!(
                err,
                "\n[GNUPG:] SIG_CREATED D 0 {hash_id} 00 0 {}",
                key_info.fingerprint
            )?;
        }
        None => {
            log::warn!(
                "no OpenPGP hash ID known for {:?}; omitting SIG_CREATED line",
                sign_result.hash_algorithm
            );
        }
    }

    Ok(())
}

/// Prompt the user for the card PIN via pinentry, including card-status
/// context (cardholder, signature counter) when available.
///
/// Returns `Zeroizing<String>` so the secret is wiped from memory when
/// the value is dropped — never converted to a plain `String`.
pub(crate) fn prompt_card_pin(
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
pub(crate) fn prompt_key_passphrase(key_info: &wecanencrypt::KeyInfo) -> Result<Zeroizing<String>> {
    let desc = format!("Enter passphrase for key {}", primary_uid(key_info));
    pinentry::get_passphrase(&desc, "Passphrase", Some(&key_info.fingerprint))
}

/// Run the bare `wecanencrypt::card::verify_user_pin` APDU to check
/// that the PIN string is correct against the connected card BEFORE
/// libtumpa spends a sign or decrypt round-trip on it.
///
/// On Err, clears the agent's cached PIN for `fingerprint` so a stale
/// (or freshly-typed-but-wrong) value doesn't replay on the next op.
/// On Ok, the PIN is known correct — caller may proceed and (after
/// the real op succeeds) cache it via [`pinentry::cache_pin`].
pub(crate) fn verify_card_pin(
    card_ident: &str,
    pin: &Zeroizing<String>,
    fingerprint: &str,
) -> Result<()> {
    match wecanencrypt::card::verify_user_pin(pin.as_bytes(), Some(card_ident)) {
        Ok(_) => Ok(()),
        Err(e) => {
            pinentry::clear_cached_pin(fingerprint);
            Err(anyhow!("Card PIN verification failed: {e}"))
        }
    }
}

/// Software-key counterpart of [`verify_card_pin`].
///
/// Calls `wecanencrypt::verify_software_passphrase`, which tries to
/// unlock the primary secret-key packet without performing any crypto
/// op. On Err, clears the agent's cached passphrase for
/// `fingerprint`.
pub(crate) fn verify_software_passphrase(
    key_data: &[u8],
    pass: &Zeroizing<String>,
    fingerprint: &str,
) -> Result<()> {
    match wecanencrypt::verify_software_passphrase(key_data, pass.as_str()) {
        Ok(()) => Ok(()),
        Err(e) => {
            pinentry::clear_cached_passphrase(fingerprint);
            Err(anyhow!("Passphrase verification failed: {e}"))
        }
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

/// Sign data from stdin and write a cleartext-signed message
/// (`-----BEGIN PGP SIGNED MESSAGE-----`) to stdout.
///
/// Card-first dispatch via `libtumpa::sign::sign_cleartext`: a connected
/// OpenPGP card whose signing slot matches the resolved signer is used
/// before falling back to a software secret key with passphrase.
pub fn clearsign(
    mut data: impl Read,
    mut out: impl Write,
    mut err: impl Write,
    signer_id: &str,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    log::info!("clearsign called for signer_id: {}", signer_id);

    let mut buffer = Vec::new();
    data.read_to_end(&mut buffer)
        .context("Failed to read data from stdin")?;

    let keystore = store::open_keystore(keystore_path)?;
    let (key_data, key_info) = store::resolve_signer(&keystore, signer_id)?;
    store::ensure_key_usable_for_signing(&key_info)?;

    let card_ident_used: RefCell<Option<String>> = RefCell::new(None);
    let last_secret: RefCell<Option<Zeroizing<String>>> = RefCell::new(None);

    let result = libtumpa_sign_cleartext(&key_data, &key_info, &buffer, |req| match req {
        SecretRequest::CardPin {
            card_ident,
            key_info,
        } => {
            *card_ident_used.borrow_mut() = Some(card_ident.to_string());
            card_touch::maybe_notify_touch(TouchOp::Sign, Some(card_ident));
            let pin: Zeroizing<String> = prompt_card_pin(card_ident, key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            verify_card_pin(card_ident, &pin, &key_info.fingerprint)
                .map_err(|e| libtumpa::Error::Sign(format!("{e}")))?;
            let pin_bytes: Pin = Zeroizing::new(pin.as_bytes().to_vec());
            *last_secret.borrow_mut() = Some(pin);
            Ok(Secret::Pin(pin_bytes))
        }
        SecretRequest::KeyPassphrase { key_info } => {
            let pass: Passphrase = prompt_key_passphrase(key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            verify_software_passphrase(&key_data, &pass, &key_info.fingerprint)
                .map_err(|e| libtumpa::Error::Sign(format!("{e}")))?;
            *last_secret.borrow_mut() = Some(pass.clone());
            Ok(Secret::Passphrase(pass))
        }
    });

    let (signed, backend) = match result {
        Ok((bytes, backend)) => {
            if let Some(secret) = last_secret.borrow().as_ref() {
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
            return Err(anyhow!("{e}")).context("cleartext sign failed");
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
                "tcli: Cleartext-signed with card {} key {}",
                ident, key_info.fingerprint
            )?;
        }
        SignBackend::Software => {
            writeln!(
                err,
                "tcli: Cleartext-signed with software key {}",
                key_info.fingerprint
            )?;
        }
    }
    out.write_all(&signed)
        .context("Failed to write cleartext-signed message to stdout")?;

    // Intentionally do NOT emit a SIG_CREATED status line for cleartext
    // signatures. libtumpa's cleartext path doesn't surface the hash
    // algorithm it actually used, and the previous code hard-coded
    // SHA-256 (`hash_algo=8`) — that lies to PGP/MIME `micalg` parsers
    // when the key is RSA-3072+ / ECDSA P-384/P-521 and ends up using a
    // different digest. Cleartext signatures are not consumed by git's
    // gpg-interface either, so dropping the line is safe.

    Ok(())
}

/// Sign data from stdin and write an inline opaque signed message
/// (`gpg --sign` shape) to stdout.
///
/// Software-key only at this layer: libtumpa does not yet expose an
/// on-card inline-opaque signing primitive. (Detached signing and
/// [`clearsign`] both have card-first dispatch already.) When a
/// connected card is the only source for the signing key, the call
/// returns an error pointing the user at `--detach-sign`.
///
/// The output is an OpenPGP message containing one-pass-signature +
/// literal + signature packets; the recipient runs
/// `tclig --verify-decrypt` to recover the original bytes plus
/// signer identity.
pub fn sign_inline(
    mut data: impl Read,
    mut out: impl Write,
    mut err: impl Write,
    signer_id: &str,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    log::info!("sign_inline called for signer_id: {}", signer_id);

    let mut buffer = Vec::new();
    data.read_to_end(&mut buffer)
        .context("Failed to read data from stdin")?;

    let keystore = store::open_keystore(keystore_path)?;
    let (key_data, key_info) = store::resolve_signer(&keystore, signer_id)?;
    store::ensure_key_usable_for_signing(&key_info)?;

    if !key_info.is_secret {
        return Err(anyhow!(
            "inline signing requires a software secret key for {}; \
             card-only keys are not supported — use --detach-sign instead",
            key_info.fingerprint
        ));
    }

    let passphrase: Passphrase =
        prompt_key_passphrase(&key_info).map_err(|e| anyhow!("pinentry: {e}"))?;
    verify_software_passphrase(&key_data, &passphrase, &key_info.fingerprint)?;

    let signed = wecanencrypt::sign_bytes(&key_data, &buffer, passphrase.as_str())
        .map_err(|e| {
            pinentry::clear_cached_passphrase(&key_info.fingerprint);
            anyhow!("{e}")
        })
        .context("inline sign failed")?;
    pinentry::cache_passphrase(&key_info.fingerprint, &passphrase);

    writeln!(
        err,
        "tcli: Inline-signed with software key {}",
        key_info.fingerprint
    )?;
    out.write_all(&signed)
        .context("Failed to write inline-signed message to stdout")?;

    // Intentionally no SIG_CREATED line for inline-opaque signing —
    // same reasoning as `clearsign`: wecanencrypt's `sign_bytes` does
    // not expose the actual hash chosen, and emitting a hard-coded
    // SHA-256 ID would lie to any PGP/MIME `micalg` consumer.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SIG_CREATED status lines must use OpenPGP's registered hash
    /// IDs (RFC 4880 §9.4 plus crypto-refresh additions). PGP/MIME
    /// callers parse `<hash_algo>` to derive the `micalg` parameter;
    /// a wrong number here means clients reject the
    /// `multipart/signed` mail as malformed.
    #[test]
    fn gpg_hash_algo_id_matches_openpgp_registry() {
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha256), Some(8));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha384), Some(9));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha512), Some(10));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha224), Some(11));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha3_256), Some(12));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha3_512), Some(14));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Md5), Some(1));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha1), Some(2));
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Ripemd160), Some(3));
    }
}
