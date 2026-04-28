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

use crate::pinentry;
use crate::store;

/// Map a `HashAlgorithm` to the GnuPG numeric ID used in `[GNUPG:]
/// SIG_CREATED` status lines (RFC 4880 §9.4).
fn gpg_hash_algo_id(alg: HashAlgorithm) -> u8 {
    match alg {
        HashAlgorithm::Sha256 => 8,
        HashAlgorithm::Sha384 => 9,
        HashAlgorithm::Sha512 => 10,
        HashAlgorithm::Sha224 => 11,
        HashAlgorithm::Sha3_256 => 12,
        HashAlgorithm::Sha3_512 => 14,
        HashAlgorithm::Md5 => 1,
        HashAlgorithm::Sha1 => 2,
        HashAlgorithm::Ripemd160 => 3,
        _ => 0,
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
    let hash_id = gpg_hash_algo_id(sign_result.hash_algorithm);
    writeln!(
        err,
        "\n[GNUPG:] SIG_CREATED D 0 {hash_id} 00 0 {}",
        key_info.fingerprint
    )?;

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
            let pin: Zeroizing<String> = prompt_card_pin(card_ident, key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
            let pin_bytes: Pin = Zeroizing::new(pin.as_bytes().to_vec());
            *last_secret.borrow_mut() = Some(pin);
            Ok(Secret::Pin(pin_bytes))
        }
        SecretRequest::KeyPassphrase { key_info } => {
            let pass: Passphrase = prompt_key_passphrase(key_info)
                .map_err(|e| libtumpa::Error::Sign(format!("pinentry: {e}")))?;
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

    // Cleartext sigs use the hash the signing key's params imply (SHA256
    // for our default Ed25519 / RSA keys, larger for ECDSA P-384/P-521).
    // We don't get the actual hash back from the cleartext path, so emit
    // an informational SIG_CREATED line keyed to SHA256 — git-on-PGP/MIME
    // callers don't consume cleartext-sig status anyway.
    writeln!(
        err,
        "\n[GNUPG:] SIG_CREATED C 0 8 00 0 {}",
        key_info.fingerprint
    )?;

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
/// `tclig --decrypt --verify` to recover the original bytes plus
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
    writeln!(
        err,
        "\n[GNUPG:] SIG_CREATED S 0 8 00 0 {}",
        key_info.fingerprint
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SIG_CREATED status lines must use GnuPG's RFC 4880 §9.4 hash IDs.
    /// PGP/MIME callers parse `<hash_algo>` to derive the `micalg`
    /// parameter; a wrong number here means clients reject the
    /// `multipart/signed` mail as malformed.
    #[test]
    fn gpg_hash_algo_id_matches_rfc4880() {
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha256), 8);
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha384), 9);
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha512), 10);
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha224), 11);
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Md5), 1);
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Sha1), 2);
        assert_eq!(gpg_hash_algo_id(HashAlgorithm::Ripemd160), 3);
    }
}
