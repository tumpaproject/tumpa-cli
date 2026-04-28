//! GPG-shape encrypt: read input file/stdin, resolve each recipient with
//! per-recipient `INV_RECP` status reporting, then delegate the actual
//! encryption to wecanencrypt. Optionally sign-then-encrypt in a single
//! OpenPGP message when a signer is supplied.
//!
//! Card-first dispatch on the signing leg: if the signer's key has a
//! matching connected card, the inner signature is produced on the card;
//! otherwise the software secret key (with passphrase) is used.
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use libtumpa::store as ltstore;
use libtumpa::{Passphrase, Pin};
use zeroize::Zeroizing;

use crate::gpg::sign::{prompt_card_pin, prompt_key_passphrase};
use crate::pinentry;
use crate::store;

/// Encrypt data to one or more recipients, optionally with an inner
/// signature.
///
/// Reads plaintext from `input` (file path or stdin if None), encrypts
/// to all recipients, and writes ciphertext to `output`. When
/// `signer_id` is provided, sign-then-encrypts (producing a single
/// OpenPGP message containing one-pass-signature + literal +
/// signature packets — what `gpg --sign --encrypt` produces). The
/// signing leg is card-first at this layer: if the signer's key has a
/// matching connected card, the inner signature is produced on-card;
/// otherwise the software secret key is used (with passphrase).
///
/// Per-recipient resolution failures are reported on stderr as
/// `[GNUPG:] INV_RECP 0 <recipient>` lines (GnuPG-compatible) before
/// the operation aborts, so PGP/MIME callers can show "no key for X"
/// in the compose UI.
pub fn encrypt(
    input: Option<&PathBuf>,
    output: &PathBuf,
    recipients: &[String],
    armor: bool,
    signer_id: Option<&str>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    encrypt_with_status(
        input,
        output,
        recipients,
        armor,
        signer_id,
        keystore_path,
        std::io::stderr(),
    )
}

/// Like [`encrypt`] but with an injectable status sink, for testability.
pub fn encrypt_with_status(
    input: Option<&PathBuf>,
    output: &PathBuf,
    recipients: &[String],
    armor: bool,
    signer_id: Option<&str>,
    keystore_path: Option<&PathBuf>,
    mut status_out: impl Write,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    // Resolve all recipients up front so we can emit INV_RECP for each
    // failure, instead of bailing on the first one. The Mail extension
    // shows a per-recipient warning in the compose pane based on this.
    let mut resolved: Vec<Vec<u8>> = Vec::with_capacity(recipients.len());
    let mut failed: Vec<&str> = Vec::new();

    for r in recipients {
        match ltstore::resolve_recipient(&keystore, r) {
            Ok((data, info)) => match ltstore::ensure_key_usable_for_encryption(&info) {
                Ok(()) => resolved.push(data),
                Err(_unusable) => {
                    // Revoked / expired / no encryption-capable subkey:
                    // GnuPG also reports these as INV_RECP.
                    emit_inv_recp(&mut status_out, r)?;
                    failed.push(r);
                }
            },
            Err(_) => {
                emit_inv_recp(&mut status_out, r)?;
                failed.push(r);
            }
        }
    }

    if !failed.is_empty() {
        anyhow::bail!("no usable key for recipient(s): {}", failed.join(", "));
    }

    let plaintext = match input {
        Some(path) => {
            std::fs::read(path).context(format!("Failed to read input file {:?}", path))?
        }
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("Failed to read from stdin")?;
            buf
        }
    };

    let key_refs: Vec<&[u8]> = resolved.iter().map(|d| d.as_slice()).collect();

    let ciphertext = match signer_id {
        Some(id) => sign_and_encrypt_dispatch(&keystore, id, &key_refs, &plaintext, armor)?,
        None => wecanencrypt::encrypt_bytes_to_multiple(&key_refs, &plaintext, armor)
            .map_err(|e| anyhow!("{e}"))
            .context("Encryption failed")?,
    };

    std::fs::write(output, &ciphertext)
        .context(format!("Failed to write output file {:?}", output))?;

    Ok(())
}

/// Resolve `signer_id`, dispatch the signing leg to a connected card when
/// available, otherwise fall back to a software secret key with passphrase.
///
/// Mirrors the card-first / software-fallback dispatch already used by the
/// detached signing path (`gpg::sign::sign`), so a sign+encrypt with a
/// YubiKey behaves the same as a `--detach-sign` with the same key.
fn sign_and_encrypt_dispatch(
    keystore: &wecanencrypt::KeyStore,
    signer_id: &str,
    recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let (key_data, key_info) = store::resolve_signer(keystore, signer_id)?;
    store::ensure_key_usable_for_signing(&key_info)?;

    // Try a connected card first.
    let card_attempt = match libtumpa::encrypt::find_signing_card_for_encrypt(&key_data) {
        Ok(Some(m)) => {
            let card_ident = m.card.ident.clone();
            let pin: Zeroizing<String> =
                prompt_card_pin(&card_ident, &key_info).map_err(|e| anyhow!("pinentry: {e}"))?;
            let pin_obj: Pin = Zeroizing::new(pin.as_bytes().to_vec());
            match wecanencrypt::card::sign_and_encrypt_to_multiple_on_card(
                &key_data,
                pin_obj.as_slice(),
                Some(&card_ident),
                recipient_keys,
                plaintext,
                armor,
            ) {
                Ok(ct) => {
                    pinentry::cache_pin(&key_info.fingerprint, &pin);
                    return Ok(ct);
                }
                Err(e) => {
                    pinentry::clear_cached_pin(&key_info.fingerprint);
                    Some(anyhow!("card sign+encrypt failed: {e}"))
                }
            }
        }
        Ok(None) => None,
        Err(e) => {
            log::info!(
                "could not enumerate smartcards ({e}); skipping card path, trying software key"
            );
            None
        }
    };

    // Software fallback.
    if !key_info.is_secret {
        let msg = match card_attempt {
            Some(card_err) => format!(
                "sign+encrypt: no software secret key available for {} ({card_err})",
                key_info.fingerprint
            ),
            None => format!(
                "sign+encrypt requires a software secret key for {} \
                 and no matching card was found",
                key_info.fingerprint
            ),
        };
        return Err(anyhow!(msg));
    }

    let passphrase: Passphrase =
        prompt_key_passphrase(&key_info).map_err(|e| anyhow!("pinentry: {e}"))?;

    let ciphertext = wecanencrypt::sign_and_encrypt_to_multiple(
        &key_data,
        passphrase.as_str(),
        recipient_keys,
        plaintext,
        armor,
    )
    .map_err(|e| {
        // Stale cached passphrase is the most common cause of a
        // sign step failing here; clear it so the next attempt
        // re-prompts cleanly.
        pinentry::clear_cached_passphrase(&key_info.fingerprint);
        match card_attempt {
            Some(card_err) => anyhow!("software fallback failed: {e}; {card_err}"),
            None => anyhow!("{e}"),
        }
    })
    .context("Sign-then-encrypt failed")?;

    pinentry::cache_passphrase(&key_info.fingerprint, &passphrase);
    Ok(ciphertext)
}

/// Sanitize a recipient string before emitting it on a `[GNUPG:]`
/// status line. The recipient comes from user input (CLI / Mail
/// compose) and could contain `\n` or other control characters that
/// would inject extra status lines downstream — same threat model as
/// `libtumpa::verify::sanitize_uid_for_status`.
fn emit_inv_recp(status_out: &mut impl Write, recipient: &str) -> std::io::Result<()> {
    let safe: String = recipient.chars().filter(|c| !c.is_control()).collect();
    writeln!(status_out, "[GNUPG:] INV_RECP 0 {safe}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;
    use wecanencrypt::create_key_simple;

    fn fresh_keystore() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.db");
        (dir, path)
    }

    /// Unknown recipient produces `INV_RECP 0 <recipient>` and aborts
    /// without writing the output file.
    #[test]
    fn unknown_recipient_emits_inv_recp() {
        let (_tmp, ks_path) = fresh_keystore();
        let out_path = ks_path.parent().unwrap().join("out.asc");

        let mut status: Vec<u8> = Vec::new();
        let err = encrypt_with_status(
            None,
            &out_path,
            &["nobody@example.com".to_string()],
            true,
            None,
            Some(&ks_path),
            &mut status,
        )
        .unwrap_err();

        let s = String::from_utf8(status).unwrap();
        assert!(
            s.contains("[GNUPG:] INV_RECP 0 nobody@example.com"),
            "status output missing INV_RECP: {s:?}"
        );
        // Bail-out message names the recipient too, for human stderr.
        assert!(err.to_string().contains("nobody@example.com"));
        assert!(
            !out_path.exists(),
            "output should not be written when any recipient is invalid"
        );
    }

    /// Multiple invalid recipients each get their own INV_RECP line —
    /// GnuPG behavior, lets the Mail extension annotate every chip in
    /// the compose pane.
    #[test]
    fn multiple_unknown_recipients_each_get_inv_recp() {
        let (_tmp, ks_path) = fresh_keystore();
        let out_path = ks_path.parent().unwrap().join("out.asc");

        let mut status: Vec<u8> = Vec::new();
        let _ = encrypt_with_status(
            None,
            &out_path,
            &[
                "alice@nope.com".to_string(),
                "bob@nope.com".to_string(),
                "carol@nope.com".to_string(),
            ],
            true,
            None,
            Some(&ks_path),
            &mut status,
        );

        let s = String::from_utf8(status).unwrap();
        for who in ["alice@nope.com", "bob@nope.com", "carol@nope.com"] {
            assert!(
                s.contains(&format!("[GNUPG:] INV_RECP 0 {who}")),
                "missing INV_RECP for {who} in: {s}"
            );
        }
    }

    /// Recipient name with embedded newline must be sanitized so the
    /// attacker can't inject a forged `[GNUPG:] VALIDSIG` line via the
    /// recipient CLI argument.
    #[test]
    fn inv_recp_strips_control_chars_from_recipient() {
        let mut buf = Cursor::new(Vec::new());
        emit_inv_recp(
            &mut buf,
            "evil@example.com\n[GNUPG:] VALIDSIG forged-fingerprint",
        )
        .unwrap();
        let s = String::from_utf8(buf.into_inner()).unwrap();
        // Exactly one line emitted.
        assert_eq!(s.matches('\n').count(), 1, "got: {s:?}");
        // The single line must start with INV_RECP, not VALIDSIG.
        assert!(s.starts_with("[GNUPG:] INV_RECP 0"));
    }

    /// Happy path: a known recipient encrypts successfully and no
    /// INV_RECP lines are emitted.
    #[test]
    fn known_recipient_no_inv_recp() {
        let (_tmp, ks_path) = fresh_keystore();
        let out_path = ks_path.parent().unwrap().join("out.asc");
        let plaintext_path = ks_path.parent().unwrap().join("plain.txt");
        std::fs::write(&plaintext_path, b"hello").unwrap();

        // Open the keystore and import a fresh public key.
        let keystore = wecanencrypt::KeyStore::open(&ks_path).unwrap();
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        keystore.import_key(alice.public_key.as_bytes()).unwrap();
        drop(keystore);

        let mut status: Vec<u8> = Vec::new();
        encrypt_with_status(
            Some(&plaintext_path),
            &out_path,
            &["alice@example.com".to_string()],
            true,
            None,
            Some(&ks_path),
            &mut status,
        )
        .unwrap();

        assert!(out_path.exists());
        let s = String::from_utf8(status).unwrap();
        assert!(
            !s.contains("INV_RECP"),
            "no INV_RECP expected on success: {s}"
        );
    }

    /// Sign+encrypt without `-u` is a usage error caught at the CLI
    /// parser layer; confirm the encrypt fn itself falls through to
    /// encrypt-only when `signer_id` is `None`.
    #[test]
    fn signer_id_none_uses_encrypt_only_path() {
        let (_tmp, ks_path) = fresh_keystore();
        let out_path = ks_path.parent().unwrap().join("ct.asc");
        let pt_path = ks_path.parent().unwrap().join("plain.txt");
        std::fs::write(&pt_path, b"plain").unwrap();

        let keystore = wecanencrypt::KeyStore::open(&ks_path).unwrap();
        let bob = create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
        keystore.import_key(bob.public_key.as_bytes()).unwrap();
        drop(keystore);

        let mut status: Vec<u8> = Vec::new();
        encrypt_with_status(
            Some(&pt_path),
            &out_path,
            &["bob@example.com".to_string()],
            true,
            None, // no signer
            Some(&ks_path),
            &mut status,
        )
        .unwrap();

        assert!(out_path.exists());
    }

    /// `TUMPA_PASSPHRASE` is process-global, so any test that sets it
    /// must serialize against any other such test in this binary. We
    /// don't hold the lock for tests that don't touch the env var.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard: set `TUMPA_PASSPHRASE` for the duration of the
    /// test, then remove it even on panic. The guard pairs with
    /// `ENV_LOCK` so the set/remove window is exclusive.
    struct PassphraseEnvGuard;
    impl PassphraseEnvGuard {
        fn set(value: &str) -> Self {
            std::env::set_var("TUMPA_PASSPHRASE", value);
            Self
        }
    }
    impl Drop for PassphraseEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("TUMPA_PASSPHRASE");
        }
    }

    /// Software sign+encrypt: with no card connected, the dispatch
    /// must fall back to the software secret key, sign, then encrypt
    /// to the recipient. Round-trip via `decrypt_and_verify` and
    /// confirm the inner signature is `Good` and the verifier is the
    /// signer we asked for. This pins the card-first/software-
    /// fallback contract called out in the doc comment.
    #[test]
    fn software_sign_and_encrypt_round_trips() {
        let _env_guard = ENV_LOCK.lock().unwrap();
        let _passphrase_guard = PassphraseEnvGuard::set("pw");

        let (_tmp, ks_path) = fresh_keystore();
        let out_path = ks_path.parent().unwrap().join("ct.asc");
        let pt_path = ks_path.parent().unwrap().join("plain.txt");
        std::fs::write(&pt_path, b"hello over signed channel").unwrap();

        // Recipient (Bob) — secret needed so the test can decrypt and
        // verify the result without involving libtumpa's card paths.
        let bob = create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
        // Signer (Alice) — secret in the keystore so software fallback
        // can sign with `TUMPA_PASSPHRASE`.
        let alice = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();

        let keystore = wecanencrypt::KeyStore::open(&ks_path).unwrap();
        keystore.import_key(&bob.secret_key).unwrap();
        keystore.import_key(&alice.secret_key).unwrap();
        drop(keystore);

        let mut status: Vec<u8> = Vec::new();
        encrypt_with_status(
            Some(&pt_path),
            &out_path,
            &["bob@example.com".to_string()],
            true,
            Some(&alice.fingerprint),
            Some(&ks_path),
            &mut status,
        )
        .unwrap();

        assert!(out_path.exists(), "ciphertext must be produced");
        let s = String::from_utf8(status).unwrap();
        assert!(!s.contains("INV_RECP"), "no recipient errors: {s}");

        // Round-trip: decrypt with Bob's secret and verify the inner
        // signature was produced by Alice. This is the property that
        // distinguishes sign+encrypt from encrypt-only.
        let ciphertext = std::fs::read(&out_path).unwrap();
        let bob_passphrase: libtumpa::Passphrase =
            zeroize::Zeroizing::new("pw".to_string());
        let store = wecanencrypt::KeyStore::open(&ks_path).unwrap();
        let result = libtumpa::decrypt::decrypt_and_verify_with_key(
            &store,
            &bob.secret_key,
            &ciphertext,
            &bob_passphrase,
        )
        .expect("decrypt+verify should succeed for sign+encrypt output");

        assert_eq!(
            &*result.plaintext,
            b"hello over signed channel",
            "round-tripped plaintext mismatch"
        );
        match result.outcome {
            libtumpa::decrypt::DecryptVerifyOutcome::Good {
                key_info,
                verifier_fingerprint,
            } => {
                // `key_info.fingerprint` is the primary cert
                // fingerprint; `verifier_fingerprint` is the actual
                // signing key, which for keys produced by
                // `create_key_simple` is a *signing subkey* — those
                // two values are not equal in general. Pin the
                // primary, since that's what identifies the signer
                // to a human / to the keystore.
                assert_eq!(
                    key_info.fingerprint.to_uppercase(),
                    alice.fingerprint.to_uppercase(),
                    "inner signature must resolve to Alice's primary cert"
                );
                // Sanity: the verifier fingerprint is some 40-char
                // hex value (either the primary or one of Alice's
                // signing subkeys). We don't pin which, only that
                // it's well-formed.
                assert_eq!(verifier_fingerprint.len(), 40, "got {verifier_fingerprint}");
                assert!(
                    verifier_fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
                    "got {verifier_fingerprint}"
                );
            }
            other => panic!("expected Good signature outcome, got {other:?}"),
        }
    }
}
