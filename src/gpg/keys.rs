use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::store;

/// Sanitize a UID string for colon-format output.
/// Strips control characters that could break the line-based format.
fn sanitize_uid(uid: &str) -> String {
    uid.chars().filter(|c| !c.is_control()).collect()
}

/// GnuPG colon-format validity character for the primary key.
///
/// Mirrors the subset of GPG's validity codes our consumers actually
/// check for — `r` revoked, `e` expired, `-` otherwise (unknown / OK,
/// since we don't compute owner trust). PGP/MIME callers (Tumpa Mail's
/// `ColonListingParser`) and `pass` both rely on `e`/`r` to skip
/// unusable keys at compose time; emitting `-` for an expired or
/// revoked key makes the caller think the key is fine, then the actual
/// encrypt fails with `INV_RECP` once `store::ensure_key_usable_*`
/// runs server-side. The validity field exists precisely to give the
/// caller a chance to filter unusable keys *before* the encrypt
/// attempt, so it must be honest.
fn primary_validity(is_revoked: bool, expiration_time: Option<DateTime<Utc>>) -> &'static str {
    if is_revoked {
        return "r";
    }
    if let Some(exp) = expiration_time {
        if exp <= Utc::now() {
            return "e";
        }
    }
    "-"
}

/// GnuPG colon-format validity character for a subkey.
///
/// Same rules as `primary_validity`, parameterized over the subkey's
/// own `is_revoked` / `expiration_time` rather than the primary's.
/// Subkey expiry is independent of primary expiry in OpenPGP, so the
/// caller computes both and the consumer (e.g. `pass`'s `grep ^sub:`)
/// gets per-subkey validity.
fn subkey_validity(is_revoked: bool, expiration_time: Option<DateTime<Utc>>) -> &'static str {
    primary_validity(is_revoked, expiration_time)
}

/// List keys in colon-delimited format (GPG --list-keys --with-colons).
///
/// `pass` parses this to find encryption subkey key IDs:
///   grep '^sub:...*e[a-zA-Z]*:' to extract encryption-capable subkey IDs.
pub fn list_keys_colon(key_ids: &[String], keystore_path: Option<&PathBuf>) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    let keys = if key_ids.is_empty() {
        keystore.list_keys()?
    } else {
        let mut results = Vec::new();
        for kid in key_ids {
            if let Ok((_, info)) = store::resolve_signer(&keystore, kid) {
                results.push(info);
            }
        }
        results
    };

    for key in &keys {
        let creation_epoch = key.creation_time.timestamp();
        let expiry_epoch = key
            .expiration_time
            .map(|t| t.timestamp().to_string())
            .unwrap_or_default();

        // Primary key line -- always "pub" for --list-keys (even if we have the secret).
        // GPG's --list-keys uses pub/sub; only --list-secret-keys uses sec/ssb.
        // pass greps for ^sub: lines, so we must use "sub" not "ssb".
        let key_type = "pub";
        // Field 12: capabilities of primary key
        let mut primary_caps = String::new();
        if key.can_primary_sign {
            primary_caps.push('s');
        }
        primary_caps.push('c'); // primary can always certify

        // GnuPG colon format: 12 fields
        // 1:type 2:validity 3:keylength 4:algo 5:keyid 6:creation 7:expiry
        // 8:trust 9:ownertrust 10:uid 11:sigclass 12:capabilities
        let validity = primary_validity(key.is_revoked, key.expiration_time);
        println!(
            "{}:{validity}:0:0:{}:{}:{}:::::{primary_caps}:",
            key_type,
            key.key_id.to_uppercase(),
            creation_epoch,
            expiry_epoch,
        );

        // UID lines
        for uid in &key.user_ids {
            if !uid.revoked {
                println!("uid:-::::::::{}:", sanitize_uid(&uid.value));
            }
        }

        // Subkey lines. Revoked subkeys stay in the listing with
        // validity "r" — GnuPG's colon format keeps them, and the
        // validity field is the documented filter knob for callers
        // (Mail's recipient picker, pass) so they can skip unusable
        // subkeys without re-querying the keystore.
        for sk in &key.subkeys {
            let sk_creation = sk.creation_time.timestamp();
            let sk_expiry = sk
                .expiration_time
                .map(|t| t.timestamp().to_string())
                .unwrap_or_default();
            let sk_validity = subkey_validity(sk.is_revoked, sk.expiration_time);

            // Capabilities
            let caps = match sk.key_type {
                wecanencrypt::KeyType::Encryption => "e",
                wecanencrypt::KeyType::Signing => "s",
                wecanencrypt::KeyType::Authentication => "a",
                wecanencrypt::KeyType::Certification => "c",
                _ => "",
            };

            println!(
                "sub:{sk_validity}:0:0:{}:{}:{}:::::{}:",
                sk.key_id.to_uppercase(),
                sk_creation,
                sk_expiry,
                caps,
            );
        }
    }

    Ok(())
}

/// List secret keys in colon-delimited format (GPG --list-secret-keys --with-colons).
///
/// `pass` bash completion parses field 10 (UID) from these lines.
pub fn list_secret_keys_colon(keystore_path: Option<&PathBuf>) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let keys = keystore.list_secret_keys()?;

    for key in &keys {
        let creation_epoch = key.creation_time.timestamp();
        let validity = primary_validity(key.is_revoked, key.expiration_time);

        // sec line (12 fields)
        println!(
            "sec:{validity}:0:0:{}:{}:::::::",
            key.key_id.to_uppercase(),
            creation_epoch,
        );

        // UID lines
        for uid in &key.user_ids {
            if !uid.revoked {
                println!("uid:-::::::::{}:", sanitize_uid(&uid.value));
            }
        }

        // Subkey lines. Revoked subkeys stay in the listing with
        // validity "r" (matches GnuPG); see list_keys_colon for the
        // rationale.
        for sk in &key.subkeys {
            let sk_creation = sk.creation_time.timestamp();
            let sk_validity = subkey_validity(sk.is_revoked, sk.expiration_time);
            let caps = match sk.key_type {
                wecanencrypt::KeyType::Encryption => "e",
                wecanencrypt::KeyType::Signing => "s",
                wecanencrypt::KeyType::Authentication => "a",
                wecanencrypt::KeyType::Certification => "c",
                _ => "",
            };

            println!(
                "ssb:{sk_validity}:0:0:{}:{}:::::{}:",
                sk.key_id.to_uppercase(),
                sk_creation,
                caps,
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn primary_validity_handles_revoked_expired_and_ok() {
        let now = Utc::now();
        // Revoked beats everything else.
        assert_eq!(primary_validity(true, None), "r");
        assert_eq!(primary_validity(true, Some(now + Duration::days(30))), "r");
        // Expired key with past expiration_time.
        assert_eq!(primary_validity(false, Some(now - Duration::days(1))), "e");
        // Future expiration_time.
        assert_eq!(primary_validity(false, Some(now + Duration::days(30))), "-");
        // No expiration set.
        assert_eq!(primary_validity(false, None), "-");
    }

    #[test]
    fn primary_validity_treats_now_as_expired() {
        // A key whose expiration time is exactly now is no longer
        // usable. Lean on the inclusive `<=` boundary.
        let exp = Utc::now();
        assert_eq!(primary_validity(false, Some(exp)), "e");
    }

    #[test]
    fn subkey_validity_uses_subkey_fields() {
        // Subkey expired but primary is fine — subkey listing must
        // surface the subkey's own validity, not the primary's, so
        // recipient pickers (like Tumpa Mail's compose UI) skip the
        // subkey rather than greenlighting an encrypt that will fail.
        let past = Utc::now() - Duration::days(7);
        assert_eq!(subkey_validity(false, Some(past)), "e");
        assert_eq!(subkey_validity(true, Some(past)), "r");
    }
}

/// Output empty config (GPG --list-config --with-colons).
///
/// `pass` uses this to expand GPG groups. We don't support groups,
/// so return empty output.
pub fn list_config() -> Result<()> {
    // No groups defined -- pass will treat recipient IDs as literal key IDs
    Ok(())
}
