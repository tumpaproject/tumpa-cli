use std::path::PathBuf;

use anyhow::Result;

use crate::store;

/// Sanitize a UID string for colon-format output.
/// Strips control characters that could break the line-based format.
fn sanitize_uid(uid: &str) -> String {
    uid.chars().filter(|c| !c.is_control()).collect()
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
        println!(
            "{}:-:0:0:{}:{}:{}:::::{primary_caps}:",
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

        // Subkey lines
        for sk in &key.subkeys {
            if sk.is_revoked {
                continue;
            }
            let sk_creation = sk.creation_time.timestamp();
            let sk_expiry = sk
                .expiration_time
                .map(|t| t.timestamp().to_string())
                .unwrap_or_default();

            // Capabilities
            let caps = match sk.key_type {
                wecanencrypt::KeyType::Encryption => "e",
                wecanencrypt::KeyType::Signing => "s",
                wecanencrypt::KeyType::Authentication => "a",
                wecanencrypt::KeyType::Certification => "c",
                _ => "",
            };

            println!(
                "sub:-:0:0:{}:{}:{}:::::{}:",
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

        // sec line (12 fields)
        println!(
            "sec:-:0:0:{}:{}:::::::",
            key.key_id.to_uppercase(),
            creation_epoch,
        );

        // UID lines
        for uid in &key.user_ids {
            if !uid.revoked {
                println!("uid:-::::::::{}:", sanitize_uid(&uid.value));
            }
        }

        // Subkey lines
        for sk in &key.subkeys {
            if sk.is_revoked {
                continue;
            }
            let sk_creation = sk.creation_time.timestamp();
            let caps = match sk.key_type {
                wecanencrypt::KeyType::Encryption => "e",
                wecanencrypt::KeyType::Signing => "s",
                wecanencrypt::KeyType::Authentication => "a",
                wecanencrypt::KeyType::Certification => "c",
                _ => "",
            };

            println!(
                "ssb:-:0:0:{}:{}:::::{}:",
                sk.key_id.to_uppercase(),
                sk_creation,
                caps,
            );
        }
    }

    Ok(())
}

/// Output empty config (GPG --list-config --with-colons).
///
/// `pass` uses this to expand GPG groups. We don't support groups,
/// so return empty output.
pub fn list_config() -> Result<()> {
    // No groups defined -- pass will treat recipient IDs as literal key IDs
    Ok(())
}
