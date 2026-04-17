use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::store;

/// Import keys from files or directories.
pub fn cmd_import(paths: &[PathBuf], recursive: bool, keystore_path: Option<&PathBuf>) -> Result<()> {
    log::debug!(
        "cmd_import: paths={} recursive={} keystore_path={:?}",
        paths.len(),
        recursive,
        keystore_path,
    );
    let keystore = store::open_keystore(keystore_path)?;

    let mut imported = 0u32;
    let mut updated = 0u32;
    let mut failed = 0u32;

    for path in paths {
        log::debug!("cmd_import: processing {:?} (is_dir={})", path, path.is_dir());
        if path.is_dir() {
            import_dir(&keystore, path, recursive, &mut imported, &mut updated, &mut failed)?;
        } else {
            import_file(&keystore, path, &mut imported, &mut updated, &mut failed);
        }
    }

    log::debug!(
        "cmd_import: done imported={} updated={} failed={}",
        imported, updated, failed,
    );
    println!("Imported {} new, {} updated, {} failed.", imported, updated, failed);
    Ok(())
}

fn import_dir(
    keystore: &wecanencrypt::KeyStore,
    dir: &Path,
    recursive: bool,
    imported: &mut u32,
    updated: &mut u32,
    failed: &mut u32,
) -> Result<()> {
    log::debug!("import_dir: scanning {:?} recursive={}", dir, recursive);
    let entries = std::fs::read_dir(dir)
        .context(format!("Failed to read directory {:?}", dir))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() && recursive {
            import_dir(keystore, &path, recursive, imported, updated, failed)?;
        } else if path.is_file() && is_key_file(&path) {
            import_file(keystore, &path, imported, updated, failed);
        } else {
            log::trace!("import_dir: skipping {:?}", path);
        }
    }

    Ok(())
}

fn is_key_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("asc" | "gpg" | "pub" | "key" | "pgp")
    )
}

fn import_file(
    keystore: &wecanencrypt::KeyStore,
    path: &Path,
    imported: &mut u32,
    updated: &mut u32,
    failed: &mut u32,
) {
    log::debug!("import_file: {:?}", path);
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            log::error!("import_file: read failed for {:?}: {:#}", path, e);
            eprintln!("Failed to read {:?}: {:#}", path, e);
            *failed += 1;
            return;
        }
    };
    log::debug!("import_file: read {} bytes from {:?}", data.len(), path);

    // If the key already exists, merge new signatures into the stored key
    match wecanencrypt::parse_key_bytes(&data, false) {
        Ok(key_info) => {
            log::debug!(
                "import_file: parsed {:?} fp={} secret={} uids={} subkeys={}",
                path,
                key_info.fingerprint,
                key_info.is_secret,
                key_info.user_ids.len(),
                key_info.subkeys.len(),
            );
            let already_present = match keystore.contains(&key_info.fingerprint) {
                Ok(b) => {
                    log::debug!("import_file: contains({})={}", key_info.fingerprint, b);
                    b
                }
                Err(e) => {
                    log::error!(
                        "import_file: contains({}) failed: {:#}",
                        key_info.fingerprint,
                        e,
                    );
                    false
                }
            };
            if already_present {
                let uid = key_info
                    .user_ids
                    .first()
                    .map(|u| u.value.as_str())
                    .unwrap_or("");
                match merge_and_reimport(keystore, &key_info.fingerprint, &data) {
                    Ok(true) => {
                        log::info!("import_file: merged fp={} (changed)", key_info.fingerprint);
                        println!("Updated {} ({}) — merged new signatures", key_info.fingerprint, uid);
                        *updated += 1;
                    }
                    Ok(false) => {
                        log::info!("import_file: merged fp={} (no change)", key_info.fingerprint);
                        println!("Unchanged {} ({}) — no new data", key_info.fingerprint, uid);
                        *updated += 1;
                    }
                    Err(e) => {
                        log::error!("import_file: merge failed for {:?}: {:#}", path, e);
                        eprintln!("Failed to merge {:?}: {:#}", path, e);
                        *failed += 1;
                    }
                }
                return;
            }
        }
        Err(e) => {
            log::debug!(
                "import_file: parse_key_bytes failed for {:?}: {:#} (falling through to raw import)",
                path,
                e,
            );
        }
    }

    match keystore.import_key(&data) {
        Ok(fp) => {
            let info = keystore.get_key_info(&fp).ok();
            let uid = info
                .and_then(|i| i.user_ids.first().map(|u| u.value.clone()))
                .unwrap_or_default();
            log::info!("import_file: imported fp={}", fp);
            println!("Imported {} ({})", fp, uid);
            *imported += 1;
        }
        Err(e) => {
            log::error!("import_file: import_key failed for {:?}: {:#}", path, e);
            eprintln!("Failed to import {:?}: {:#}", path, e);
            *failed += 1;
        }
    }
}

/// Merge new key data into an existing keystore entry.
/// Returns Ok(true) if the merge produced changes, Ok(false) if identical.
fn merge_and_reimport(
    keystore: &wecanencrypt::KeyStore,
    fingerprint: &str,
    new_data: &[u8],
) -> Result<bool> {
    let existing = keystore.export_key(fingerprint)?;
    let merged = wecanencrypt::merge_keys(&existing, new_data)
        .context("Key merge failed")?;

    // Re-import the merged key (INSERT OR REPLACE updates the row)
    keystore.import_key(&merged)?;
    Ok(existing != *merged)
}

/// Export a key from the keystore.
pub fn cmd_export(
    key_id: &str,
    _armor: bool,
    binary: bool,
    output: Option<&PathBuf>,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let (_key_data, key_info) = store::resolve_signer(&keystore, key_id)?;

    if binary {
        // Parse the stored key and re-serialize as binary OpenPGP packets
        use pgp::composed::Deserializable;
        use pgp::ser::Serialize;
        let raw = keystore.export_key(&key_info.fingerprint)?;
        let cursor = std::io::Cursor::new(&raw);
        let data = if let Ok((pk, _)) = pgp::composed::SignedPublicKey::from_armor_single(cursor) {
            let mut buf = Vec::new();
            pk.to_writer(&mut buf).context("Failed to serialize as binary")?;
            buf
        } else {
            raw // Already binary
        };
        match output {
            Some(path) => {
                std::fs::write(path, &data)?;
                eprintln!("Exported {} to {:?}", key_info.fingerprint, path);
            }
            None => {
                io::stdout().write_all(&data)?;
            }
        }
    } else {
        // Default: armored
        let armored = keystore.export_key_armored(&key_info.fingerprint)?;
        match output {
            Some(path) => {
                std::fs::write(path, &armored)?;
                eprintln!("Exported {} to {:?}", key_info.fingerprint, path);
            }
            None => {
                print!("{}", armored);
            }
        }
    }

    Ok(())
}

/// Show detailed information about a key.
pub fn cmd_info(key_id: &str, keystore_path: Option<&PathBuf>) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let (key_data, key_info) = store::resolve_signer(&keystore, key_id)?;
    print_key_info(&key_data, &key_info);
    Ok(())
}

/// Show detailed information about a key file without importing it.
///
/// Parses the key bytes directly and reuses the same renderer as
/// `--info`. Accepts both armored and binary, and both public and
/// secret key files. Never touches the keystore.
pub fn cmd_desc(path: &Path) -> Result<()> {
    let key_data =
        std::fs::read(path).with_context(|| format!("Failed to read {:?}", path))?;
    let key_info = wecanencrypt::parse_key_bytes(&key_data, false)
        .with_context(|| format!("Failed to parse key from {:?}", path))?;
    print_key_info(&key_data, &key_info);
    Ok(())
}

/// Print detailed key information.
fn print_key_info(key_data: &[u8], key_info: &wecanencrypt::KeyInfo) {
    let key_type = if key_info.is_secret { "sec" } else { "pub" };
    let time_fmt = "%Y-%m-%d %H:%M:%S UTC";

    // Get primary key algorithm details
    let primary_algo = wecanencrypt::get_key_cipher_details(key_data)
        .ok()
        .and_then(|details| details.into_iter().next())
        .map(|d| format_algo(&d.algorithm, d.bit_length))
        .unwrap_or_default();

    // Primary key capabilities
    let mut primary_caps = Vec::new();
    if key_info.can_primary_sign {
        primary_caps.push("sign");
    }
    primary_caps.push("certify"); // primary can always certify

    println!(
        "{}  {}  {}  [{}]",
        key_type,
        key_info.fingerprint,
        primary_algo,
        primary_caps.join(", ")
    );
    println!(
        "     Created:  {}",
        key_info.creation_time.format(time_fmt)
    );
    if let Some(ref exp) = key_info.expiration_time {
        println!("     Expires:  {}", exp.format(time_fmt));
    } else {
        println!("     Expires:  never");
    }

    if key_info.is_revoked {
        if let Some(ref rev_time) = key_info.revocation_time {
            println!("     Revoked:  {}", rev_time.format(time_fmt));
        } else {
            println!("     Revoked:  yes");
        }
    }

    // UIDs (primary first)
    let mut uids: Vec<_> = key_info.user_ids.iter().filter(|u| !u.revoked).collect();
    uids.sort_by_key(|u| std::cmp::Reverse(u.is_primary));

    if !uids.is_empty() {
        println!("     UIDs:");
        for uid in &uids {
            let prefix = if uid.is_primary {
                "[primary] "
            } else {
                "          "
            };
            println!("       {}{}", prefix, uid.value);
        }
    }

    // Subkeys
    if !key_info.subkeys.is_empty() {
        println!("     Subkeys:");
        for sk in &key_info.subkeys {
            let revoked = if sk.is_revoked { " [REVOKED]" } else { "" };
            let algo = format_algo(&sk.algorithm, sk.bit_length);
            let expiry = sk
                .expiration_time
                .map(|t| format!("\n                 Expires:  {}", t.format(time_fmt)))
                .unwrap_or_default();
            println!(
                "       {}  {}  [{}]{}",
                sk.fingerprint,
                algo,
                sk.key_type,
                revoked
            );
            println!(
                "                 Created:  {}{}",
                sk.creation_time.format(time_fmt),
                expiry
            );
        }
    }
}

fn format_algo(algorithm: &str, bit_length: usize) -> String {
    if bit_length > 0 {
        format!("{}{}", algorithm, bit_length)
    } else {
        algorithm.to_string()
    }
}

/// Delete a key from the keystore.
pub fn cmd_delete(key_id: &str, force: bool, keystore_path: Option<&PathBuf>) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let (_key_data, key_info) = store::resolve_signer(&keystore, key_id)?;

    let uid = key_info
        .user_ids
        .first()
        .map(|u| u.value.as_str())
        .unwrap_or("<no UID>");

    if !force {
        eprint!(
            "Delete {} {} ({})? [y/N] ",
            if key_info.is_secret { "SECRET key" } else { "public key" },
            key_info.fingerprint,
            uid
        );
        io::stderr().flush()?;
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        if !matches!(response.trim(), "y" | "Y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    keystore.delete_key(&key_info.fingerprint)?;
    println!("Deleted {} ({})", key_info.fingerprint, uid);

    Ok(())
}

/// Search for keys by name or email.
pub fn cmd_search(query: &str, email: bool, keystore_path: Option<&PathBuf>) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    let results = if email {
        keystore.search_by_email(query)?
    } else {
        keystore.search_by_uid(query)?
    };

    if results.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    for key in &results {
        let marker = if key.is_secret { "sec" } else { "pub" };
        let uid = key
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or("<no UID>");
        println!("{} {} {}", marker, key.fingerprint, uid);
    }

    println!("\n{} key(s) found.", results.len());

    Ok(())
}

/// Fetch and import a key via WKD.
pub fn cmd_fetch(email: &str, dry_run: bool, keystore_path: Option<&PathBuf>) -> Result<()> {
    eprintln!("Fetching key for {} via WKD...", email);

    let key_data = wecanencrypt::fetch_key_by_email(email)
        .context(format!("WKD lookup failed for {}", email))?;

    let key_info = wecanencrypt::parse_key_bytes(&key_data, false)?;

    print_key_info(&key_data, &key_info);

    if dry_run {
        return Ok(());
    }

    // Import or merge
    let keystore = store::open_keystore(keystore_path)?;
    let already_exists = keystore.contains(&key_info.fingerprint)?;

    let uid = key_info
        .user_ids
        .first()
        .map(|u| u.value.as_str())
        .unwrap_or("<no UID>");

    if already_exists {
        eprint!("\nKey already in keystore. Merge updates? [y/N] ");
    } else {
        eprint!("\nImport this key? [y/N] ");
    }
    io::stderr().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    if !matches!(response.trim(), "y" | "Y") {
        println!("Aborted.");
        return Ok(());
    }

    if already_exists {
        match merge_and_reimport(&keystore, &key_info.fingerprint, &key_data) {
            Ok(true) => println!("Updated {} ({}) — merged new signatures", key_info.fingerprint, uid),
            Ok(false) => println!("Unchanged {} ({}) — no new data", key_info.fingerprint, uid),
            Err(e) => anyhow::bail!("Merge failed: {}", e),
        }
    } else {
        keystore.import_key(&key_data)?;
        println!("Imported {} ({})", key_info.fingerprint, uid);
    }

    Ok(())
}
