use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::store;

/// Import keys from files or directories.
pub fn cmd_import(paths: &[PathBuf], recursive: bool, keystore_path: Option<&PathBuf>) -> Result<()> {
    let keystore = store::open_keystore(keystore_path)?;

    let mut imported = 0u32;
    let mut skipped = 0u32;
    let mut failed = 0u32;

    for path in paths {
        if path.is_dir() {
            import_dir(&keystore, path, recursive, &mut imported, &mut skipped, &mut failed)?;
        } else {
            import_file(&keystore, path, &mut imported, &mut skipped, &mut failed);
        }
    }

    println!("Imported {} key(s), skipped {} (already present), {} failed.", imported, skipped, failed);
    Ok(())
}

fn import_dir(
    keystore: &wecanencrypt::KeyStore,
    dir: &Path,
    recursive: bool,
    imported: &mut u32,
    skipped: &mut u32,
    failed: &mut u32,
) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .context(format!("Failed to read directory {:?}", dir))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() && recursive {
            import_dir(keystore, &path, recursive, imported, skipped, failed)?;
        } else if path.is_file()
            && is_key_file(&path) {
                import_file(keystore, &path, imported, skipped, failed);
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
    skipped: &mut u32,
    failed: &mut u32,
) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {:?}: {}", path, e);
            *failed += 1;
            return;
        }
    };

    // Check if key already exists before importing
    if let Ok(cert_info) = wecanencrypt::parse_cert_bytes(&data, false) {
        if keystore.contains(&cert_info.fingerprint).unwrap_or(false) {
            let uid = cert_info
                .user_ids
                .first()
                .map(|u| u.value.as_str())
                .unwrap_or("");
            println!(
                "Skipping {} ({}) — already imported",
                cert_info.fingerprint, uid
            );
            *skipped += 1;
            return;
        }
    }

    match keystore.import_cert(&data) {
        Ok(fp) => {
            let info = keystore.get_cert_info(&fp).ok();
            let uid = info
                .and_then(|i| i.user_ids.first().map(|u| u.value.clone()))
                .unwrap_or_default();
            println!("Imported {} ({})", fp, uid);
            *imported += 1;
        }
        Err(e) => {
            eprintln!("Failed to import {:?}: {}", path, e);
            *failed += 1;
        }
    }
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
    let (_cert_data, cert_info) = store::resolve_signer(&keystore, key_id)?;

    if binary {
        // Parse the stored cert and re-serialize as binary OpenPGP packets
        use pgp::composed::Deserializable;
        use pgp::ser::Serialize;
        let raw = keystore.export_cert(&cert_info.fingerprint)?;
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
                eprintln!("Exported {} to {:?}", cert_info.fingerprint, path);
            }
            None => {
                io::stdout().write_all(&data)?;
            }
        }
    } else {
        // Default: armored
        let armored = keystore.export_cert_armored(&cert_info.fingerprint)?;
        match output {
            Some(path) => {
                std::fs::write(path, &armored)?;
                eprintln!("Exported {} to {:?}", cert_info.fingerprint, path);
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
    let (cert_data, cert_info) = store::resolve_signer(&keystore, key_id)?;
    print_cert_info(&cert_data, &cert_info);
    Ok(())
}

/// Print detailed certificate information.
fn print_cert_info(cert_data: &[u8], cert_info: &wecanencrypt::CertificateInfo) {
    let key_type = if cert_info.is_secret { "sec" } else { "pub" };
    let time_fmt = "%Y-%m-%d %H:%M:%S UTC";

    // Get primary key algorithm details
    let primary_algo = wecanencrypt::get_key_cipher_details(cert_data)
        .ok()
        .and_then(|details| details.into_iter().next())
        .map(|d| format_algo(&d.algorithm, d.bit_length))
        .unwrap_or_default();

    // Primary key capabilities
    let mut primary_caps = Vec::new();
    if cert_info.can_primary_sign {
        primary_caps.push("sign");
    }
    primary_caps.push("certify"); // primary can always certify

    println!(
        "{}  {}  {}  [{}]",
        key_type,
        cert_info.fingerprint,
        primary_algo,
        primary_caps.join(", ")
    );
    println!(
        "     Created:  {}",
        cert_info.creation_time.format(time_fmt)
    );
    if let Some(ref exp) = cert_info.expiration_time {
        println!("     Expires:  {}", exp.format(time_fmt));
    } else {
        println!("     Expires:  never");
    }

    if cert_info.is_revoked {
        if let Some(ref rev_time) = cert_info.revocation_time {
            println!("     Revoked:  {}", rev_time.format(time_fmt));
        } else {
            println!("     Revoked:  yes");
        }
    }

    // UIDs (primary first)
    let mut uids: Vec<_> = cert_info.user_ids.iter().filter(|u| !u.revoked).collect();
    uids.sort_by(|a, b| b.is_primary.cmp(&a.is_primary));

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
    if !cert_info.subkeys.is_empty() {
        println!("     Subkeys:");
        for sk in &cert_info.subkeys {
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
    let (_cert_data, cert_info) = store::resolve_signer(&keystore, key_id)?;

    let uid = cert_info
        .user_ids
        .first()
        .map(|u| u.value.as_str())
        .unwrap_or("<no UID>");

    if !force {
        eprint!(
            "Delete {} {} ({})? [y/N] ",
            if cert_info.is_secret { "SECRET key" } else { "public key" },
            cert_info.fingerprint,
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

    keystore.delete_cert(&cert_info.fingerprint)?;
    println!("Deleted {} ({})", cert_info.fingerprint, uid);

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

    for cert in &results {
        let key_type = if cert.is_secret { "sec" } else { "pub" };
        let uid = cert
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or("<no UID>");
        println!("{} {} {}", key_type, cert.fingerprint, uid);
    }

    println!("\n{} key(s) found.", results.len());

    Ok(())
}

/// Fetch and import a key via WKD.
pub fn cmd_fetch(email: &str, dry_run: bool, keystore_path: Option<&PathBuf>) -> Result<()> {
    eprintln!("Fetching key for {} via WKD...", email);

    let cert_data = wecanencrypt::fetch_key_by_email(email)
        .context(format!("WKD lookup failed for {}", email))?;

    let cert_info = wecanencrypt::parse_cert_bytes(&cert_data, false)?;

    print_cert_info(&cert_data, &cert_info);

    if dry_run {
        return Ok(());
    }

    // Import
    let keystore = store::open_keystore(keystore_path)?;
    if keystore.contains(&cert_info.fingerprint)? {
        println!("\nKey {} already in keystore.", cert_info.fingerprint);
        return Ok(());
    }

    let uid = cert_info
        .user_ids
        .first()
        .map(|u| u.value.as_str())
        .unwrap_or("<no UID>");

    eprint!("\nImport this key? [y/N] ");
    io::stderr().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    if !matches!(response.trim(), "y" | "Y") {
        println!("Aborted.");
        return Ok(());
    }

    keystore.import_cert(&cert_data)?;
    println!("Imported {} ({})", cert_info.fingerprint, uid);

    Ok(())
}
