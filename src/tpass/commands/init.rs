use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

use crate::util::{config, crypto, git};

/// Resolve GPG recipients for a given path within the store.
/// Walks up directories to find the nearest .gpg-id file.
/// If PASSWORD_STORE_KEY is set, uses that instead.
pub fn get_recipients(prefix: &std::path::Path, subpath: &str) -> Result<Vec<String>> {
    if let Some(keys) = config::store_key() {
        return Ok(keys);
    }

    let mut current = checked_store_path(prefix, subpath)?;
    loop {
        let gpg_id_file = current.join(".gpg-id");
        if gpg_id_file.is_file() {
            ensure_no_symlink_in_path(&gpg_id_file, prefix)?;
            // Verify signature if signing key is set
            if let Some(signing_keys) = config::signing_key() {
                crypto::verify_file_signature(&gpg_id_file, &signing_keys, None)?;
            }
            return read_gpg_id_file(&gpg_id_file);
        }
        if current == prefix {
            break;
        }
        if !current.pop() {
            break;
        }
    }

    anyhow::bail!(
        "Error: You must run:\n    tpass init your-gpg-id\nbefore you may use the password store."
    )
}

/// Read a .gpg-id file, returning the list of GPG IDs.
fn read_gpg_id_file(path: &std::path::Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).context(format!("Failed to read {:?}", path))?;
    let ids: Vec<String> = content
        .lines()
        .map(|line| {
            // Strip comments (everything after #)
            let line = line.split('#').next().unwrap_or("").trim();
            line.to_string()
        })
        .filter(|line| !line.is_empty())
        .collect();
    Ok(ids)
}

/// Reencrypt all .gpg files under a path when recipients change.
pub fn reencrypt_path(
    path: &std::path::Path,
    prefix: &std::path::Path,
    keystore_path: Option<&PathBuf>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let mut prev_recipients: Option<Vec<String>> = None;
    let mut target_key_ids: Option<Vec<String>> = None;

    for entry in walkdir(path)? {
        let entry = entry?;
        let entry_path = entry.path();

        // Skip non-.gpg files
        if entry_path.extension().map(|e| e != "gpg").unwrap_or(true) {
            continue;
        }

        // Skip symlinks
        if entry_path.symlink_metadata()?.file_type().is_symlink() {
            continue;
        }

        let passfile_dir = entry_path.parent().unwrap_or(path);
        let rel_dir = passfile_dir
            .strip_prefix(prefix)
            .unwrap_or(std::path::Path::new(""));

        let recipients = get_recipients(prefix, &rel_dir.to_string_lossy())?;

        // Recompute target key IDs if recipients changed
        if prev_recipients.as_ref() != Some(&recipients) {
            target_key_ids = Some(crypto::recipient_encryption_key_ids(
                &recipients,
                keystore_path,
            )?);
            prev_recipients = Some(recipients.clone());
        }

        let target_ids = target_key_ids.as_ref().unwrap();

        // Get current encryption key IDs
        let mut current_ids = crypto::file_encrypted_for(&entry_path)?;
        current_ids.sort();
        current_ids.dedup();

        let mut sorted_target = target_ids.clone();
        sorted_target.sort();

        if current_ids != sorted_target {
            let display = entry_path
                .strip_prefix(prefix)
                .unwrap_or(&entry_path)
                .to_string_lossy()
                .trim_end_matches(".gpg")
                .to_string();
            eprintln!("{}: reencrypting to {}", display, sorted_target.join(" "));

            // Decrypt and re-encrypt
            let plaintext = crypto::decrypt_file(&entry_path, keystore_path)?;
            let temp_path = entry_path.with_extension("gpg.tmp");
            crypto::encrypt_to_recipients(&plaintext, &recipients, &temp_path, keystore_path)?;
            std::fs::rename(&temp_path, entry_path)?;
        }
    }

    Ok(())
}

fn walkdir(
    path: &std::path::Path,
) -> Result<Box<dyn Iterator<Item = Result<std::fs::DirEntry, std::io::Error>>>> {
    // Simple recursive walk that skips .git and .extensions directories
    let mut entries = Vec::new();
    walk_recursive(path, &mut entries)?;
    Ok(Box::new(entries.into_iter().map(Ok)))
}

fn walk_recursive(path: &std::path::Path, entries: &mut Vec<std::fs::DirEntry>) -> Result<()> {
    if !path.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip .git and .extensions
        if name_str == ".git" || name_str == ".extensions" {
            continue;
        }

        if entry.file_type()?.is_dir() {
            walk_recursive(&entry.path(), entries)?;
        } else {
            entries.push(entry);
        }
    }

    Ok(())
}

/// `tpass init [-p subfolder] gpg-id...`
pub fn cmd_init(path: Option<&str>, gpg_ids: &[String]) -> Result<()> {
    let prefix = config::store_dir();

    if let Some(p) = path {
        check_sneaky_paths(&[p])?;
    }

    let id_path = path.unwrap_or("");
    let full_path = if id_path.is_empty() {
        prefix.clone()
    } else {
        checked_store_path(&prefix, id_path)?
    };

    // Check that if id_path exists, it's a directory
    if !id_path.is_empty() && full_path.exists() && !full_path.is_dir() {
        anyhow::bail!(
            "Error: {} exists but is not a directory.",
            full_path.display()
        );
    }

    let gpg_id_file = full_path.join(".gpg-id");

    let git_dir = git::find_git_dir(&gpg_id_file, &prefix);

    if gpg_ids.len() == 1 && gpg_ids[0].is_empty() {
        // De-initialize
        if !gpg_id_file.exists() {
            anyhow::bail!(
                "Error: {} does not exist and so cannot be removed.",
                gpg_id_file.display()
            );
        }
        std::fs::remove_file(&gpg_id_file)?;
        if let Some(ref gd) = git_dir {
            let _ = git::git_rm(
                gd,
                &gpg_id_file,
                false,
                &format!(
                    "Deinitialize {}{}.",
                    gpg_id_file.display(),
                    if id_path.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", id_path)
                    }
                ),
            );
        }
        // Remove empty directories
        let _ = remove_empty_parents(&full_path, &prefix);
    } else {
        // Initialize
        std::fs::create_dir_all(&full_path)?;

        // Write gpg-ids to .gpg-id file
        let content = gpg_ids.join("\n") + "\n";
        std::fs::write(&gpg_id_file, &content)?;

        let id_print = gpg_ids.join(", ");
        let suffix = if id_path.is_empty() {
            String::new()
        } else {
            format!(" ({})", id_path)
        };
        println!("Password store initialized for {}{}", id_print, suffix);

        if let Some(ref gd) = git_dir {
            let _ = git::git_add_file(
                gd,
                &gpg_id_file,
                &format!("Set GPG id to {}{}.", id_print, suffix),
            );
        }

        // Sign .gpg-id if signing key is set
        if let Some(signing_keys) = config::signing_key() {
            crypto::sign_file_detached(&gpg_id_file, &signing_keys, None)?;
            if let Some(ref gd) = git_dir {
                let sig_file = gpg_id_file.with_extension("gpg-id.sig");
                let _ = git::git_add_file(
                    gd,
                    &sig_file,
                    &format!("Signing new GPG id with {}.", signing_keys.join(",")),
                );
            }
        }

        // Reencrypt
        reencrypt_path(&full_path, &prefix, None)?;

        if let Some(ref gd) = git_dir {
            let _ = git::git_add_file(
                gd,
                &full_path,
                &format!(
                    "Reencrypt password store using new GPG id {}{}.",
                    id_print, suffix
                ),
            );
        }
    }

    Ok(())
}

/// Reject paths containing ".." components.
pub fn check_sneaky_paths(paths: &[&str]) -> Result<()> {
    for path in paths {
        if path.is_empty() {
            continue;
        }

        let candidate = Path::new(path);
        if candidate.is_absolute() {
            anyhow::bail!("Error: Path escapes the password store.");
        }

        for component in candidate.components() {
            match component {
                Component::Normal(_) | Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    anyhow::bail!("Error: Path escapes the password store.");
                }
            }
        }
    }
    Ok(())
}

pub fn checked_store_path(prefix: &Path, path: &str) -> Result<PathBuf> {
    check_sneaky_paths(&[path])?;
    let joined = prefix.join(path);
    ensure_no_symlink_in_path(&joined, prefix)?;
    Ok(joined)
}

pub fn checked_passfile_path(prefix: &Path, path: &str) -> Result<PathBuf> {
    let clean = path.trim_end_matches('/');
    check_sneaky_paths(&[clean])?;
    let joined = prefix.join(format!("{}.gpg", clean));
    ensure_no_symlink_in_path(&joined, prefix)?;
    Ok(joined)
}

pub fn ensure_no_symlink_in_path(path: &Path, prefix: &Path) -> Result<()> {
    let rel = path
        .strip_prefix(prefix)
        .map_err(|_| anyhow::anyhow!("Error: Path escapes the password store."))?;

    let mut current = prefix.to_path_buf();
    for component in rel.components() {
        match component {
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("Error: Path escapes the password store.");
            }
        }

        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!(
                    "Error: Refusing to follow symlinked path {}.",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// Remove empty parent directories up to (but not including) the stop directory.
pub fn remove_empty_parents(start: &std::path::Path, stop: &std::path::Path) -> Result<()> {
    let mut current = start.to_path_buf();
    while current != stop.to_path_buf() {
        if current.is_dir() {
            if std::fs::read_dir(&current)?.next().is_none() {
                std::fs::remove_dir(&current)?;
            } else {
                break;
            }
        }
        if !current.pop() {
            break;
        }
    }
    Ok(())
}
