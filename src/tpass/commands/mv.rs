use anyhow::Result;

use crate::util::{config, git};

use super::init::{
    check_sneaky_paths, checked_passfile_path, checked_store_path, reencrypt_path,
    remove_empty_parents,
};
use super::insert::yesno;

/// `tpass mv [--force,-f] old-path new-path`
pub fn cmd_mv(old_path: &str, new_path: &str, force: bool) -> Result<()> {
    let prefix = config::store_dir();
    check_sneaky_paths(&[old_path, new_path])?;

    let old_full = resolve_pass_path(&prefix, old_path)?;
    let new_full = resolve_new_path(&prefix, new_path, &old_full)?;

    if !old_full.exists() {
        anyhow::bail!("Error: {} is not in the password store.", old_path);
    }

    // Create parent directories
    if let Some(parent) = new_full.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Check for overwrite
    if !force && new_full.exists() && !yesno(&format!("{} already exists. Overwrite it?", new_path))
    {
        std::process::exit(1);
    }

    // Move
    std::fs::rename(&old_full, &new_full)?;

    // Reencrypt at new location (recipients might differ)
    if new_full.exists() {
        reencrypt_path(&new_full, &prefix, None)?;
    }

    // Git integration
    let git_dir = git::find_git_dir(&new_full, &prefix);
    if let Some(ref gd) = git_dir {
        if !old_full.exists() {
            // Remove old from git
            let _ = std::process::Command::new("git")
                .args([
                    "-C",
                    &gd.to_string_lossy(),
                    "rm",
                    "-qr",
                    &old_full.to_string_lossy(),
                ])
                .status();
        }
        let _ = git::git_add_file(
            gd,
            &new_full,
            &format!("Rename {} to {}.", old_path, new_path),
        );
    }

    // Also handle old path's git repo if different
    let old_git_dir = git::find_git_dir(&old_full, &prefix);
    if let Some(ref gd) = old_git_dir {
        if !old_full.exists() {
            let _ = std::process::Command::new("git")
                .args([
                    "-C",
                    &gd.to_string_lossy(),
                    "rm",
                    "-qr",
                    &old_full.to_string_lossy(),
                ])
                .status();

            // Check if there's something to commit
            let output = std::process::Command::new("git")
                .args([
                    "-C",
                    &gd.to_string_lossy(),
                    "status",
                    "--porcelain",
                    &old_full.to_string_lossy(),
                ])
                .output()
                .ok();

            if let Some(out) = output {
                if !out.stdout.is_empty() {
                    let _ = git::git_commit(gd, &format!("Remove {}.", old_path));
                }
            }
        }
    }

    // Remove empty parent directories
    if let Some(parent) = old_full.parent() {
        let _ = remove_empty_parents(parent, &prefix);
    }

    Ok(())
}

/// Resolve a pass path to its actual filesystem path.
/// If path.gpg exists and path is not a directory (or path doesn't end with /),
/// append .gpg extension.
fn resolve_pass_path(prefix: &std::path::Path, path: &str) -> Result<std::path::PathBuf> {
    let clean = path.trim_end_matches('/');
    let full = checked_store_path(prefix, clean)?;
    let gpg = checked_passfile_path(prefix, clean)?;

    // Match pass logic for determining file vs directory
    if gpg.is_file() && !(full.is_dir() && path.ends_with('/')) {
        Ok(gpg)
    } else {
        Ok(full)
    }
}

/// Resolve the new path, appending .gpg if needed.
fn resolve_new_path(
    prefix: &std::path::Path,
    new_path: &str,
    old_full: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let new_full = checked_store_path(prefix, new_path)?;

    // If old is a directory, or new is a directory, or new ends with /, don't add .gpg
    if old_full.is_dir() || new_full.is_dir() || new_path.ends_with('/') {
        Ok(new_full)
    } else {
        checked_passfile_path(prefix, new_path)
    }
}
