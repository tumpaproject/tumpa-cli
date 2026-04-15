use anyhow::Result;

use crate::util::{config, git};

use super::init::{check_sneaky_paths, checked_passfile_path, checked_store_path, reencrypt_path};
use super::insert::yesno;

/// `tpass cp [--force,-f] old-path new-path`
pub fn cmd_cp(old_path: &str, new_path: &str, force: bool) -> Result<()> {
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
    if !force && new_full.exists()
        && !yesno(&format!("{} already exists. Overwrite it?", new_path)) {
            std::process::exit(1);
        }

    // Copy
    if old_full.is_dir() {
        copy_dir_recursive(&old_full, &new_full)?;
    } else {
        std::fs::copy(&old_full, &new_full)?;
    }

    // Reencrypt at new location (recipients might differ)
    if new_full.exists() {
        reencrypt_path(&new_full, &prefix, None)?;
    }

    // Git integration
    let git_dir = git::find_git_dir(&new_full, &prefix);
    if let Some(ref gd) = git_dir {
        let _ = git::git_add_file(
            gd,
            &new_full,
            &format!("Copy {} to {}.", old_path, new_path),
        );
    }

    Ok(())
}

fn resolve_pass_path(prefix: &std::path::Path, path: &str) -> Result<std::path::PathBuf> {
    let clean = path.trim_end_matches('/');
    let full = checked_store_path(prefix, clean)?;
    let gpg = checked_passfile_path(prefix, clean)?;

    if gpg.is_file() && !(full.is_dir() && path.ends_with('/')) {
        Ok(gpg)
    } else {
        Ok(full)
    }
}

fn resolve_new_path(
    prefix: &std::path::Path,
    new_path: &str,
    old_full: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let new_full = checked_store_path(prefix, new_path)?;

    if old_full.is_dir() || new_full.is_dir() || new_path.ends_with('/') {
        Ok(new_full)
    } else {
        checked_passfile_path(prefix, new_path)
    }
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&src_path)?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!("Error: Refusing to copy symlinked path {}.", src_path.display());
        }
        if metadata.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
