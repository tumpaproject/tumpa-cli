use anyhow::Result;

use crate::util::{config, git};

use super::init::{check_sneaky_paths, checked_passfile_path, checked_store_path, remove_empty_parents};
use super::insert::yesno;

/// `tpass rm [--recursive,-r] [--force,-f] pass-name`
pub fn cmd_rm(path: &str, recursive: bool, force: bool) -> Result<()> {
    let prefix = config::store_dir();
    check_sneaky_paths(&[path])?;

    let passdir = checked_store_path(&prefix, path.trim_end_matches('/'))?;
    let passfile = checked_passfile_path(&prefix, path)?;

    // Determine target: directory or file
    // Match pass logic: if both file and dir exist, prefer dir if path ends with /
    let target = if passfile.is_file() && passdir.is_dir() && path.ends_with('/') {
        passdir.clone()
    } else if passfile.is_file() && !passdir.is_dir() {
        passfile.clone()
    } else if !passfile.is_file() {
        // Use directory path (with trailing /)
        let mut p = passdir.to_string_lossy().to_string();
        if !p.ends_with('/') {
            p.push('/');
        }
        std::path::PathBuf::from(p)
    } else {
        passfile.clone()
    };

    if !target.exists() && !passfile.exists() && !passdir.exists() {
        anyhow::bail!("Error: {} is not in the password store.", path);
    }

    if !force
        && !yesno(&format!(
            "Are you sure you would like to delete {}?",
            path
        )) {
            std::process::exit(1);
        }

    // Remove the file/directory
    if target.is_dir() {
        if recursive {
            std::fs::remove_dir_all(&target)?;
        } else {
            anyhow::bail!("Error: {} is a directory. Use -r to remove recursively.", path);
        }
    } else {
        std::fs::remove_file(&target)?;
    }

    // Git integration
    let git_dir = git::find_git_dir(&target, &prefix);
    if let Some(ref gd) = git_dir {
        if !target.exists() {
            let _ = git::git_rm(
                gd,
                &target,
                recursive,
                &format!("Remove {} from store.", path),
            );
        }
    }

    // Remove empty parent directories
    if let Some(parent) = target.parent() {
        let _ = remove_empty_parents(parent, &prefix);
    }

    Ok(())
}
