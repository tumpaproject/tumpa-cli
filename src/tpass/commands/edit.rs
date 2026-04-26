use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::util::{config, crypto, git};

use super::init::{check_sneaky_paths, checked_passfile_path, get_recipients};

/// `tpass edit pass-name`
pub fn cmd_edit(path: &str) -> Result<()> {
    let prefix = config::store_dir();
    let path = path.trim_end_matches('/');
    check_sneaky_paths(&[path])?;

    // Create parent directories
    let passfile = checked_passfile_path(&prefix, path)?;
    if let Some(parent) = passfile.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let dir_path = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let recipients = get_recipients(&prefix, &dir_path)?;
    let git_dir = git::find_git_dir(&passfile, &prefix);

    // Create secure temp directory
    let tmpdir = create_secure_tmpdir()?;
    let tmp_file = create_secure_tmpfile(&tmpdir, path)?;

    // Decrypt existing file to temp if it exists
    let action;
    let old_content;
    if passfile.is_file() {
        let plaintext = crypto::decrypt_file(&passfile, None)?;
        std::fs::write(&tmp_file, plaintext.as_slice())?;
        old_content = Some(plaintext);
        action = "Edit";
    } else {
        // Create empty temp file
        std::fs::write(&tmp_file, b"")?;
        old_content = None;
        action = "Add";
    }

    // Launch editor
    let editor = config::editor();
    let status = std::process::Command::new(&editor)
        .arg(&tmp_file)
        .status()
        .context(format!("Failed to launch editor '{}'", editor))?;

    if !status.success() {
        cleanup_tmpdir(&tmpdir);
        anyhow::bail!("Editor exited with non-zero status");
    }

    // Check if file exists after editing
    if !tmp_file.exists() {
        cleanup_tmpdir(&tmpdir);
        anyhow::bail!("New password not saved.");
    }

    // Read new content
    let new_content = std::fs::read(&tmp_file)?;

    // Check if content changed
    if let Some(ref old) = old_content {
        if old.as_slice() == new_content.as_slice() {
            cleanup_tmpdir(&tmpdir);
            anyhow::bail!("Password unchanged.");
        }
    }

    // Encrypt new content
    crypto::encrypt_to_recipients(&new_content, &recipients, &passfile, None)?;

    // Cleanup temp files
    cleanup_tmpdir(&tmpdir);

    if let Some(ref gd) = git_dir {
        let _ = git::git_add_file(
            gd,
            &passfile,
            &format!("{} password for {} using {}.", action, path, editor),
        );
    }

    Ok(())
}

/// Create a secure temporary directory, preferring /dev/shm.
fn create_secure_tmpdir() -> Result<PathBuf> {
    let base = if Path::new("/dev/shm").is_dir() {
        PathBuf::from("/dev/shm")
    } else {
        PathBuf::from(std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string()))
    };

    for _ in 0..16 {
        let dir = base.join(format!("tpass.{}", random_suffix()?));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }

    anyhow::bail!("Failed to create secure temporary directory")
}

fn create_secure_tmpfile(dir: &Path, path: &str) -> Result<PathBuf> {
    let tmp_file = dir.join(format!(
        "{}-{}.txt",
        path.replace('/', "-"),
        random_suffix()?
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(&tmp_file)?;
    Ok(tmp_file)
}

fn random_suffix() -> Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

/// Clean up temp directory: overwrite files with zeros then remove.
fn cleanup_tmpdir(dir: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                // Overwrite with zeros
                if let Ok(metadata) = std::fs::metadata(&path) {
                    let len = metadata.len() as usize;
                    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
                        let _ = f.write_all(&vec![0u8; len]);
                        let _ = f.sync_all();
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
