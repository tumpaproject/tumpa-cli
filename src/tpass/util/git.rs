use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// Find the innermost git directory for a path within the password store.
/// Equivalent to pass's set_git() function.
pub fn find_git_dir(path: &Path, prefix: &Path) -> Option<std::path::PathBuf> {
    let mut current = path.parent().unwrap_or(path).to_path_buf();

    // Walk up directories looking for a git repo, but don't go above prefix
    loop {
        if !current.starts_with(prefix) {
            break;
        }
        let output = Command::new("git")
            .args([
                "-C",
                &current.to_string_lossy(),
                "rev-parse",
                "--is-inside-work-tree",
            ])
            .output()
            .ok()?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim() == "true" {
                return Some(current);
            }
        }
        if current == prefix {
            break;
        }
        if !current.pop() {
            break;
        }
    }
    None
}

/// git add file(s) + commit with message.
/// Checks pass.signcommits config for -S flag.
pub fn git_add_file(git_dir: &Path, file: &Path, message: &str) -> Result<()> {
    let status = Command::new("git")
        .args([
            "-C",
            &git_dir.to_string_lossy(),
            "add",
            &file.to_string_lossy(),
        ])
        .status()
        .context("Failed to run git add")?;

    if !status.success() {
        return Ok(()); // git add can fail if file doesn't exist yet, that's ok
    }

    // Check if there's actually something to commit
    let output = Command::new("git")
        .args([
            "-C",
            &git_dir.to_string_lossy(),
            "status",
            "--porcelain",
            &file.to_string_lossy(),
        ])
        .output()
        .context("Failed to run git status")?;

    if output.stdout.is_empty() {
        return Ok(()); // Nothing to commit
    }

    git_commit(git_dir, message)?;
    Ok(())
}

/// git commit with optional -S flag for signing.
pub fn git_commit(git_dir: &Path, message: &str) -> Result<()> {
    // Check pass.signcommits config
    let git_dir_str = git_dir.to_string_lossy().to_string();
    let sign = Command::new("git")
        .args([
            "-C",
            &git_dir_str,
            "config",
            "--bool",
            "--get",
            "pass.signcommits",
        ])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false);

    let mut cmd_args = vec!["-C".to_string(), git_dir_str, "commit".to_string()];
    if sign {
        cmd_args.push("-S".to_string());
    }
    cmd_args.push("-m".to_string());
    cmd_args.push(message.to_string());

    Command::new("git")
        .args(&cmd_args)
        .status()
        .context("Failed to run git commit")?;

    Ok(())
}

/// git rm + commit
pub fn git_rm(git_dir: &Path, file: &Path, recursive: bool, message: &str) -> Result<()> {
    let mut args = vec![
        "-C".to_string(),
        git_dir.to_string_lossy().to_string(),
        "rm".to_string(),
        "-q".to_string(),
    ];
    if recursive {
        args.push("-r".to_string());
    }
    args.push(file.to_string_lossy().to_string());

    Command::new("git")
        .args(&args)
        .status()
        .context("Failed to run git rm")?;

    git_commit(git_dir, message)?;
    Ok(())
}

/// Run an arbitrary git command in the store directory.
pub fn git_run(git_dir: &Path, args: &[String]) -> Result<()> {
    let mut cmd_args = vec!["-C".to_string(), git_dir.to_string_lossy().to_string()];
    cmd_args.extend_from_slice(args);

    let status = Command::new("git")
        .args(&cmd_args)
        .status()
        .context("Failed to run git command")?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}
