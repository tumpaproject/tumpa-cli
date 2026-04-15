use std::io::{self, BufRead, Read, Write};

use anyhow::Result;

use crate::util::{config, crypto, git};

use super::init::{check_sneaky_paths, checked_passfile_path, get_recipients};

/// `tpass insert [--echo,-e | --multiline,-m] [--force,-f] pass-name`
pub fn cmd_insert(path: &str, multiline: bool, echo: bool, force: bool) -> Result<()> {
    let prefix = config::store_dir();
    let path = path.trim_end_matches('/');
    check_sneaky_paths(&[path])?;

    let passfile = checked_passfile_path(&prefix, path)?;
    let git_dir = git::find_git_dir(&passfile, &prefix);

    if !force && passfile.exists()
        && !yesno(&format!(
            "An entry already exists for {}. Overwrite it?",
        path
        )) {
            std::process::exit(1);
        }

    // Create parent directories
    if let Some(parent) = passfile.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let dir_path = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let recipients = get_recipients(&prefix, &dir_path)?;

    let password = if multiline {
        eprintln!(
            "Enter contents of {} and press Ctrl+D when finished:\n",
            path
        );
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else if echo {
        eprint!("Enter password for {}: ", path);
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        // Remove trailing newline from read_line, then add our own
        let password = line.trim_end_matches('\n').trim_end_matches('\r');
        format!("{}\n", password).into_bytes()
    } else {
        // No-echo mode: read password twice, confirm match
        let password = rpassword::prompt_password(format!("Enter password for {}: ", path))?;
        let password_again =
            rpassword::prompt_password(format!("Retype password for {}: ", path))?;

        if password != password_again {
            anyhow::bail!("Error: the entered passwords do not match.");
        }
        format!("{}\n", password).into_bytes()
    };

    crypto::encrypt_to_recipients(&password, &recipients, &passfile, None)?;

    if let Some(ref gd) = git_dir {
        let _ = git::git_add_file(
            gd,
            &passfile,
            &format!("Add given password for {} to store.", path),
        );
    }

    Ok(())
}

/// Prompt user for yes/no confirmation.
pub fn yesno(prompt: &str) -> bool {
    // Only prompt if stdin is a TTY
    if !atty_is_tty() {
        return true;
    }

    eprint!("{} [y/N] ", prompt);
    io::stderr().flush().ok();

    let mut response = String::new();
    io::stdin().lock().read_line(&mut response).ok();
    matches!(response.trim(), "y" | "Y")
}

fn atty_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) != 0 }
}
