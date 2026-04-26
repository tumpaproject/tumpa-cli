use std::io::Read;

use anyhow::Result;

use crate::util::{clip, config, crypto, git};

use super::init::{check_sneaky_paths, checked_passfile_path, get_recipients};
use super::insert::yesno;

/// `tpass generate [--no-symbols,-n] [--clip,-c] [--qrcode,-q] [--in-place,-i | --force,-f] pass-name [pass-length]`
pub fn cmd_generate(
    path: &str,
    no_symbols: bool,
    clip_mode: bool,
    qrcode: bool,
    in_place: bool,
    force: bool,
    length: Option<usize>,
) -> Result<()> {
    let prefix = config::store_dir();
    check_sneaky_paths(&[path])?;

    let length = length.unwrap_or_else(config::generated_length);
    if length == 0 {
        anyhow::bail!("Error: pass-length must be greater than zero.");
    }

    let characters = if no_symbols {
        config::character_set_no_symbols()
    } else {
        config::character_set()
    };

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

    if !in_place
        && !force
        && passfile.exists()
        && !yesno(&format!(
            "An entry already exists for {}. Overwrite it?",
            path
        ))
    {
        std::process::exit(1);
    }

    // Generate password using /dev/urandom + tr (matching pass behavior)
    let pass = generate_password(length, &characters)?;

    if in_place {
        // Replace only the first line of the existing file
        if !passfile.exists() {
            anyhow::bail!("Error: {} does not exist. Cannot use --in-place.", path);
        }
        let existing = crypto::decrypt_file(&passfile, None)?;
        let existing_str = String::from_utf8_lossy(&existing);
        let rest: String = existing_str.lines().skip(1).collect::<Vec<_>>().join("\n");

        let new_content = if rest.is_empty() {
            format!("{}\n", pass)
        } else {
            format!("{}\n{}\n", pass, rest)
        };

        crypto::encrypt_to_recipients(new_content.as_bytes(), &recipients, &passfile, None)?;
    } else {
        let content = format!("{}\n", pass);
        crypto::encrypt_to_recipients(content.as_bytes(), &recipients, &passfile, None)?;
    }

    let verb = if in_place { "Replace" } else { "Add" };
    if let Some(ref gd) = git_dir {
        let _ = git::git_add_file(
            gd,
            &passfile,
            &format!("{} generated password for {}.", verb, path),
        );
    }

    if clip_mode {
        clip::clip(&pass, path)?;
    } else if qrcode {
        // Use show's qrcode functionality
        use std::process::{Command, Stdio};
        let mut child = Command::new("qrencode")
            .args(["-t", "utf8"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|_| anyhow::anyhow!("qrencode is not installed"))?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(pass.as_bytes());
        }
        let _ = child.wait();
    } else {
        println!(
            "\x1b[1mThe generated password for \x1b[4m{}\x1b[24m is:\x1b[0m\n\x1b[1m\x1b[93m{}\x1b[0m",
            path, pass
        );
    }

    Ok(())
}

/// Generate a random password from /dev/urandom using the given character set.
/// This matches pass's: `LC_ALL=C tr -dc "$characters" < /dev/urandom | head -c $length`
fn generate_password(length: usize, characters: &str) -> Result<String> {
    use std::process::{Command, Stdio};

    // Use tr + /dev/urandom for exact compatibility with pass
    let mut child = Command::new("bash")
        .args([
            "-c",
            &format!(
                "LC_ALL=C tr -dc '{}' < /dev/urandom | head -c {}",
                characters.replace('\'', "'\\''"),
                length
            ),
        ])
        .stdout(Stdio::piped())
        .spawn()?;

    let mut output = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_string(&mut output)?;
    }
    let _ = child.wait();

    if output.len() != length {
        anyhow::bail!("Could not generate password from /dev/urandom.");
    }

    Ok(output)
}
