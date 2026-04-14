use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Get a passphrase or PIN via the pinentry program.
///
/// Checks TUMPA_PASSPHRASE env var first, then tries pinentry,
/// then falls back to terminal prompt.
pub fn get_passphrase(description: &str, prompt: &str) -> Result<Zeroizing<String>> {
    // Check environment variable first
    if let Ok(pass) = std::env::var("TUMPA_PASSPHRASE") {
        log::debug!("Using passphrase from TUMPA_PASSPHRASE env var");
        return Ok(Zeroizing::new(pass));
    }

    // Try pinentry
    match try_pinentry(description, prompt) {
        Ok(pass) => return Ok(pass),
        Err(e) => {
            log::debug!("pinentry failed: {}, falling back to terminal", e);
        }
    }

    // Fall back to terminal prompt
    let pass = rpassword_prompt(prompt)?;
    Ok(pass)
}

/// Try to get passphrase via pinentry Assuan protocol.
fn try_pinentry(description: &str, prompt: &str) -> Result<Zeroizing<String>> {
    let pinentry_program =
        std::env::var("PINENTRY_PROGRAM").unwrap_or_else(|_| "pinentry".to_string());

    let mut child = Command::new(&pinentry_program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context(format!("Failed to spawn {}", pinentry_program))?;

    let mut stdin = child
        .stdin
        .take()
        .context("Failed to open pinentry stdin")?;
    let stdout = child
        .stdout
        .take()
        .context("Failed to open pinentry stdout")?;
    let mut reader = BufReader::new(stdout);

    // Read the greeting
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if !line.starts_with("OK") {
        anyhow::bail!("pinentry greeting failed: {}", line.trim());
    }

    // Set the description
    let desc_escaped = description.replace('%', "%25").replace('\n', "%0A");
    writeln!(stdin, "SETDESC {}", desc_escaped)?;
    line.clear();
    reader.read_line(&mut line)?;

    // Set the prompt
    writeln!(stdin, "SETPROMPT {}", prompt)?;
    line.clear();
    reader.read_line(&mut line)?;

    // Get the PIN
    writeln!(stdin, "GETPIN")?;
    line.clear();
    reader.read_line(&mut line)?;

    let passphrase = if let Some(data) = line.strip_prefix("D ") {
        let pass = Zeroizing::new(data.trim_end().to_string());
        // Read the OK after D line
        line.clear();
        reader.read_line(&mut line)?;
        pass
    } else if line.starts_with("ERR") {
        // User cancelled
        writeln!(stdin, "BYE")?;
        let _ = child.wait();
        anyhow::bail!("pinentry cancelled by user");
    } else {
        writeln!(stdin, "BYE")?;
        let _ = child.wait();
        anyhow::bail!("unexpected pinentry response: {}", line.trim());
    };

    writeln!(stdin, "BYE")?;
    let _ = child.wait();

    Ok(passphrase)
}

/// Fallback: prompt on terminal via rpassword-style read.
fn rpassword_prompt(prompt: &str) -> Result<Zeroizing<String>> {
    let pass = rpassword::prompt_password(format!("{}: ", prompt))
        .context("Failed to read passphrase from terminal")?;
    Ok(Zeroizing::new(pass))
}
