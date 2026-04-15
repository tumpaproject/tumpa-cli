use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::agent;

/// Get a passphrase or PIN via the pinentry program.
///
/// Acquisition order:
/// 1. Agent cache (if tcli agent is running)
/// 2. TUMPA_PASSPHRASE env var
/// 3. pinentry program
/// 4. Terminal prompt
///
/// If a passphrase is obtained from steps 2-4 and the agent is running,
/// it is stored in the agent cache for future use.
///
/// `cache_key` is the key fingerprint used for agent cache lookups.
/// If None, agent caching is skipped.
pub fn get_passphrase(
    description: &str,
    prompt: &str,
    cache_key: Option<&str>,
) -> Result<Zeroizing<String>> {
    // 1. Check agent cache
    if let Some(key) = cache_key {
        if let Some(pass) = try_agent_get(key) {
            log::debug!("Using passphrase from agent cache");
            return Ok(pass);
        }
    }

    // 2. Check environment variable
    if let Ok(pass) = std::env::var("TUMPA_PASSPHRASE") {
        log::debug!("Using passphrase from TUMPA_PASSPHRASE env var");
        let pass = Zeroizing::new(pass);
        if let Some(key) = cache_key {
            try_agent_put(key, &pass);
        }
        return Ok(pass);
    }

    // 3. Try pinentry
    match try_pinentry(description, prompt) {
        Ok(pass) => {
            if let Some(key) = cache_key {
                try_agent_put(key, &pass);
            }
            return Ok(pass);
        }
        Err(e) => {
            log::debug!("pinentry failed: {}, falling back to terminal", e);
        }
    }

    // 4. Fall back to terminal prompt
    let pass = rpassword_prompt(prompt)?;
    if let Some(key) = cache_key {
        try_agent_put(key, &pass);
    }
    Ok(pass)
}

/// Try to get a cached passphrase from the agent.
/// Returns None if agent is not running or key not cached.
fn try_agent_get(fingerprint: &str) -> Option<Zeroizing<String>> {
    let socket_path = agent::default_socket_path().ok()?;
    let mut stream = UnixStream::connect(&socket_path).ok()?;

    // Set a short timeout to avoid hanging if agent is unresponsive
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok()?;

    let request = format!("GET_PASSPHRASE {}\n", fingerprint);
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = String::new();
    let mut reader = std::io::BufReader::new(&stream);
    reader.read_line(&mut response).ok()?;

    match agent::protocol::parse_response(&response) {
        Some(agent::protocol::Response::Passphrase(pass)) => Some(pass),
        _ => None,
    }
}

/// Try to store a passphrase in the agent cache.
/// Silently does nothing if agent is not running.
fn try_agent_put(fingerprint: &str, passphrase: &Zeroizing<String>) {
    let socket_path = match agent::default_socket_path() {
        Ok(p) => p,
        Err(_) => return,
    };

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(_) => return,
    };

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();

    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(passphrase.as_bytes())
    };
    let request = format!("PUT_PASSPHRASE {} {}\n", fingerprint, b64);
    let _ = stream.write_all(request.as_bytes());

    // Read the OK response
    let mut response = String::new();
    let mut reader = std::io::BufReader::new(&stream);
    let _ = reader.read_line(&mut response);
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

    let mut stdin = child.stdin.take().context("Failed to open pinentry stdin")?;
    let stdout = child.stdout.take().context("Failed to open pinentry stdout")?;
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
