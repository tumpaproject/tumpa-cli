use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::agent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheSlot {
    Pin,
    Passphrase,
}

/// Get a passphrase or PIN via the pinentry program.
///
/// Acquisition order:
/// 1. Agent cache (if tcli agent is running, `cache_key` is `Some`, and
///    `prompt` is not `"Admin PIN"`)
/// 2. `TUMPA_ADMIN_PIN` env var — only when `prompt` is `"Admin PIN"`
///    (case-insensitive); skipped for any other prompt.
/// 3. `TUMPA_PASSPHRASE` env var
/// 4. pinentry program
/// 5. Terminal prompt
///
/// `cache_key` is the key fingerprint used for **reading** the agent
/// cache. A returned value is **never written** to the cache by this
/// function — the caller must call [`cache_passphrase`] after a
/// successful sign/decrypt and [`clear_cached_passphrase`] after a
/// failed one. Caching unverified values would burn card PIN attempts
/// when the user typed the wrong PIN once.
pub fn get_passphrase(
    description: &str,
    prompt: &str,
    cache_key: Option<&str>,
) -> Result<Zeroizing<String>> {
    let allow_agent_cache = should_use_agent_cache(prompt);
    let cache_slot = cache_slot_for_prompt(prompt);

    // 1. Check agent cache for user PIN/passphrase prompts only.
    // Admin PIN must not share the generic fingerprint cache key.
    if allow_agent_cache {
        if let (Some(key), Some(slot)) = (cache_key, cache_slot) {
            let namespaced_key = cache_key_for_slot(key, slot);
            if let Some(pass) = try_agent_get(&namespaced_key) {
                log::debug!("Using passphrase from agent cache");
                return Ok(pass);
            }
        }
    }

    // 2a. Admin-PIN prompts have a dedicated env var so non-interactive
    // runs (tests, CI) can feed a distinct admin PIN without also
    // exposing the key passphrase as the admin PIN.
    if prompt.eq_ignore_ascii_case("Admin PIN") {
        if let Ok(pin) = std::env::var("TUMPA_ADMIN_PIN") {
            log::debug!("Using admin PIN from TUMPA_ADMIN_PIN env var");
            return Ok(Zeroizing::new(pin));
        }
    }

    // 2b. Fall back to the generic passphrase env var for user
    // passphrases and user PINs.
    if let Ok(pass) = std::env::var("TUMPA_PASSPHRASE") {
        log::debug!("Using passphrase from TUMPA_PASSPHRASE env var");
        return Ok(Zeroizing::new(pass));
    }

    // 3. Try pinentry
    match try_pinentry(description, prompt) {
        Ok(pass) => return Ok(pass),
        Err(e) => {
            log::debug!("pinentry failed: {}, falling back to terminal", e);
        }
    }

    // 4. Fall back to terminal prompt
    rpassword_prompt(prompt)
}

fn should_use_agent_cache(prompt: &str) -> bool {
    !prompt.eq_ignore_ascii_case("Admin PIN")
}

fn cache_slot_for_prompt(prompt: &str) -> Option<CacheSlot> {
    if prompt.eq_ignore_ascii_case("Admin PIN") {
        None
    } else if prompt.eq_ignore_ascii_case("PIN") {
        Some(CacheSlot::Pin)
    } else {
        Some(CacheSlot::Passphrase)
    }
}

fn cache_key_for_slot(fingerprint: &str, slot: CacheSlot) -> String {
    match slot {
        CacheSlot::Pin => format!("pin:{fingerprint}"),
        CacheSlot::Passphrase => format!("passphrase:{fingerprint}"),
    }
}

pub fn cache_pin(fingerprint: &str, pin: &Zeroizing<String>) {
    try_agent_put(&cache_key_for_slot(fingerprint, CacheSlot::Pin), pin);
}

/// Store a passphrase in the running tumpa agent's cache.
///
/// Call this only **after** the value has been confirmed correct by a
/// successful sign or decrypt. Silent no-op if no agent is running.
pub fn cache_passphrase(fingerprint: &str, passphrase: &Zeroizing<String>) {
    try_agent_put(
        &cache_key_for_slot(fingerprint, CacheSlot::Passphrase),
        passphrase,
    );
}

pub fn clear_cached_pin(fingerprint: &str) {
    try_agent_clear(&cache_key_for_slot(fingerprint, CacheSlot::Pin));
}

/// Drop a cached passphrase from the running tumpa agent.
///
/// Call this whenever a sign or decrypt operation fails, to ensure a
/// stale (or freshly-typed-but-wrong) value is never reused on the
/// next request. Silent no-op if no agent is running.
pub fn clear_cached_passphrase(fingerprint: &str) {
    try_agent_clear(&cache_key_for_slot(fingerprint, CacheSlot::Passphrase));
}

pub fn clear_all_cached_secrets(fingerprint: &str) {
    clear_cached_pin(fingerprint);
    clear_cached_passphrase(fingerprint);
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

    try_agent_put_at_path(&socket_path, fingerprint, passphrase);
}

fn try_agent_put_at_path(socket_path: &Path, fingerprint: &str, passphrase: &Zeroizing<String>) {
    let mut stream = match UnixStream::connect(socket_path) {
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

/// Try to drop a cached passphrase from the agent.
/// Silently does nothing if agent is not running.
fn try_agent_clear(fingerprint: &str) {
    let socket_path = match agent::default_socket_path() {
        Ok(p) => p,
        Err(_) => return,
    };

    try_agent_clear_at_path(&socket_path, fingerprint);
}

fn try_agent_clear_at_path(socket_path: &Path, fingerprint: &str) {
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(_) => return,
    };

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok();

    let request = format!("CLEAR_PASSPHRASE {}\n", fingerprint);
    let _ = stream.write_all(request.as_bytes());

    // Read the OK response
    let mut response = String::new();
    let mut reader = std::io::BufReader::new(&stream);
    let _ = reader.read_line(&mut response);
}

/// Candidate pinentry programs, in preference order.
///
/// If `PINENTRY_PROGRAM` is set, only that program is tried. Otherwise:
/// - On macOS, `pinentry-mac` (GUI, works without a TTY) is preferred,
///   then bare `pinentry`. Homebrew absolute paths are appended so an
///   agent spawned by launchd with a reduced PATH still finds the
///   binary.
/// - Elsewhere, `pinentry` is the only default.
pub fn pinentry_candidates() -> Vec<String> {
    if let Ok(explicit) = std::env::var("PINENTRY_PROGRAM") {
        return vec![explicit];
    }
    if cfg!(target_os = "macos") {
        vec![
            "pinentry-mac".to_string(),
            "/opt/homebrew/bin/pinentry-mac".to_string(),
            "/usr/local/bin/pinentry-mac".to_string(),
            "pinentry".to_string(),
        ]
    } else {
        vec!["pinentry".to_string()]
    }
}

/// Resolve the first available pinentry candidate to an absolute path.
///
/// Absolute paths are checked with `metadata()`; bare names are resolved
/// by walking `PATH`. Returns `None` if nothing resolves — callers should
/// still attempt the candidates (the runtime PATH may differ from the
/// PATH seen here) but the absence is worth logging at agent startup.
pub fn resolve_pinentry() -> Option<(String, PathBuf)> {
    for name in pinentry_candidates() {
        if let Some(path) = which_on_path(&name) {
            return Some((name, path));
        }
    }
    None
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let p = Path::new(name);
    if p.is_absolute() {
        return if p.is_file() {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Try to get passphrase via pinentry Assuan protocol.
///
/// Iterates `pinentry_candidates()` in order. A candidate that isn't on
/// PATH (spawn failure) falls through to the next; a protocol/runtime
/// error from a spawned candidate is logged and also falls through, so
/// a broken `pinentry` (e.g. curses with no TTY) does not mask a
/// working `pinentry-mac`. User cancellation is preserved and does not
/// trigger further fallbacks.
fn try_pinentry(description: &str, prompt: &str) -> Result<Zeroizing<String>> {
    let candidates = pinentry_candidates();
    let mut last_err: Option<anyhow::Error> = None;

    for program in &candidates {
        match try_pinentry_with(program, description, prompt) {
            Ok(Some(pass)) => return Ok(pass),
            Ok(None) => log::debug!("{} not on PATH, trying next pinentry", program),
            Err(e) => {
                if is_user_cancel(&e) {
                    return Err(e);
                }
                log::debug!("{} failed ({:#}), trying next pinentry", program, e);
                last_err = Some(e);
            }
        }
    }

    if let Some(e) = last_err {
        Err(e).context(format!(
            "all pinentry candidates failed (tried: {})",
            candidates.join(", ")
        ))
    } else {
        anyhow::bail!(
            "no pinentry program found (tried: {})",
            candidates.join(", ")
        );
    }
}

fn is_user_cancel(e: &anyhow::Error) -> bool {
    let s = format!("{:#}", e);
    s.contains("cancelled by user")
}

/// Run the Assuan conversation with a specific pinentry program.
///
/// Returns `Ok(None)` if the program itself cannot be spawned (e.g. not
/// on `PATH`), so the caller can try the next candidate. Returns
/// `Err(..)` for protocol errors or user cancellation — those must not
/// cascade to the next candidate.
fn try_pinentry_with(
    program: &str,
    description: &str,
    prompt: &str,
) -> Result<Option<Zeroizing<String>>> {
    let mut child = match Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

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

    Ok(Some(passphrase))
}

/// Fallback: prompt on terminal via rpassword-style read.
fn rpassword_prompt(prompt: &str) -> Result<Zeroizing<String>> {
    let pass = rpassword::prompt_password(format!("{}: ", prompt))
        .context("Failed to read passphrase from terminal")?;
    Ok(Zeroizing::new(pass))
}

/// Format an ISO/IEC 7816-6 cardholder name for human display.
///
/// OpenPGP cards store the cardholder name per ISO/IEC 7816-6 §8.2:
/// `Surname<<GivenNames` with `<` standing in for spaces within each
/// component, and optional trailing `<` characters padding the field.
/// Display convention is given names first, then surname.
///
/// Handles single-component names (no `<<`), missing surname, missing
/// given names, multi-word components, and trailing padding.
///
/// Examples:
///   "Das<<Kushal"           → "Kushal Das"
///   "Van<Der<Berg<<Kushal"  → "Kushal Van Der Berg"
///   "Madonna"               → "Madonna"
///   "<<Kushal"              → "Kushal"
///   "Das<<"                 → "Das"
///   "Das<<<<<<"             → "Das"
///   ""                      → ""
pub fn format_cardholder_name(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('<');
    if trimmed.is_empty() {
        return String::new();
    }

    match trimmed.split_once("<<") {
        Some((surname, given)) => {
            let surname = surname.replace('<', " ").trim().to_string();
            let given = given.replace('<', " ").trim().to_string();
            match (given.is_empty(), surname.is_empty()) {
                (false, false) => format!("{} {}", given, surname),
                (false, true) => given,
                (true, false) => surname,
                (true, true) => String::new(),
            }
        }
        None => trimmed.replace('<', " ").trim().to_string(),
    }
}

#[cfg(test)]
mod cardholder_tests {
    use super::format_cardholder_name;

    #[test]
    fn full_surname_given() {
        assert_eq!(format_cardholder_name("Das<<Kushal"), "Kushal Das");
    }

    #[test]
    fn multi_word_surname() {
        assert_eq!(
            format_cardholder_name("Van<Der<Berg<<Kushal"),
            "Kushal Van Der Berg"
        );
    }

    #[test]
    fn multi_word_given() {
        assert_eq!(
            format_cardholder_name("Das<<Kushal<Sunil"),
            "Kushal Sunil Das"
        );
    }

    #[test]
    fn single_name_no_separator() {
        assert_eq!(format_cardholder_name("Madonna"), "Madonna");
    }

    #[test]
    fn only_given_name() {
        assert_eq!(format_cardholder_name("<<Kushal"), "Kushal");
    }

    #[test]
    fn only_surname() {
        assert_eq!(format_cardholder_name("Das<<"), "Das");
    }

    #[test]
    fn trailing_padding_stripped() {
        assert_eq!(format_cardholder_name("Das<<Kushal<<<<"), "Kushal Das");
        assert_eq!(format_cardholder_name("Das<<<<<<"), "Das");
    }

    #[test]
    fn empty_input() {
        assert_eq!(format_cardholder_name(""), "");
        assert_eq!(format_cardholder_name("<<<"), "");
    }

    #[test]
    fn single_given_name_no_surname_with_spaces() {
        assert_eq!(format_cardholder_name("<<Kushal<Das"), "Kushal Das");
    }
}

#[cfg(test)]
mod cache_helper_tests {
    //! Coverage for the agent cache helpers in their no-agent branch.
    //!
    //! When no agent is listening on `~/.tumpa/agent.sock`, the helpers
    //! must silently no-op rather than panic or block. This is the
    //! contract callers in gpg/sign and gpg/decrypt rely on.
    use super::{try_agent_clear_at_path, try_agent_put_at_path};
    use std::path::Path;
    use zeroize::Zeroizing;

    fn unreachable_socket_path() -> &'static Path {
        Path::new("/proc/tumpa-cli-pinentry-tests/no-such-socket.sock")
    }

    #[test]
    fn cache_passphrase_no_agent_is_silent() {
        let pass = Zeroizing::new("ignored".to_string());
        try_agent_put_at_path(unreachable_socket_path(), "AAAAAAAAAAAAAAAA", &pass);
    }

    #[test]
    fn clear_cached_passphrase_no_agent_is_silent() {
        try_agent_clear_at_path(unreachable_socket_path(), "AAAAAAAAAAAAAAAA");
    }
}

#[cfg(test)]
mod get_passphrase_policy_tests {
    use super::{cache_key_for_slot, cache_slot_for_prompt, should_use_agent_cache, CacheSlot};

    #[test]
    fn admin_pin_skips_agent_cache() {
        assert!(!should_use_agent_cache("Admin PIN"));
        assert!(!should_use_agent_cache("admin pin"));
    }

    #[test]
    fn user_pin_and_passphrase_still_use_agent_cache() {
        assert!(should_use_agent_cache("PIN"));
        assert!(should_use_agent_cache("Passphrase"));
    }

    #[test]
    fn pin_and_passphrase_use_distinct_cache_slots() {
        assert_eq!(cache_slot_for_prompt("PIN"), Some(CacheSlot::Pin));
        assert_eq!(
            cache_slot_for_prompt("Passphrase"),
            Some(CacheSlot::Passphrase)
        );
        assert_eq!(cache_key_for_slot("ABCDEF", CacheSlot::Pin), "pin:ABCDEF");
        assert_eq!(
            cache_key_for_slot("ABCDEF", CacheSlot::Passphrase),
            "passphrase:ABCDEF"
        );
    }
}
