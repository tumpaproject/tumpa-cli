//! Client-side passphrase / PIN acquisition.
//!
//! Orchestrates the fallback chain:
//!
//!   1. Tumpa agent `GET_OR_PROMPT` (cache + agent-side pinentry)
//!   2. Env vars (`TUMPA_ADMIN_PIN` for admin prompts; `TUMPA_PASSPHRASE` otherwise)
//!   3. Local pinentry (`assuan::run_pinentry`)
//!   4. Terminal `rpassword` prompt
//!
//! The Assuan/pinentry plumbing is shared with the agent's
//! prompt-on-miss path via the [`assuan`] submodule.

pub mod assuan;

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::agent;
use assuan::PromptOutcome;

// Re-exports for callers that previously imported these from the
// flat-file `pinentry.rs`. Avoids touching every call site.
pub use assuan::{pinentry_candidates, resolve_pinentry};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheSlot {
    Pin,
    Passphrase,
}

/// Get a passphrase or PIN.
///
/// Acquisition order:
/// 1. Agent `GET_OR_PROMPT` (cache + agent-side pinentry, when the
///    prompt is not `"Admin PIN"` and `cache_key` is `Some`). A
///    `NOT_FOUND` reply from a pre-`GET_OR_PROMPT` agent is treated
///    the same as `PINENTRY_UNAVAILABLE`: fall through to the rest of
///    the chain.
/// 2. `TUMPA_ADMIN_PIN` env var — only when `prompt` is `"Admin PIN"`
///    (case-insensitive); skipped for any other prompt.
/// 3. `TUMPA_PASSPHRASE` env var.
/// 4. Local pinentry (`assuan::run_pinentry`).
/// 5. Terminal prompt.
///
/// `cache_key` is the key fingerprint used for the agent cache. A
/// returned value is **never written** to the cache by this function —
/// the caller must call [`cache_passphrase`] / [`cache_pin`] after a
/// successful sign/decrypt and [`clear_cached_passphrase`] /
/// [`clear_cached_pin`] after a failed one. Caching unverified values
/// would burn card PIN attempts when the user typed the wrong PIN
/// once.
pub fn get_passphrase(
    description: &str,
    prompt: &str,
    cache_key: Option<&str>,
) -> Result<Zeroizing<String>> {
    let allow_agent_cache = should_use_agent_cache(prompt);
    let cache_slot = cache_slot_for_prompt(prompt);
    let namespaced_key = match (cache_key, cache_slot) {
        (Some(k), Some(s)) if allow_agent_cache => Some(cache_key_for_slot(k, s)),
        _ => None,
    };

    // 1. Agent cache (no prompting). A cache hit is always preferred:
    //    by definition the value was confirmed correct on a previous
    //    op, so it beats whatever the env or pinentry would offer.
    if let Some(ref key) = namespaced_key {
        if let Some(pass) = try_agent_get(key) {
            log::debug!("Using passphrase from agent cache");
            return Ok(pass);
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
    // passphrases and user PINs. Env wins over the agent's
    // *interactive* prompt (step 3) so non-interactive runs
    // (tests, CI, scripted automation) never get blocked behind a
    // pinentry-mac dialog the harness can't dismiss.
    if let Ok(pass) = std::env::var("TUMPA_PASSPHRASE") {
        log::debug!("Using passphrase from TUMPA_PASSPHRASE env var");
        return Ok(Zeroizing::new(pass));
    }

    // 3. Agent-driven pinentry. Cache was already checked at step 1
    //    so this round-trip exists for the prompt path; the agent
    //    will either pop pinentry-mac (desktop session) or report
    //    PINENTRY_UNAVAILABLE (headless / no pinentry binary) and
    //    we fall through.
    if let Some(ref key) = namespaced_key {
        match try_agent_get_or_prompt(key, description, prompt) {
            AgentPromptOutcome::Got(pass) => {
                log::debug!("Got passphrase from agent (GET_OR_PROMPT)");
                return Ok(pass);
            }
            AgentPromptOutcome::Cancelled => {
                anyhow::bail!("pinentry cancelled by user");
            }
            AgentPromptOutcome::Unavailable | AgentPromptOutcome::NoAgent => {
                // Fall through.
            }
        }
    }

    // 4. Local pinentry (shared assuan helpers).
    match assuan::run_pinentry(description, prompt, None) {
        PromptOutcome::Got(pass) => return Ok(pass),
        PromptOutcome::Cancelled => anyhow::bail!("pinentry cancelled by user"),
        PromptOutcome::NoCandidate => {
            log::debug!("no pinentry program found, falling back to terminal");
        }
        PromptOutcome::Err { message, tried } => {
            log::debug!(
                "all pinentry candidates failed: {} (tried {})",
                message,
                tried.join(", ")
            );
        }
    }

    // 5. Fall back to terminal prompt.
    rpassword_prompt(prompt)
}

/// Outcome of the agent's `GET_OR_PROMPT` round-trip.
enum AgentPromptOutcome {
    /// The agent returned a value (cached or freshly-prompted).
    Got(Zeroizing<String>),
    /// The user cancelled the agent's pinentry dialog. Do NOT fall
    /// back to env vars / local pinentry / terminal — the user
    /// declined.
    Cancelled,
    /// The agent has no usable pinentry, or returned ERR. Fall back to
    /// the rest of the chain.
    Unavailable,
    /// No agent socket reachable.
    NoAgent,
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
/// successful sign or decrypt (or by an explicit verify step). Silent
/// no-op if no agent is running.
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

/// Open a connection to the agent socket with a 10-minute read timeout.
///
/// The timeout has to cover the full pinentry round-trip — the agent
/// only replies once the user finishes typing — so a short cache-style
/// timeout would spuriously kill interactive prompts. On a cache hit
/// the agent answers in milliseconds, so the long ceiling only
/// matters when humans are involved.
fn agent_connect() -> Option<UnixStream> {
    let socket_path = agent::default_socket_path().ok()?;
    let stream = UnixStream::connect(&socket_path).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(600)))
        .ok()?;
    Some(stream)
}

/// Try a cache-only `GET_PASSPHRASE` against the agent.
///
/// Used by step 1 of `get_passphrase` so a cache hit can short-circuit
/// the env-var / pinentry chain. Returns `None` when the agent is
/// unreachable, the key is not cached, or the response is unparseable.
/// The read timeout here is short (2s) since we never block on user
/// input on this path — that's the job of [`try_agent_get_or_prompt`].
fn try_agent_get(cache_key: &str) -> Option<Zeroizing<String>> {
    let socket_path = agent::default_socket_path().ok()?;
    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).ok()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .ok()?;

    let request = format!("GET_PASSPHRASE {}\n", cache_key);
    stream.write_all(request.as_bytes()).ok()?;

    let mut response = String::new();
    let mut reader = std::io::BufReader::new(&stream);
    reader.read_line(&mut response).ok()?;

    match agent::protocol::parse_response(&response) {
        Some(agent::protocol::Response::Passphrase(p)) => Some(p),
        _ => None,
    }
}

/// Try `GET_OR_PROMPT` against the agent.
fn try_agent_get_or_prompt(cache_key: &str, description: &str, prompt: &str) -> AgentPromptOutcome {
    let mut stream = match agent_connect() {
        Some(s) => s,
        None => return AgentPromptOutcome::NoAgent,
    };

    let b64_desc = agent::protocol::encode_utf8(description);
    let b64_prompt = agent::protocol::encode_utf8(prompt);
    let request = format!("GET_OR_PROMPT {} {} {}\n", cache_key, b64_desc, b64_prompt);
    if stream.write_all(request.as_bytes()).is_err() {
        return AgentPromptOutcome::NoAgent;
    }

    let mut response = String::new();
    let mut reader = std::io::BufReader::new(&stream);
    if reader.read_line(&mut response).is_err() {
        return AgentPromptOutcome::NoAgent;
    }

    match agent::protocol::parse_response(&response) {
        Some(agent::protocol::Response::Passphrase(pass)) => AgentPromptOutcome::Got(pass),
        Some(agent::protocol::Response::Cancelled) => AgentPromptOutcome::Cancelled,
        Some(agent::protocol::Response::PinentryUnavailable) => AgentPromptOutcome::Unavailable,
        Some(agent::protocol::Response::Err(msg)) => {
            log::debug!("agent GET_OR_PROMPT err: {}", msg);
            AgentPromptOutcome::Unavailable
        }
        // NOT_FOUND from an old agent (pre-GET_OR_PROMPT) → treat as
        // unavailable so the client falls through to local pinentry.
        Some(agent::protocol::Response::NotFound) => AgentPromptOutcome::Unavailable,
        _ => AgentPromptOutcome::Unavailable,
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
