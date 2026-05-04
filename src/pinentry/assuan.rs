//! Shared pinentry / Assuan-protocol helpers.
//!
//! Used by both:
//! - the client-side fallback path in `super::get_passphrase` (when
//!   the agent is unreachable, replies `PINENTRY_UNAVAILABLE`, or
//!   replies `ERR`), and
//! - the agent-side prompt-on-miss path in
//!   `crate::agent::pinentry::PromptDeduper`.
//!
//! Centralising the candidate resolution and the Assuan conversation
//! here keeps the macOS Homebrew fallback logic from ADR-0005 in one
//! place. The previous client-only implementation lived in
//! `super::pinentry` (file `src/pinentry.rs`) before being split out.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

/// Outcome of running a pinentry conversation.
///
/// The variants intentionally mirror the agent-protocol responses so
/// the agent can map them to wire responses without re-classifying
/// errors via string matching (which the previous client-side
/// implementation did via `is_user_cancel`).
pub enum PromptOutcome {
    /// User entered a value and confirmed.
    Got(Zeroizing<String>),
    /// User pressed Cancel. Callers must NOT silently fall back to
    /// another prompt — the user explicitly declined.
    Cancelled,
    /// None of the candidate pinentry binaries could be spawned. On a
    /// headless box this is the dominant case.
    NoCandidate,
    /// At least one candidate spawned but the Assuan conversation
    /// failed (protocol error, unexpected response, broken pipe).
    /// `tried` lists the candidate names attempted, for diagnostics.
    Err { message: String, tried: Vec<String> },
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

/// Run a pinentry conversation against the first working candidate.
///
/// Iterates `pinentry_candidates()` in order. A candidate that isn't on
/// PATH (spawn failure) falls through to the next; a protocol/runtime
/// error from a spawned candidate is logged and also falls through, so
/// a broken `pinentry` (e.g. curses with no TTY) does not mask a
/// working `pinentry-mac`. User cancellation is preserved and does not
/// trigger further fallbacks.
///
/// `keyinfo` is forwarded to pinentry as `SETKEYINFO` if `Some`; some
/// pinentry implementations use it to display a "cached" badge or
/// suppress repeat prompts. We don't depend on the behaviour.
pub fn run_pinentry(description: &str, prompt: &str, keyinfo: Option<&str>) -> PromptOutcome {
    let candidates = pinentry_candidates();
    let mut last_err: Option<String> = None;

    for program in &candidates {
        match try_one(program, description, prompt, keyinfo) {
            CandidateResult::Got(p) => return PromptOutcome::Got(p),
            CandidateResult::Cancelled => return PromptOutcome::Cancelled,
            CandidateResult::SpawnFailed => {
                log::debug!("could not spawn {}, trying next pinentry", program);
            }
            CandidateResult::ProtocolErr(msg) => {
                log::debug!("{} failed ({}), trying next pinentry", program, msg);
                last_err = Some(format!("{}: {}", program, msg));
            }
        }
    }

    if let Some(msg) = last_err {
        PromptOutcome::Err {
            message: msg,
            tried: candidates,
        }
    } else {
        PromptOutcome::NoCandidate
    }
}

enum CandidateResult {
    Got(Zeroizing<String>),
    Cancelled,
    SpawnFailed,
    ProtocolErr(String),
}

fn try_one(
    program: &str,
    description: &str,
    prompt: &str,
    keyinfo: Option<&str>,
) -> CandidateResult {
    let mut child = match Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        // NotFound = binary isn't on PATH; that's the expected
        // "try the next candidate" path and not worth surfacing.
        // Anything else (permission denied, exec format error, …)
        // is an actionable failure: keep the OS error message so
        // the user can see *why* their pinentry didn't work
        // instead of a misleading "not on PATH" log line.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return CandidateResult::SpawnFailed;
        }
        Err(e) => {
            return CandidateResult::ProtocolErr(format!("spawn failed: {}", e));
        }
    };

    let stdin = match child.stdin.take() {
        Some(s) => s,
        None => return CandidateResult::ProtocolErr("Failed to open stdin".to_string()),
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => return CandidateResult::ProtocolErr("Failed to open stdout".to_string()),
    };

    let result = drive_assuan(stdin, stdout, description, prompt, keyinfo);
    let _ = child.wait();
    result
}

fn drive_assuan(
    mut stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
    description: &str,
    prompt: &str,
    keyinfo: Option<&str>,
) -> CandidateResult {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    macro_rules! err {
        ($($arg:tt)*) => {{
            let _ = writeln!(stdin, "BYE");
            return CandidateResult::ProtocolErr(format!($($arg)*));
        }};
    }

    if let Err(e) = reader.read_line(&mut line) {
        err!("greeting read failed: {}", e);
    }
    if !line.starts_with("OK") {
        err!("greeting failed: {}", line.trim());
    }

    if let Some(ki) = keyinfo {
        let escaped = assuan_escape(ki);
        if writeln!(stdin, "SETKEYINFO {}", escaped).is_err() {
            err!("SETKEYINFO write failed");
        }
        line.clear();
        if reader.read_line(&mut line).is_err() {
            err!("SETKEYINFO read failed");
        }
        // Tolerate ERR here — old pinentries may not support SETKEYINFO.
    }

    let desc_escaped = assuan_escape(description);
    if writeln!(stdin, "SETDESC {}", desc_escaped).is_err() {
        err!("SETDESC write failed");
    }
    line.clear();
    if reader.read_line(&mut line).is_err() {
        err!("SETDESC read failed");
    }

    let prompt_escaped = assuan_escape(prompt);
    if writeln!(stdin, "SETPROMPT {}", prompt_escaped).is_err() {
        err!("SETPROMPT write failed");
    }
    line.clear();
    if reader.read_line(&mut line).is_err() {
        err!("SETPROMPT read failed");
    }

    if writeln!(stdin, "GETPIN").is_err() {
        err!("GETPIN write failed");
    }
    line.clear();
    if reader.read_line(&mut line).is_err() {
        err!("GETPIN read failed");
    }

    let outcome = if let Some(data) = line.strip_prefix("D ") {
        let pass = Zeroizing::new(data.trim_end().to_string());
        // Read trailing OK after data line.
        line.clear();
        let _ = reader.read_line(&mut line);
        CandidateResult::Got(pass)
    } else if let Some(rest) = line.strip_prefix("ERR ") {
        // Pinentry distinguishes user cancellation from real errors
        // via the GPG error code: GPG_ERR_CANCELED (=83886179) when
        // libgcrypt's `gpg-error` is in use, or the bare `99`
        // returned by some pinentry forks. Anything else is a real
        // protocol/runtime failure that callers may want to surface
        // (or fall back to the next candidate for); flattening it to
        // `Cancelled` would suppress the diagnostic and block the
        // tolerant-loop fallback. The first whitespace-delimited
        // token after `ERR ` is the numeric code.
        match parse_gpg_err_code(rest) {
            Some(code) if is_cancel_code(code) => CandidateResult::Cancelled,
            _ => {
                let _ = writeln!(stdin, "BYE");
                return CandidateResult::ProtocolErr(format!("pinentry error: {}", rest.trim()));
            }
        }
    } else if line.starts_with("OK") {
        // Empty input → treat as cancel.
        CandidateResult::Cancelled
    } else {
        let _ = writeln!(stdin, "BYE");
        return CandidateResult::ProtocolErr(format!("unexpected response: {}", line.trim()));
    };

    let _ = writeln!(stdin, "BYE");
    outcome
}

fn assuan_escape(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\n', "%0A")
        .replace('\r', "%0D")
}

/// Extract the numeric error code from an Assuan `ERR ...` line tail.
///
/// Format is `ERR <code> [description]`. We parse the first
/// whitespace-delimited token as a `u32`. Returns `None` for
/// non-numeric / missing codes — callers should treat that as a
/// protocol error rather than guessing the user's intent.
fn parse_gpg_err_code(rest: &str) -> Option<u32> {
    rest.split_whitespace().next()?.parse::<u32>().ok()
}

/// Known pinentry cancel codes:
/// - `83886179` (`0x05000063`) — `GPG_ERR_CANCELED` per gpg-error.
/// - `99` — bare cancel code emitted by some pinentry forks that
///   don't compose against gpg-error's source-id encoding.
fn is_cancel_code(code: u32) -> bool {
    code == 83886179 || code == 99
}

#[cfg(test)]
mod tests {
    use super::{assuan_escape, pinentry_candidates};

    #[test]
    fn escape_quotes_percent_and_newlines() {
        assert_eq!(assuan_escape("a%b"), "a%25b");
        assert_eq!(assuan_escape("a\nb"), "a%0Ab");
        assert_eq!(assuan_escape("a\r\nb"), "a%0D%0Ab");
        assert_eq!(assuan_escape("plain"), "plain");
    }

    #[test]
    fn parse_gpg_err_code_reads_first_token() {
        use super::parse_gpg_err_code;
        assert_eq!(parse_gpg_err_code("83886179"), Some(83886179));
        assert_eq!(
            parse_gpg_err_code("83886179 Operation cancelled <Pinentry>"),
            Some(83886179)
        );
        assert_eq!(parse_gpg_err_code("99"), Some(99));
        assert_eq!(parse_gpg_err_code(""), None);
        assert_eq!(parse_gpg_err_code("not-a-number text"), None);
    }

    #[test]
    fn is_cancel_code_matches_known_values() {
        use super::is_cancel_code;
        // GPG_ERR_CANCELED with the gpg-error source-id encoding,
        // and the bare 99 some pinentry forks emit.
        assert!(is_cancel_code(83886179));
        assert!(is_cancel_code(99));
        // Other GPG error codes (e.g. GPG_ERR_BAD_PIN, source-encoded
        // as 83886187) must NOT be silently treated as cancellation,
        // otherwise `run_pinentry` would skip the tolerant-loop
        // fallback and the caller would see a Cancelled instead of
        // a re-prompt.
        assert!(!is_cancel_code(83886187));
        assert!(!is_cancel_code(0));
    }

    #[test]
    fn candidates_respect_explicit_program() {
        // Process-wide env vars are global state; serialise across
        // every test in this module that touches `PINENTRY_PROGRAM`
        // so parallel test runs don't see each other's writes. The
        // mutex is local to this test module — same shape as the
        // DISPLAY/WAYLAND lock in `agent::pinentry::tests`.
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _g = ENV_LOCK.lock().unwrap();
        let prev = std::env::var("PINENTRY_PROGRAM").ok();
        std::env::set_var("PINENTRY_PROGRAM", "/opt/custom/pinentry");
        let cands = pinentry_candidates();
        assert_eq!(cands, vec!["/opt/custom/pinentry".to_string()]);
        match prev {
            Some(p) => std::env::set_var("PINENTRY_PROGRAM", p),
            None => std::env::remove_var("PINENTRY_PROGRAM"),
        }
    }
}
