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
    Err {
        message: String,
        tried: Vec<String>,
    },
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
                log::debug!("{} not on PATH, trying next pinentry", program);
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
        Err(_) => return CandidateResult::SpawnFailed,
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
    } else if line.starts_with("ERR") {
        // Distinguish user cancel from other ERRs by GnuPG error code.
        // Pinentry signals cancellation with code 83886179 (GPG_ERR_CANCELED)
        // or code 99 in some forks. We treat any ERR after GETPIN as
        // user cancel — by the time we send GETPIN the conversation is
        // healthy, so the only realistic ERRs are user-initiated.
        CandidateResult::Cancelled
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
    s.replace('%', "%25").replace('\n', "%0A").replace('\r', "%0D")
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
    fn candidates_respect_explicit_program() {
        // Save and restore env to avoid leaking into other tests.
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
