//! Best-effort macOS Notification Center banner for "touch your card now"
//! prompts.
//!
//! Shells out to `terminal-notifier` (Homebrew: `brew install
//! terminal-notifier`). We used to drive `osascript -e 'display
//! notification ...'` but that posts under the calling Terminal's bundle
//! identity, so the user-facing notification appeared with the Terminal
//! icon and inherited Terminal's banner style — meaning a "banner style
//! = None" on Terminal would silently route every Tumpa prompt straight
//! to Notification Center history with no on-screen banner.
//! `terminal-notifier` ships its own bundle identity, so it gets its own
//! entry under System Settings → Notifications and the user can grant it
//! Banner / Alert style independently of Terminal's settings.
//!
//! On non-macOS builds the public function compiles to a no-op so call
//! sites don't need their own `#[cfg]` guards.

/// Which slot is about to be exercised — only used to pick the verb in the
/// notification body.
#[derive(Debug, Clone, Copy)]
pub enum TouchOp {
    Sign,
    Decrypt,
    Auth,
}

impl TouchOp {
    fn verb(self) -> &'static str {
        match self {
            TouchOp::Sign => "sign",
            TouchOp::Decrypt => "decrypt",
            TouchOp::Auth => "authenticate",
        }
    }
}

/// Post a "touch your card" banner.
///
/// Best-effort: any failure (terminal-notifier missing, user denied
/// notification permission, Focus mode suppressing) is logged but
/// never propagated — the notify path is purely UX, never load-bearing
/// for the crypto op.
///
/// On macOS we run `terminal-notifier` synchronously and capture
/// stderr so the user can see *why* a banner didn't appear when they
/// expected one. The call site runs immediately before
/// `pinentry::get_passphrase`, which blocks for human input anyway,
/// so the extra ~50–150 ms wait is invisible.
///
/// `card_serial` is rendered in the body when present; pass the
/// user-facing serial from `wecanencrypt::card::get_card_details`
/// (already a hex string straight from the card).
#[cfg(target_os = "macos")]
pub fn touch_prompt(op: TouchOp, card_serial: Option<&str>) {
    use std::process::{Command, Stdio};

    let title = "Tumpa";
    let subtitle = format!("Touch your card to {}", op.verb());
    let body = match card_serial {
        Some(s) => {
            let trimmed = last_hex(s, 8);
            format!("Card {}", trimmed)
        }
        None => "Waiting for touch confirmation".to_string(),
    };

    log::info!(
        "posting touch banner via terminal-notifier: title={title:?} subtitle={subtitle:?} body={body:?}"
    );

    // `Command::arg` uses argv directly (no shell), so `title` /
    // `subtitle` / `body` don't need escaping — quotes and special
    // characters travel as bytes.
    let result = Command::new("terminal-notifier")
        .arg("-title")
        .arg(title)
        .arg("-subtitle")
        .arg(&subtitle)
        .arg("-message")
        .arg(&body)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output();

    match result {
        Ok(out) if out.status.success() => {
            log::info!("terminal-notifier posted touch banner ok");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            log::warn!(
                "terminal-notifier exited non-zero (status={:?}); stderr={}",
                out.status.code(),
                stderr.trim()
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log::warn!(
                "terminal-notifier not found on PATH — install with `brew install terminal-notifier` to enable touch-confirmation banners"
            );
        }
        Err(e) => {
            log::warn!("could not spawn terminal-notifier: {e}");
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn touch_prompt(_op: TouchOp, _card_serial: Option<&str>) {}

/// Trim a long hex serial down to its last `n` characters so the
/// notification body stays readable. Falls back to the whole string when
/// it's already short enough.
#[cfg(target_os = "macos")]
fn last_hex(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= n {
        s.to_string()
    } else {
        chars[chars.len() - n..].iter().collect()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn last_hex_trims_long_serial() {
        assert_eq!(last_hex("0123456789ABCDEF", 8), "89ABCDEF");
    }

    #[test]
    fn last_hex_keeps_short_serial() {
        assert_eq!(last_hex("ABCD", 8), "ABCD");
    }
}
