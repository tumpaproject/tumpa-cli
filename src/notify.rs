//! Best-effort "touch your card now" banner.
//!
//! macOS: shells out to `terminal-notifier` (Homebrew: `brew install
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
//! Linux: posts via `notify-rust` → D-Bus `org.freedesktop.Notifications`.
//! `zbus`'s session-bus discovery walks `DBUS_SESSION_BUS_ADDRESS` →
//! `$XDG_RUNTIME_DIR/bus` per the D-Bus spec, so a user-systemd-started
//! agent (with or without lingering) finds the bus without extra plumbing.
//! On a headless server with no notification daemon, the call returns
//! `Err`, we log a `warn!`, and the card op proceeds unchanged.
//!
//! Other Unix / Windows: `touch_prompt` compiles to a no-op so call sites
//! don't need their own `#[cfg]` guards.
//!
//! Best-effort everywhere: any failure (terminal-notifier missing,
//! permission denied, Focus mode, D-Bus not reachable, …) is logged but
//! never propagated — the notify path is purely UX, never load-bearing
//! for the crypto op.

/// Which slot is about to be exercised -- only used to pick the verb in
/// the notification headline (macOS subtitle / Linux summary). The body
/// holds the card identifier, not the verb.
#[derive(Debug, Clone, Copy)]
pub enum TouchOp {
    Sign,
    Decrypt,
    Auth,
}

// `verb`, `render`, and `last_hex` are only used from the per-OS post
// path or from the unit tests. Gating them with the same cfg that
// guards their call sites keeps non-supported release builds free of
// `dead_code` warnings under `-D warnings` and keeps the
// "compile-time no-op" contract honest -- on those targets, nothing
// here is even compiled.
#[cfg(any(test, target_os = "macos", target_os = "linux"))]
impl TouchOp {
    fn verb(self) -> &'static str {
        match self {
            TouchOp::Sign => "sign",
            TouchOp::Decrypt => "decrypt",
            TouchOp::Auth => "authenticate",
        }
    }
}

/// Shared, pure rendering of the headline + supporting strings used in
/// the banner.
///
/// Returns `(headline, supporting)`:
///   * `headline` becomes the macOS subtitle / Linux summary — the
///     prominent action line.
///   * `supporting` becomes the macOS body / Linux body — the card
///     identifier (or a generic fallback when no serial is known).
///
/// Factored out so both platform paths produce identical text, and so
/// the rendering can be unit-tested without any system call.
#[cfg(any(test, target_os = "macos", target_os = "linux"))]
fn render(op: TouchOp, card_serial: Option<&str>) -> (String, String) {
    let headline = format!("Touch your card to {}", op.verb());
    let supporting = match card_serial {
        Some(s) => format!("Card {}", last_hex(s, 8)),
        None => "Waiting for touch confirmation".to_string(),
    };
    (headline, supporting)
}

/// Trim a long hex serial down to its last `n` characters so the
/// notification body stays readable. Falls back to the whole string
/// when it's already short enough.
#[cfg(any(test, target_os = "macos", target_os = "linux"))]
fn last_hex(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= n {
        s.to_string()
    } else {
        chars[chars.len() - n..].iter().collect()
    }
}

/// Post a "touch your card" banner.
///
/// Best-effort: any failure is logged but never propagated. On platforms
/// where there is no notification path (other Unix, Windows), this is a
/// true compile-time no-op -- the function does not even render strings
/// or emit a log line; nothing happens at the call site.
///
/// `card_serial` is rendered in the body when present; pass the
/// user-facing serial from `wecanencrypt::card::get_card_details`
/// (already a hex string straight from the card).
pub fn touch_prompt(op: TouchOp, card_serial: Option<&str>) {
    // Single `info!` line per banner attempt lives here in the
    // dispatcher; the per-backend post functions log only `debug!` on
    // success and `warn!` on failure so a successful run produces one
    // info line per touch-required op, not two.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let (headline, supporting) = render(op, card_serial);
        log::info!("touch banner: op={op:?} headline={headline:?} body={supporting:?}");

        #[cfg(target_os = "macos")]
        post_macos(&headline, &supporting);

        #[cfg(target_os = "linux")]
        post_linux(&headline, &supporting);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (op, card_serial);
    }
}

/// Post via `terminal-notifier` synchronously. We capture stderr so the
/// user can see *why* a banner didn't appear when they expected one.
/// The call site runs immediately before `pinentry::get_passphrase`,
/// which blocks for human input anyway, so the extra ~50–150 ms wait is
/// invisible.
#[cfg(target_os = "macos")]
fn post_macos(headline: &str, supporting: &str) {
    use std::process::{Command, Stdio};

    let title = "tumpa-cli";

    // `Command::arg` uses argv directly (no shell), so `title` /
    // `headline` / `supporting` don't need escaping — quotes and special
    // characters travel as bytes.
    let result = Command::new("terminal-notifier")
        .arg("-title")
        .arg(title)
        .arg("-subtitle")
        .arg(headline)
        .arg("-message")
        .arg(supporting)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .output();

    match result {
        Ok(out) if out.status.success() => {
            log::debug!("terminal-notifier posted touch banner ok");
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

/// Post via `notify-rust` → D-Bus. `urgency = Normal` and no explicit
/// `expire_timeout` so the user's notification daemon decides how long
/// the banner stays up. `dialog-password` is the freedesktop stock
/// "auth-needed" icon name and is present in adwaita / breeze / papirus
/// / numix.
///
/// `Notification::show()` returns a `NotificationHandle`; we drop it
/// immediately because we don't manage its lifetime (no replace, no
/// explicit close). On a headless server with no D-Bus session bus or no
/// notification daemon, this returns `Err` — we warn and continue, and
/// the card op proceeds unchanged.
#[cfg(target_os = "linux")]
fn post_linux(headline: &str, supporting: &str) {
    use notify_rust::{Notification, Urgency};

    let result = Notification::new()
        .appname("tumpa-cli")
        .summary(headline)
        .body(supporting)
        .icon("dialog-password")
        .urgency(Urgency::Normal)
        .show();

    match result {
        Ok(_handle) => {
            log::debug!("notify-rust posted touch banner ok");
        }
        Err(e) => {
            log::warn!(
                "could not post touch banner via notify-rust ({e}); \
                 card op proceeds normally"
            );
        }
    }
}

#[cfg(test)]
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

    #[test]
    fn render_uses_action_verb_in_headline() {
        let (headline, body) = render(TouchOp::Sign, Some("0123456789ABCDEF"));
        assert_eq!(headline, "Touch your card to sign");
        assert_eq!(body, "Card 89ABCDEF");

        let (headline, _) = render(TouchOp::Decrypt, None);
        assert_eq!(headline, "Touch your card to decrypt");

        let (headline, _) = render(TouchOp::Auth, None);
        assert_eq!(headline, "Touch your card to authenticate");
    }

    #[test]
    fn render_without_serial_uses_fallback_body() {
        let (_, body) = render(TouchOp::Sign, None);
        assert_eq!(body, "Waiting for touch confirmation");
    }
}
