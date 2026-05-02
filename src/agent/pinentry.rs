//! Agent-side pinentry orchestration.
//!
//! Two responsibilities:
//!
//! 1. **Headless detection** ([`is_desktop_session`]) — on Linux,
//!    require `$DISPLAY` or `$WAYLAND_DISPLAY`; on macOS, assume yes
//!    (the tcli agent runs in the user's Aqua session by construction
//!    and `pinentry-mac` has no DISPLAY dependency). On a headless
//!    server the agent answers `PINENTRY_UNAVAILABLE` to every
//!    `GET_OR_PROMPT`, and the client falls back to env-var / local
//!    Assuan / terminal prompts.
//!
//! 2. **Prompt deduplication** ([`PromptDeduper`]) — Mail's library
//!    indexer fans out one decode per inbox message, so without
//!    serialisation the agent would race itself and pop N pinentry
//!    windows for the same key. The deduper keeps a per-`cache_key`
//!    `broadcast::Sender`; concurrent callers for the same key
//!    subscribe instead of starting their own pinentry.
//!
//! The Assuan conversation itself is delegated to
//! [`crate::pinentry::assuan::run_pinentry`], which is the same code
//! the client-side fallback uses.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};
use zeroize::Zeroizing;

use crate::pinentry::assuan::{run_pinentry, PromptOutcome};

/// Outcome of a deduper prompt — clonable so a single pinentry result
/// can be broadcast to multiple subscribers.
#[derive(Clone)]
pub enum SharedOutcome {
    Got(Zeroizing<String>),
    Cancelled,
    /// No candidate spawned. Agent reports `PINENTRY_UNAVAILABLE`.
    Unavailable,
    /// At least one candidate spawned but the conversation failed.
    /// Agent reports `ERR <message>`; clients may fall back.
    Err(String),
}

/// Decide whether the agent should attempt pinentry for a request.
///
/// Linux/BSD: at least one of `$DISPLAY` / `$WAYLAND_DISPLAY` must be
/// non-empty.
///
/// macOS: always true. The agent process is started by the user (e.g.
/// via `tcli agent` from a login shell) and inherits the Aqua session;
/// `pinentry-mac` is a Cocoa app that draws to the active session
/// without consulting `$DISPLAY`. There's no reliable way to detect
/// "no Aqua session" cheaply, but in practice the user starting the
/// agent IS the desktop user.
///
/// Other unixes: same Linux rules.
pub fn is_desktop_session() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    has_nonempty_env("DISPLAY") || has_nonempty_env("WAYLAND_DISPLAY")
}

fn has_nonempty_env(name: &str) -> bool {
    std::env::var(name).map(|v| !v.is_empty()).unwrap_or(false)
}

/// Per-cache-key prompt deduper.
///
/// `prompt(...)` is the only public entry point. When the first caller
/// for a key arrives, the deduper installs a `broadcast::Sender` and
/// runs the (blocking) pinentry conversation off-thread via
/// `tokio::task::spawn_blocking`. Any further caller arriving while
/// the conversation is in flight subscribes to the same channel and
/// awaits the same outcome. After the spawn completes, the entry is
/// removed and the result is broadcast.
#[derive(Clone, Default)]
pub struct PromptDeduper {
    inflight: Arc<Mutex<HashMap<String, broadcast::Sender<SharedOutcome>>>>,
}

impl PromptDeduper {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run a pinentry prompt, deduplicating concurrent calls for the
    /// same `cache_key`.
    ///
    /// Returns `SharedOutcome::Unavailable` when no candidate could be
    /// spawned (which the caller maps to `PINENTRY_UNAVAILABLE`).
    pub async fn prompt(
        &self,
        cache_key: &str,
        description: String,
        prompt_text: String,
        keyinfo: Option<String>,
    ) -> SharedOutcome {
        // Fast path: if a prompt is already in flight, subscribe.
        let rx = {
            let mut map = self.inflight.lock().await;
            if let Some(existing) = map.get(cache_key) {
                let rx = existing.subscribe();
                drop(map);
                return wait_or_disconnect(rx).await;
            }
            let (tx, rx) = broadcast::channel::<SharedOutcome>(1);
            map.insert(cache_key.to_string(), tx);
            rx
        };

        // Run pinentry off-thread; tokio runtime stays responsive.
        let desc = description;
        let prom = prompt_text;
        let ki = keyinfo;
        let outcome_blocking = tokio::task::spawn_blocking(move || {
            run_pinentry(&desc, &prom, ki.as_deref())
        })
        .await;

        let outcome = match outcome_blocking {
            Ok(o) => map_outcome(o),
            Err(join_err) => SharedOutcome::Err(format!("pinentry task panicked: {}", join_err)),
        };

        // Remove the in-flight entry, then broadcast. Doing this in
        // this order means a brand-new caller that arrives between
        // remove() and send() will start its own (correct) prompt
        // instead of subscribing to a channel about to drop.
        let sender = {
            let mut map = self.inflight.lock().await;
            map.remove(cache_key)
        };
        if let Some(tx) = sender {
            // Subscribers get the broadcast; the sender's own receiver
            // (rx, above) does too.
            let _ = tx.send(outcome.clone());
        }

        // Drain our own subscriber side (or just return outcome).
        drop(rx);
        outcome
    }
}

async fn wait_or_disconnect(mut rx: broadcast::Receiver<SharedOutcome>) -> SharedOutcome {
    match rx.recv().await {
        Ok(outcome) => outcome,
        Err(broadcast::error::RecvError::Closed) => {
            SharedOutcome::Err("in-flight prompt cancelled".to_string())
        }
        Err(broadcast::error::RecvError::Lagged(_)) => {
            // Capacity is 1 and we always send exactly once — lag is
            // unreachable in practice. Fall through defensively.
            SharedOutcome::Err("broadcast lagged".to_string())
        }
    }
}

fn map_outcome(o: PromptOutcome) -> SharedOutcome {
    match o {
        PromptOutcome::Got(p) => SharedOutcome::Got(p),
        PromptOutcome::Cancelled => SharedOutcome::Cancelled,
        PromptOutcome::NoCandidate => SharedOutcome::Unavailable,
        PromptOutcome::Err { message, .. } => SharedOutcome::Err(message),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_desktop_session, PromptDeduper, SharedOutcome};

    /// Save / restore DISPLAY and WAYLAND_DISPLAY together. The
    /// process-wide env is global state; tests touching it are
    /// serialised through a single global mutex. Both vars are saved
    /// and restored even if only one is being toggled, so a parallel
    /// test that read the unmutated var still sees a consistent value
    /// after this returns.
    fn with_display_env<F: FnOnce()>(display: Option<&str>, wayland: Option<&str>, f: F) {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _g = ENV_LOCK.lock().unwrap();
        let prev_d = std::env::var("DISPLAY").ok();
        let prev_w = std::env::var("WAYLAND_DISPLAY").ok();
        match display {
            Some(v) => std::env::set_var("DISPLAY", v),
            None => std::env::remove_var("DISPLAY"),
        }
        match wayland {
            Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
            None => std::env::remove_var("WAYLAND_DISPLAY"),
        }
        f();
        match prev_d {
            Some(v) => std::env::set_var("DISPLAY", v),
            None => std::env::remove_var("DISPLAY"),
        }
        match prev_w {
            Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
            None => std::env::remove_var("WAYLAND_DISPLAY"),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_no_display_is_headless() {
        with_display_env(None, None, || {
            assert!(!is_desktop_session());
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_x11_display_is_desktop() {
        with_display_env(Some(":0"), None, || {
            assert!(is_desktop_session());
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_wayland_display_is_desktop() {
        with_display_env(None, Some("wayland-0"), || {
            assert!(is_desktop_session());
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_empty_display_is_headless() {
        with_display_env(Some(""), Some(""), || {
            assert!(!is_desktop_session());
        });
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_is_always_desktop() {
        // Even with no DISPLAY set, macOS path returns true.
        with_display_env(None, None, || {
            assert!(is_desktop_session());
        });
    }

    /// Subscribe-then-broadcast: a single subscriber attached to a
    /// pre-seeded in-flight entry receives the simulated outcome.
    /// Doesn't spawn real pinentry — that would block on user input.
    #[tokio::test(flavor = "current_thread")]
    async fn deduper_subscriber_receives_broadcast() {
        let deduper = PromptDeduper::new();
        let key = "pin:0123456789ABCDEF";

        let (tx, _rx0) = tokio::sync::broadcast::channel::<SharedOutcome>(1);
        deduper
            .inflight
            .lock()
            .await
            .insert(key.to_string(), tx.clone());

        // Subscribe BEFORE sending so the broadcast value is delivered.
        let mut rx = {
            let map = deduper.inflight.lock().await;
            map.get(key).unwrap().subscribe()
        };

        if tx
            .send(SharedOutcome::Got(zeroize::Zeroizing::new(
                "123456".to_string(),
            )))
            .is_err()
        {
            panic!("broadcast send failed");
        }

        match rx.recv().await.unwrap() {
            SharedOutcome::Got(p) => assert_eq!(&*p, "123456"),
            _ => panic!("expected Got"),
        }

        deduper.inflight.lock().await.remove(key);
    }

    /// Cancelled outcomes propagate verbatim to a subscriber.
    #[tokio::test(flavor = "current_thread")]
    async fn deduper_cancelled_propagates() {
        let deduper = PromptDeduper::new();
        let key = "pin:0123456789ABCDEF";

        let (tx, _rx0) = tokio::sync::broadcast::channel::<SharedOutcome>(1);
        deduper
            .inflight
            .lock()
            .await
            .insert(key.to_string(), tx.clone());

        let mut rx = {
            let map = deduper.inflight.lock().await;
            map.get(key).unwrap().subscribe()
        };

        if tx.send(SharedOutcome::Cancelled).is_err() {
            panic!("broadcast send failed");
        }

        match rx.recv().await.unwrap() {
            SharedOutcome::Cancelled => (),
            _ => panic!("expected Cancelled"),
        }
        deduper.inflight.lock().await.remove(key);
    }
}
