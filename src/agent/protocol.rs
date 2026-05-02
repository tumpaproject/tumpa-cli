//! GPG cache agent protocol.
//!
//! Simple line-based protocol over Unix socket:
//!
//! ```text
//! Client → Agent:  GET_PASSPHRASE <cache-key>\n
//! Agent → Client:  PASSPHRASE <base64>\n  or  NOT_FOUND\n
//!
//! Client → Agent:  PUT_PASSPHRASE <cache-key> <base64>\n
//! Agent → Client:  OK\n
//!
//! Client → Agent:  CLEAR_PASSPHRASE <cache-key>\n
//! Agent → Client:  OK\n
//!
//! Client → Agent:  CLEAR_ALL\n
//! Agent → Client:  OK\n
//!
//! Client → Agent:  GET_OR_PROMPT <cache-key> <b64-desc> <b64-prompt> [<b64-keyinfo>]\n
//! Agent → Client:  PASSPHRASE <base64>\n
//!                  or  PINENTRY_UNAVAILABLE\n  (no desktop / no pinentry binary)
//!                  or  CANCELLED\n              (user pressed Cancel)
//!                  or  ERR <base64-message>\n   (spawn / Assuan error)
//! ```

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Validate an agent cache key.
///
/// Raw fingerprint keys are 16 or 40 hex chars. Namespaced cache keys use
/// `<slot>:<fingerprint>`, where slot is `pin` or `passphrase`.
fn is_valid_cache_key(s: &str) -> bool {
    fn is_valid_fingerprint(s: &str) -> bool {
        let len = s.len();
        (len == 16 || len == 40) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    if is_valid_fingerprint(s) {
        return true;
    }

    let Some((slot, fingerprint)) = s.split_once(':') else {
        return false;
    };

    matches!(slot, "pin" | "passphrase") && is_valid_fingerprint(fingerprint)
}

/// A request from a client to the agent.
pub enum Request {
    Get {
        cache_key: String,
    },
    Put {
        cache_key: String,
        passphrase: Zeroizing<String>,
    },
    Clear {
        cache_key: String,
    },
    ClearAll,
    /// Cache lookup with pinentry fallback. On a cache miss, the agent
    /// drives a pinentry conversation and returns the user-typed value
    /// — but does NOT cache it. The caller is responsible for verifying
    /// the value (e.g. card VERIFY APDU or sequoia secret-key unlock)
    /// and issuing PUT_PASSPHRASE only after verification succeeds, so
    /// a wrong PIN typed once cannot replay across N indexer-driven
    /// decode calls and burn the smartcard's attempt counter.
    GetOrPrompt {
        cache_key: String,
        description: String,
        prompt: String,
        keyinfo: Option<String>,
    },
}

/// A response from the agent to a client.
pub enum Response {
    Passphrase(Zeroizing<String>),
    NotFound,
    Ok,
    /// Agent has no usable pinentry (server / headless / spawn failed).
    /// The client should fall back to its own prompt path (env vars,
    /// local Assuan, terminal).
    PinentryUnavailable,
    /// User pressed Cancel in the pinentry dialog. Clients MUST NOT
    /// fall back to another prompt — the user explicitly declined.
    Cancelled,
    /// An unexpected error happened while running pinentry on the
    /// agent. Clients MAY fall back to their own prompt path; the
    /// message is for diagnostics only.
    Err(String),
}

/// Parse a request line from a client.
pub fn parse_request(line: &str) -> Option<Request> {
    let line = line.trim();

    if let Some(cache_key) = line.strip_prefix("GET_PASSPHRASE ") {
        let cache_key = cache_key.trim();
        if is_valid_cache_key(cache_key) {
            return Some(Request::Get {
                cache_key: cache_key.to_string(),
            });
        }
    }

    if let Some(rest) = line.strip_prefix("PUT_PASSPHRASE ") {
        let mut parts = rest.splitn(2, ' ');
        if let (Some(cache_key), Some(b64)) = (parts.next(), parts.next()) {
            let cache_key = cache_key.trim();
            let b64 = b64.trim();
            if is_valid_cache_key(cache_key) && !b64.is_empty() {
                if let Ok(decoded) = base64_decode(b64) {
                    return Some(Request::Put {
                        cache_key: cache_key.to_string(),
                        passphrase: decoded,
                    });
                }
            }
        }
    }

    if let Some(cache_key) = line.strip_prefix("CLEAR_PASSPHRASE ") {
        let cache_key = cache_key.trim();
        if is_valid_cache_key(cache_key) {
            return Some(Request::Clear {
                cache_key: cache_key.to_string(),
            });
        }
    }

    if line == "CLEAR_ALL" {
        return Some(Request::ClearAll);
    }

    if let Some(rest) = line.strip_prefix("GET_OR_PROMPT ") {
        // `split_whitespace` collapses runs of spaces / tabs and skips
        // empty fields, so the parser tolerates senders that emit
        // double-spaces (or other inter-token whitespace) without
        // rejecting otherwise-valid requests.
        let parts: Vec<&str> = rest.split_whitespace().collect();
        // Three required (cache_key, desc, prompt) + optional keyinfo.
        if parts.len() != 3 && parts.len() != 4 {
            return None;
        }
        let cache_key = parts[0];
        let b64_desc = parts[1];
        let b64_prompt = parts[2];
        let b64_keyinfo = parts.get(3).copied();

        if !is_valid_cache_key(cache_key) {
            return None;
        }
        // Description and prompt are required and must decode to UTF-8.
        let description = base64_decode_utf8(b64_desc).ok()?;
        let prompt = base64_decode_utf8(b64_prompt).ok()?;
        let keyinfo = match b64_keyinfo {
            Some(s) if !s.is_empty() => Some(base64_decode_utf8(s).ok()?),
            _ => None,
        };

        return Some(Request::GetOrPrompt {
            cache_key: cache_key.to_string(),
            description,
            prompt,
            keyinfo,
        });
    }

    None
}

/// Format a response for sending to a client.
pub fn format_response(response: &Response) -> String {
    match response {
        Response::Passphrase(pass) => format!("PASSPHRASE {}\n", base64_encode(pass.as_bytes())),
        Response::NotFound => "NOT_FOUND\n".to_string(),
        Response::Ok => "OK\n".to_string(),
        Response::PinentryUnavailable => "PINENTRY_UNAVAILABLE\n".to_string(),
        Response::Cancelled => "CANCELLED\n".to_string(),
        Response::Err(msg) => format!("ERR {}\n", base64_encode(msg.as_bytes())),
    }
}

/// Parse a response line from the agent.
pub fn parse_response(line: &str) -> Option<Response> {
    let line = line.trim();

    if let Some(b64) = line.strip_prefix("PASSPHRASE ") {
        if let Ok(decoded) = base64_decode(b64.trim()) {
            return Some(Response::Passphrase(decoded));
        }
    }

    if line == "NOT_FOUND" {
        return Some(Response::NotFound);
    }

    if line == "OK" {
        return Some(Response::Ok);
    }

    if line == "PINENTRY_UNAVAILABLE" {
        return Some(Response::PinentryUnavailable);
    }

    if line == "CANCELLED" {
        return Some(Response::Cancelled);
    }

    if let Some(b64) = line.strip_prefix("ERR ") {
        if let Ok(msg) = base64_decode_utf8(b64.trim()) {
            return Some(Response::Err(msg));
        }
    }

    None
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Result<Zeroizing<String>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("Invalid base64")?;
    let s = String::from_utf8(bytes).context("Invalid UTF-8")?;
    Ok(Zeroizing::new(s))
}

fn base64_decode_utf8(s: &str) -> Result<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("Invalid base64")?;
    String::from_utf8(bytes).context("Invalid UTF-8")
}

/// Encode a UTF-8 string as base64 for use in a request or response.
///
/// Public so client and server side share the same encoding for
/// description / prompt / error message arguments.
pub fn encode_utf8(s: &str) -> String {
    base64_encode(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{
        encode_utf8, format_response, parse_request, parse_response, Request, Response,
    };
    use zeroize::Zeroizing;

    #[test]
    fn parse_request_accepts_namespaced_cache_keys() {
        let get = parse_request("GET_PASSPHRASE pin:0123456789ABCDEF\n");
        assert!(matches!(
            get,
            Some(Request::Get { cache_key }) if cache_key == "pin:0123456789ABCDEF"
        ));

        let put = parse_request("PUT_PASSPHRASE passphrase:0123456789ABCDEF c2VjcmV0\n");
        assert!(matches!(
            put,
            Some(Request::Put { cache_key, .. }) if cache_key == "passphrase:0123456789ABCDEF"
        ));

        let clear =
            parse_request("CLEAR_PASSPHRASE passphrase:0123456789ABCDEF0123456789ABCDEF01234567\n");
        assert!(matches!(
            clear,
            Some(Request::Clear { cache_key })
                if cache_key == "passphrase:0123456789ABCDEF0123456789ABCDEF01234567"
        ));
    }

    #[test]
    fn parse_request_rejects_invalid_namespaced_cache_keys() {
        assert!(parse_request("GET_PASSPHRASE other:0123456789ABCDEF\n").is_none());
        assert!(parse_request("GET_PASSPHRASE pin:not-hex\n").is_none());
    }

    #[test]
    fn parse_request_accepts_clear_all() {
        assert!(matches!(
            parse_request("CLEAR_ALL\n"),
            Some(Request::ClearAll)
        ));
        assert!(matches!(
            parse_request("CLEAR_ALL"),
            Some(Request::ClearAll)
        ));
    }

    #[test]
    fn parse_request_clear_all_does_not_swallow_garbage_suffix() {
        // "CLEAR_ALL extra" is not a valid request — the verb takes no argument.
        assert!(parse_request("CLEAR_ALL extra\n").is_none());
    }

    #[test]
    fn parse_request_accepts_get_or_prompt_minimal() {
        let desc = encode_utf8("Card 0006:12345678 — please enter your PIN.");
        let prompt = encode_utf8("PIN");
        let line = format!("GET_OR_PROMPT pin:0123456789ABCDEF {} {}\n", desc, prompt);
        match parse_request(&line) {
            Some(Request::GetOrPrompt {
                cache_key,
                description,
                prompt,
                keyinfo,
            }) => {
                assert_eq!(cache_key, "pin:0123456789ABCDEF");
                assert_eq!(description, "Card 0006:12345678 — please enter your PIN.");
                assert_eq!(prompt, "PIN");
                assert!(keyinfo.is_none());
            }
            other => panic!("expected GetOrPrompt, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn parse_request_accepts_get_or_prompt_with_keyinfo() {
        let desc = encode_utf8("Multi\nline\ndescription with non-ASCII: ✓");
        let prompt = encode_utf8("Passphrase");
        let keyinfo = encode_utf8("n/0123456789ABCDEF");
        let line = format!(
            "GET_OR_PROMPT passphrase:0123456789ABCDEF0123456789ABCDEF01234567 {} {} {}\n",
            desc, prompt, keyinfo
        );
        match parse_request(&line) {
            Some(Request::GetOrPrompt {
                description,
                prompt,
                keyinfo,
                ..
            }) => {
                assert_eq!(description, "Multi\nline\ndescription with non-ASCII: ✓");
                assert_eq!(prompt, "Passphrase");
                assert_eq!(keyinfo.as_deref(), Some("n/0123456789ABCDEF"));
            }
            _ => panic!("expected GetOrPrompt"),
        }
    }

    #[test]
    fn parse_request_rejects_get_or_prompt_with_too_few_args() {
        // Missing prompt.
        let desc = encode_utf8("hi");
        let line = format!("GET_OR_PROMPT pin:0123456789ABCDEF {}\n", desc);
        assert!(parse_request(&line).is_none());
    }

    #[test]
    fn parse_request_rejects_get_or_prompt_with_too_many_args() {
        let desc = encode_utf8("d");
        let prompt = encode_utf8("p");
        let keyinfo = encode_utf8("k");
        let extra = encode_utf8("x");
        let line = format!(
            "GET_OR_PROMPT pin:0123456789ABCDEF {} {} {} {}\n",
            desc, prompt, keyinfo, extra
        );
        assert!(parse_request(&line).is_none());
    }

    #[test]
    fn parse_request_rejects_get_or_prompt_with_invalid_base64() {
        let line = "GET_OR_PROMPT pin:0123456789ABCDEF !!notbase64!! cHJvbXB0\n";
        assert!(parse_request(line).is_none());
    }

    #[test]
    fn parse_request_rejects_get_or_prompt_with_invalid_cache_key() {
        let desc = encode_utf8("d");
        let prompt = encode_utf8("p");
        let line = format!("GET_OR_PROMPT not-a-key {} {}\n", desc, prompt);
        assert!(parse_request(&line).is_none());
    }

    #[test]
    fn format_response_round_trips_new_responses() {
        // PinentryUnavailable
        let s = format_response(&Response::PinentryUnavailable);
        assert_eq!(s, "PINENTRY_UNAVAILABLE\n");
        assert!(matches!(
            parse_response(&s),
            Some(Response::PinentryUnavailable)
        ));

        // Cancelled
        let s = format_response(&Response::Cancelled);
        assert_eq!(s, "CANCELLED\n");
        assert!(matches!(parse_response(&s), Some(Response::Cancelled)));

        // Err with non-ASCII
        let s = format_response(&Response::Err("pinentry crashed: ☠".to_string()));
        let parsed = parse_response(&s);
        match parsed {
            Some(Response::Err(msg)) => assert_eq!(msg, "pinentry crashed: ☠"),
            _ => panic!("expected Err"),
        }
    }

    #[test]
    fn format_response_passphrase_round_trips() {
        let s = format_response(&Response::Passphrase(Zeroizing::new("secret".to_string())));
        match parse_response(&s) {
            Some(Response::Passphrase(p)) => assert_eq!(&*p, "secret"),
            _ => panic!("expected Passphrase"),
        }
    }
}
