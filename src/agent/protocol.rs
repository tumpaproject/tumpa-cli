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
}

/// A response from the agent to a client.
pub enum Response {
    Passphrase(Zeroizing<String>),
    NotFound,
    Ok,
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

    None
}

/// Format a response for sending to a client.
pub fn format_response(response: &Response) -> String {
    match response {
        Response::Passphrase(pass) => format!("PASSPHRASE {}\n", base64_encode(pass.as_bytes())),
        Response::NotFound => "NOT_FOUND\n".to_string(),
        Response::Ok => "OK\n".to_string(),
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

#[cfg(test)]
mod tests {
    use super::{parse_request, Request};

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
}
