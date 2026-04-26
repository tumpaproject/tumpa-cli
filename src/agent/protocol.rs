//! GPG cache agent protocol.
//!
//! Simple line-based protocol over Unix socket:
//!
//! ```text
//! Client → Agent:  GET_PASSPHRASE <fingerprint>\n
//! Agent → Client:  PASSPHRASE <base64>\n  or  NOT_FOUND\n
//!
//! Client → Agent:  PUT_PASSPHRASE <fingerprint> <base64>\n
//! Agent → Client:  OK\n
//!
//! Client → Agent:  CLEAR_PASSPHRASE <fingerprint>\n
//! Agent → Client:  OK\n
//! ```

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Validate that a fingerprint is a hex string of 16 or 40 characters.
fn is_valid_fingerprint(s: &str) -> bool {
    let len = s.len();
    (len == 16 || len == 40) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// A request from a client to the agent.
pub enum Request {
    Get {
        fingerprint: String,
    },
    Put {
        fingerprint: String,
        passphrase: Zeroizing<String>,
    },
    Clear {
        fingerprint: String,
    },
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

    if let Some(fp) = line.strip_prefix("GET_PASSPHRASE ") {
        let fp = fp.trim();
        if is_valid_fingerprint(fp) {
            return Some(Request::Get {
                fingerprint: fp.to_string(),
            });
        }
    }

    if let Some(rest) = line.strip_prefix("PUT_PASSPHRASE ") {
        let mut parts = rest.splitn(2, ' ');
        if let (Some(fp), Some(b64)) = (parts.next(), parts.next()) {
            let fp = fp.trim();
            let b64 = b64.trim();
            if is_valid_fingerprint(fp) && !b64.is_empty() {
                if let Ok(decoded) = base64_decode(b64) {
                    return Some(Request::Put {
                        fingerprint: fp.to_string(),
                        passphrase: decoded,
                    });
                }
            }
        }
    }

    if let Some(fp) = line.strip_prefix("CLEAR_PASSPHRASE ") {
        let fp = fp.trim();
        if is_valid_fingerprint(fp) {
            return Some(Request::Clear {
                fingerprint: fp.to_string(),
            });
        }
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
