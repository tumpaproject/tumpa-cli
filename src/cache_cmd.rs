//! `tcli cache` subcommand handlers.
//!
//! Talks to the running `tcli agent` over `~/.tumpa/agent.sock` using the
//! line protocol defined in [`crate::agent::protocol`].

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use crate::agent;
use crate::agent::protocol;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Clear cache entries on the running agent.
///
/// - `target = None` → send a single `CLEAR_ALL` and wipe the entire cache.
/// - `target = Some(fp)` → send three `CLEAR_PASSPHRASE` requests, one for the
///   raw fingerprint and one for each `pin:` / `passphrase:` slot, so callers
///   don't need to know the cache-key namespacing.
pub fn cmd_cache_clear(target: Option<&str>) -> Result<()> {
    let socket_path = agent::default_socket_path()?;

    if !socket_path.exists() {
        bail!(
            "Agent socket {} does not exist. Start it with `tcli agent`.",
            socket_path.display()
        );
    }

    match target {
        None => {
            send_line(&socket_path, "CLEAR_ALL\n")?;
            eprintln!("Cleared all cached credentials.");
        }
        Some(fp) => {
            let fp = fp.trim();
            if !is_valid_fingerprint(fp) {
                bail!(
                    "{:?} is not a valid fingerprint (expected 40 or 16 hex characters).",
                    fp
                );
            }
            // Cache producers (gpg/sign.rs, gpg/decrypt.rs, …) always pass
            // `key_info.fingerprint` from the keystore, which is uppercase.
            // Normalise here so a user pasting a lowercase fingerprint
            // actually clears the entries instead of silently no-op'ing.
            let fp = fp.to_uppercase();
            for cache_key in cache_keys_for_fingerprint(&fp) {
                send_line(&socket_path, &format!("CLEAR_PASSPHRASE {cache_key}\n"))?;
            }
            eprintln!("Cleared cached credentials for {fp}.");
        }
    }

    Ok(())
}

fn is_valid_fingerprint(s: &str) -> bool {
    matches!(s.len(), 16 | 40) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Three cache keys an entry tied to `fp` may live under: bare fingerprint,
/// `pin:<fp>`, and `passphrase:<fp>`. Caller must have already normalised
/// `fp` to the case the agent stores under (uppercase).
fn cache_keys_for_fingerprint(fp: &str) -> [String; 3] {
    [
        fp.to_string(),
        format!("pin:{fp}"),
        format!("passphrase:{fp}"),
    ]
}

fn send_line(socket_path: &Path, request: &str) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to agent at {}", socket_path.display()))?;

    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .context("Failed to set socket read timeout")?;
    stream
        .set_write_timeout(Some(REQUEST_TIMEOUT))
        .context("Failed to set socket write timeout")?;

    stream
        .write_all(request.as_bytes())
        .context("Failed to send request to agent")?;

    let mut response = String::new();
    BufReader::new(&stream)
        .read_line(&mut response)
        .context("Failed to read response from agent")?;

    match protocol::parse_response(&response) {
        Some(protocol::Response::Ok) => Ok(()),
        Some(_) => Err(anyhow!(
            "Unexpected response from agent: {}",
            response.trim()
        )),
        None => Err(anyhow!(
            "Agent returned an unparseable response: {:?}",
            response
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{cache_keys_for_fingerprint, is_valid_fingerprint};

    #[test]
    fn fingerprint_validator_accepts_both_cases_and_lengths() {
        assert!(is_valid_fingerprint("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"));
        assert!(is_valid_fingerprint("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"));
        assert!(is_valid_fingerprint("ABCDABCDABCDABCD"));
        assert!(is_valid_fingerprint("abcdabcdabcdabcd"));
    }

    #[test]
    fn fingerprint_validator_rejects_garbage() {
        assert!(!is_valid_fingerprint(""));
        assert!(!is_valid_fingerprint("ABCD"));
        assert!(!is_valid_fingerprint("not-hex-not-hex"));
        // length 41 — must reject (a leading 0xnnnn… form would slip through
        // otherwise and shift cache-key namespacing).
        assert!(!is_valid_fingerprint(
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDA"
        ));
        // injection attempts
        assert!(!is_valid_fingerprint(
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABC\n"
        ));
        assert!(!is_valid_fingerprint(
            "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABC "
        ));
    }

    #[test]
    fn cache_keys_for_fingerprint_emits_three_namespaced_variants() {
        let keys = cache_keys_for_fingerprint("ABCDABCDABCDABCD");
        assert_eq!(keys[0], "ABCDABCDABCDABCD");
        assert_eq!(keys[1], "pin:ABCDABCDABCDABCD");
        assert_eq!(keys[2], "passphrase:ABCDABCDABCDABCD");
    }

    // Pins L-1 from DIFFERENTIAL_REVIEW_CACHE_CLEAR_2026-04-29.md: a user
    // typing a lowercase fingerprint must produce the same cache keys as a
    // signer storing entries via `key_info.fingerprint` (uppercase).
    #[test]
    fn lowercase_user_input_normalises_to_match_keystore_casing() {
        let user_input = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let normalised = user_input.to_uppercase();
        let keys = cache_keys_for_fingerprint(&normalised);
        assert_eq!(keys[0], "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD");
        assert!(keys[1].starts_with("pin:ABCD"));
        assert!(keys[2].starts_with("passphrase:ABCD"));
    }
}
