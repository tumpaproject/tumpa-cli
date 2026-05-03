pub mod decrypt;
pub mod encrypt;
pub mod keys;
pub mod sign;
pub mod verify;

/// Pick the human-facing UID for a key.
///
/// Prefers the UID flagged primary by an RFC 9580 `PrimaryUserId`
/// signature subpacket, falls back to any non-revoked UID, then to
/// the fingerprint. `wecanencrypt::parse::extract_key_info` populates
/// `user_ids` in packet order — primary is *not* guaranteed to be the
/// first entry — so callers showing a UID to the user (pinentry
/// description, status messages) must go through this helper instead
/// of `user_ids.first()`.
pub fn primary_uid(key_info: &wecanencrypt::KeyInfo) -> &str {
    key_info
        .user_ids
        .iter()
        .find(|u| u.is_primary && !u.revoked)
        .or_else(|| key_info.user_ids.iter().find(|u| !u.revoked))
        .map(|u| u.value.as_str())
        .unwrap_or(&key_info.fingerprint)
}
