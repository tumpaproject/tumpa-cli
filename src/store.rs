use std::path::PathBuf;

use anyhow::{Context, Result};
use wecanencrypt::CertificateInfo;
use wecanencrypt::KeyType;
use wecanencrypt::KeyStore;

/// Open the tumpa keystore at the given path or default ~/.tumpa/keys.db.
pub fn open_keystore(path: Option<&PathBuf>) -> Result<KeyStore> {
    match path {
        Some(p) => KeyStore::open(p).context(format!("Failed to open keystore at {:?}", p)),
        None => {
            let home = dirs::home_dir().context("Could not determine home directory")?;
            let db_path = home.join(".tumpa").join("keys.db");
            KeyStore::open(&db_path)
                .context(format!("Failed to open keystore at {:?}", db_path))
        }
    }
}

/// Resolve a signer ID (fingerprint, key ID, or subkey fingerprint) to cert data + info.
///
/// The `id` can be:
/// - A 40-char hex fingerprint (primary key)
/// - A 16-char hex key ID
/// - A 40-char hex subkey fingerprint
/// - Any of the above prefixed with "0x"
pub fn resolve_signer(store: &KeyStore, id: &str) -> Result<(Vec<u8>, CertificateInfo)> {
    let id = id.strip_prefix("0x").unwrap_or(id);
    // wecanencrypt stores both fingerprints and key IDs in uppercase
    // (via hex::encode_upper in fingerprint_to_hex and keyid_to_hex)
    let id_upper = id.to_uppercase();

    // Try as primary fingerprint (40 hex chars)
    if id.len() == 40 {
        if let Ok((data, info)) = store.get_cert(&id_upper) {
            return Ok((data, info));
        }
    }

    // Try as key ID (16 hex chars)
    if id.len() == 16 {
        if let Ok(Some(data)) = store.find_by_key_id(&id_upper) {
            let info = wecanencrypt::parse_cert_bytes(&data, true)?;
            return Ok((data, info));
        }
    }

    // Try as subkey fingerprint - stored uppercase
    if id.len() == 40 {
        if let Ok(Some(data)) = store.find_by_subkey_fingerprint(&id_upper) {
            let info = wecanencrypt::parse_cert_bytes(&data, true)?;
            return Ok((data, info));
        }
    }

    anyhow::bail!("No key found for identifier: {}", id)
}

/// Extract the issuer fingerprint or key ID from a parsed signature config.
/// Returns a list of possible identifiers (fingerprints first, then key IDs).
pub fn extract_issuer_ids(sig: &pgp::packet::SignatureConfig) -> Vec<String> {
    let mut ids = Vec::new();

    // Issuer fingerprints (preferred)
    for fp in sig.issuer_fingerprint() {
        ids.push(hex::encode(fp.as_bytes()));
    }

    // Issuer key IDs (fallback)
    for kid in sig.issuer_key_id() {
        ids.push(hex::encode(kid));
    }

    ids
}

/// Look up a certificate in the keystore by the issuer info from a signature.
pub fn resolve_from_issuer_ids(
    store: &KeyStore,
    issuer_ids: &[String],
) -> Result<Option<(Vec<u8>, CertificateInfo)>> {
    for id in issuer_ids {
        if let Ok(result) = resolve_signer(store, id) {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub fn cert_is_expired(cert_info: &CertificateInfo) -> bool {
    cert_info
        .expiration_time
        .map(|time| time.timestamp() <= current_unix_timestamp())
        .unwrap_or(false)
}

pub fn subkey_is_expired(subkey: &wecanencrypt::SubkeyInfo) -> bool {
    subkey
        .expiration_time
        .map(|time| time.timestamp() <= current_unix_timestamp())
        .unwrap_or(false)
}

fn has_usable_subkey(cert_info: &CertificateInfo, key_type: KeyType) -> bool {
    cert_info.subkeys.iter().any(|subkey| {
        subkey.key_type == key_type && !subkey.is_revoked && !subkey_is_expired(subkey)
    })
}

pub fn ensure_cert_usable_for_signing(cert_info: &CertificateInfo) -> Result<()> {
    if cert_info.is_revoked {
        anyhow::bail!("Key {} is revoked and cannot sign new data", cert_info.fingerprint);
    }

    if cert_is_expired(cert_info) {
        anyhow::bail!("Key {} is expired and cannot sign new data", cert_info.fingerprint);
    }

    if cert_info.can_primary_sign || has_usable_subkey(cert_info, KeyType::Signing) {
        return Ok(());
    }

    anyhow::bail!(
        "Key {} has no usable signing-capable key material",
        cert_info.fingerprint
    )
}

pub fn ensure_cert_usable_for_encryption(cert_info: &CertificateInfo) -> Result<()> {
    if cert_info.is_revoked {
        anyhow::bail!(
            "Key {} is revoked and cannot be used as an encryption recipient",
            cert_info.fingerprint
        );
    }

    if cert_is_expired(cert_info) {
        anyhow::bail!(
            "Key {} is expired and cannot be used as an encryption recipient",
            cert_info.fingerprint
        );
    }

    if has_usable_subkey(cert_info, KeyType::Encryption) {
        return Ok(());
    }

    anyhow::bail!(
        "Key {} has no usable encryption-capable subkey",
        cert_info.fingerprint
    )
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use wecanencrypt::{
        create_key, create_key_simple, parse_cert_bytes, revoke_key, CipherSuite, SubkeyFlags,
    };

    use super::{ensure_cert_usable_for_encryption, ensure_cert_usable_for_signing};

    const TEST_PASSWORD: &str = "test-password";

    #[test]
    fn rejects_revoked_keys_for_signing_and_encryption() {
        let key = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let revoked = revoke_key(&key.secret_key, TEST_PASSWORD).unwrap();
        let cert_info = parse_cert_bytes(&revoked, true).unwrap();

        assert!(ensure_cert_usable_for_signing(&cert_info).is_err());
        assert!(ensure_cert_usable_for_encryption(&cert_info).is_err());
    }

    #[test]
    fn rejects_expired_certificates_for_signing_and_encryption() {
        let creation_time = Utc::now() - Duration::days(3);
        let primary_expiry = Utc::now() - Duration::days(1);
        let subkey_expiry = Utc::now() - Duration::days(1);
        let key = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            Some(primary_expiry),
            Some(subkey_expiry),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        let cert_info = parse_cert_bytes(&key.secret_key, true).unwrap();

        assert!(ensure_cert_usable_for_signing(&cert_info).is_err());
        assert!(ensure_cert_usable_for_encryption(&cert_info).is_err());
    }

    #[test]
    fn rejects_certificates_with_only_expired_subkeys() {
        let creation_time = Utc::now() - Duration::days(3);
        let subkey_expiry = Utc::now() - Duration::days(1);
        let key = create_key(
            TEST_PASSWORD,
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519,
            Some(creation_time),
            None,
            Some(subkey_expiry),
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();
        let cert_info = parse_cert_bytes(&key.secret_key, true).unwrap();

        assert!(ensure_cert_usable_for_signing(&cert_info).is_err());
        assert!(ensure_cert_usable_for_encryption(&cert_info).is_err());
    }

    #[test]
    fn accepts_non_revoked_non_expired_certificates() {
        let key = create_key_simple(TEST_PASSWORD, &["Alice <alice@example.com>"]).unwrap();
        let cert_info = parse_cert_bytes(&key.secret_key, true).unwrap();

        ensure_cert_usable_for_signing(&cert_info).unwrap();
        ensure_cert_usable_for_encryption(&cert_info).unwrap();
    }
}
