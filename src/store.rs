use std::path::PathBuf;

use anyhow::{Context, Result};
use wecanencrypt::CertificateInfo;
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
