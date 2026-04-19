//! Thin `anyhow`-flavoured facade over `libtumpa::store`.
//!
//! All real keystore-open + key-resolution logic lives in libtumpa; this
//! module exists so existing `crate::store::*` call sites in tumpa-cli
//! keep their `anyhow::Result` ergonomics without touching every caller.

use std::path::PathBuf;

use anyhow::{Context, Result};
use wecanencrypt::{KeyInfo, KeyStore, SubkeyInfo};

pub fn open_keystore(path: Option<&PathBuf>) -> Result<KeyStore> {
    libtumpa::store::open_keystore(path.map(|p| p.as_path()))
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("Failed to open keystore")
}

pub fn resolve_signer(store: &KeyStore, id: &str) -> Result<(Vec<u8>, KeyInfo)> {
    libtumpa::store::resolve_signer(store, id).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn extract_issuer_ids(sig: &pgp::packet::SignatureConfig) -> Vec<String> {
    libtumpa::store::extract_issuer_ids(sig)
}

pub fn resolve_from_issuer_ids(
    store: &KeyStore,
    issuer_ids: &[String],
) -> Result<Option<(Vec<u8>, KeyInfo)>> {
    libtumpa::store::resolve_from_issuer_ids(store, issuer_ids).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn key_is_expired(key_info: &KeyInfo) -> bool {
    libtumpa::store::key_is_expired(key_info)
}

pub fn subkey_is_expired(subkey: &SubkeyInfo) -> bool {
    libtumpa::store::subkey_is_expired(subkey)
}

pub fn ensure_key_usable_for_signing(key_info: &KeyInfo) -> Result<()> {
    libtumpa::store::ensure_key_usable_for_signing(key_info).map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn ensure_key_usable_for_encryption(key_info: &KeyInfo) -> Result<()> {
    libtumpa::store::ensure_key_usable_for_encryption(key_info).map_err(|e| anyhow::anyhow!("{e}"))
}
