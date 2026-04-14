use std::collections::HashMap;

use zeroize::Zeroizing;

/// In-memory cache for passphrases and card PINs.
///
/// - Card PINs are keyed by card ident (e.g., "MANUFACTURER:SERIAL")
/// - Software key passphrases are keyed by certificate fingerprint
///
/// All values use Zeroizing<String> for automatic zeroing on drop.
#[derive(Default)]
pub struct CredentialCache {
    entries: HashMap<String, Zeroizing<String>>,
}

impl CredentialCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a credential (passphrase or PIN).
    pub fn store(&mut self, key: &str, value: Zeroizing<String>) {
        self.entries.insert(key.to_string(), value);
    }

    /// Retrieve a cached credential.
    pub fn get(&self, key: &str) -> Option<&Zeroizing<String>> {
        self.entries.get(key)
    }

    /// Remove a cached credential (e.g., when card is reconnected).
    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Clear all cached credentials for a specific card ident.
    pub fn clear_card(&mut self, card_ident: &str) {
        self.entries.remove(card_ident);
    }
}
