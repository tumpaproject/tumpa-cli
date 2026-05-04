pub mod agent;
pub mod cache_cmd;
pub mod card_link;
pub mod card_touch;
pub mod cli;
pub mod gpg;
pub mod keystore;
pub mod list_cards;
pub mod notify;
pub mod pinentry;
pub mod sign_cmd;
pub mod ssh;
pub mod store;
#[cfg(feature = "experimental")]
pub mod upload_card;
pub mod verify_cmd;

/// In-memory credential cache (passphrases and card PINs).
///
/// Re-exported from libtumpa so existing `crate::cache::CredentialCache`
/// imports keep working after the move.
pub mod cache {
    pub use libtumpa::cache::CredentialCache;
}
