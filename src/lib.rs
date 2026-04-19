pub mod agent;
pub mod gpg;
pub mod keystore;
pub mod pinentry;
pub mod ssh;
pub mod store;

/// In-memory credential cache (passphrases and card PINs).
///
/// Re-exported from libtumpa so existing `crate::cache::CredentialCache`
/// imports keep working after the move.
pub mod cache {
    pub use libtumpa::cache::CredentialCache;
}
