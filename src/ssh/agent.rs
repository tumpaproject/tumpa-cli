use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sha2::Digest;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Extension, Identity, SignRequest};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Signature};

use crate::cache::CredentialCache;
use crate::pinentry;
use crate::store;

/// Pre-resolved card SSH identity, cached in memory.
#[derive(Clone, Debug)]
struct CardSshIdentity {
    card_ident: String,
    cardholder_name: Option<String>,
    ssh_key_data: KeyData,
    comment: String,
}

/// SSH agent backend serving keys from the tumpa keystore and OpenPGP cards.
///
/// Card identities are enumerated once at startup and cached. On each
/// `request_identities()` call, only `list_all_cards()` (1 SELECT) is
/// called to check if the card set changed — full re-enumeration happens
/// only when cards are added, removed, or swapped. `sign()` uses the
/// cache directly with zero card I/O.
#[derive(Clone)]
pub struct TumpaBackend {
    keystore_path: Option<PathBuf>,
    cache: Arc<Mutex<CredentialCache>>,
    /// Cached card SSH identities. Updated on startup and when
    /// `request_identities` detects a card set change.
    card_identities: Arc<Mutex<Vec<CardSshIdentity>>>,
    /// Card ident set from the last enumeration, used to detect changes.
    known_card_idents: Arc<Mutex<HashSet<String>>>,
}

impl TumpaBackend {
    pub fn new(keystore_path: Option<PathBuf>) -> Self {
        let backend = Self {
            keystore_path,
            cache: Arc::new(Mutex::new(CredentialCache::new())),
            card_identities: Arc::new(Mutex::new(Vec::new())),
            known_card_idents: Arc::new(Mutex::new(HashSet::new())),
        };
        backend.refresh_card_identities();
        backend
    }

    /// Create a backend with a shared credential cache.
    /// Used when the SSH agent runs alongside the GPG cache agent.
    pub fn with_cache(
        keystore_path: Option<PathBuf>,
        cache: Arc<Mutex<CredentialCache>>,
    ) -> Self {
        let backend = Self {
            keystore_path,
            cache,
            card_identities: Arc::new(Mutex::new(Vec::new())),
            known_card_idents: Arc::new(Mutex::new(HashSet::new())),
        };
        backend.refresh_card_identities();
        backend
    }

    /// Full card enumeration: list cards, get details, resolve SSH pubkeys.
    ///
    /// Called at startup and when `check_card_changes` detects the card
    /// set has changed. Updates `card_identities` and `known_card_idents`.
    /// Also clears stale cached PINs for removed/swapped cards.
    fn refresh_card_identities(&self) {
        let cards = wecanencrypt::card::list_all_cards().unwrap_or_default();
        let current_idents: HashSet<String> = cards.iter().map(|c| c.ident.clone()).collect();

        let mut new_identities = Vec::new();

        for card in &cards {
            if let Ok(info) = wecanencrypt::card::get_card_details(Some(&card.ident)) {
                log::info!(
                    "Card {} ({}): auth_fp={:?}",
                    card.ident,
                    card.manufacturer_name,
                    info.authentication_fingerprint
                );
                if let Some(ref auth_fp) = info.authentication_fingerprint {
                    let auth_fp_upper = auth_fp.to_uppercase();
                    if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
                        if let Ok(Some(key_data)) =
                            keystore.find_by_subkey_fingerprint(&auth_fp_upper)
                        {
                            if let Ok(ssh_pubkey) =
                                wecanencrypt::get_ssh_pubkey(&key_data, Some(&card.ident))
                            {
                                if let Ok(parsed_pubkey) = parse_ssh_pubkey_line(&ssh_pubkey) {
                                    log::info!("  Cached SSH identity for card {}", card.ident);
                                    new_identities.push(CardSshIdentity {
                                        card_ident: card.ident.clone(),
                                        cardholder_name: info.cardholder_name.clone(),
                                        ssh_key_data: parsed_pubkey,
                                        comment: format!("card:{}", card.ident),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clear stale PINs for cards that disappeared
        if let (Ok(old_idents), Ok(mut pin_cache)) =
            (self.known_card_idents.lock(), self.cache.lock())
        {
            for ident in old_idents.iter() {
                if !current_idents.contains(ident) {
                    log::info!("Card {} removed, clearing cached PIN", ident);
                    pin_cache.remove(ident);
                }
            }
        }

        if let Ok(mut ids) = self.card_identities.lock() {
            *ids = new_identities;
        }
        if let Ok(mut known) = self.known_card_idents.lock() {
            *known = current_idents;
        }
    }

    /// Quick check: has the set of connected cards changed?
    ///
    /// Calls only `list_all_cards()` (1 SELECT) and compares the ident
    /// set against the cached set. If different, triggers a full
    /// `refresh_card_identities()`.
    fn check_card_changes(&self) {
        let cards = wecanencrypt::card::list_all_cards().unwrap_or_default();
        let current_idents: HashSet<String> = cards.iter().map(|c| c.ident.clone()).collect();

        let changed = match self.known_card_idents.lock() {
            Ok(known) => *known != current_idents,
            Err(_) => true,
        };

        if changed {
            log::info!("Card set changed, refreshing identities");
            self.refresh_card_identities();
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for TumpaBackend {
    async fn extension(&mut self, _extension: Extension) -> Result<Option<Extension>, AgentError> {
        Ok(None)
    }

    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        log::debug!("request_identities");

        // Quick check if cards changed (1 SELECT only)
        self.check_card_changes();

        let mut identities = Vec::new();

        // 1. Card identities from cache (zero additional card I/O)
        if let Ok(card_ids) = self.card_identities.lock() {
            for id in card_ids.iter() {
                identities.push(Identity {
                    pubkey: id.ssh_key_data.clone(),
                    comment: id.comment.clone(),
                });
            }
        }

        // 2. Software key identities from keystore
        if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
            if let Ok(secret_keys) = keystore.list_secret_keys() {
                for key_info in &secret_keys {
                    if key_info.is_revoked {
                        continue;
                    }

                    let has_auth = key_info.subkeys.iter().any(|sk| {
                        matches!(sk.key_type, wecanencrypt::KeyType::Authentication)
                            && !sk.is_revoked
                    });
                    if !has_auth {
                        continue;
                    }

                    if let Ok(key_data) = keystore.export_key(&key_info.fingerprint) {
                        if let Ok(ssh_pubkey) = wecanencrypt::get_ssh_pubkey(
                            &key_data,
                            Some(
                                key_info
                                    .user_ids
                                    .first()
                                    .map(|u| u.value.as_str())
                                    .unwrap_or(&key_info.fingerprint),
                            ),
                        ) {
                            if let Ok(parsed_pubkey) = parse_ssh_pubkey_line(&ssh_pubkey) {
                                let comment = key_info
                                    .user_ids
                                    .first()
                                    .map(|u| u.value.clone())
                                    .unwrap_or_else(|| key_info.fingerprint.clone());
                                identities.push(Identity {
                                    pubkey: parsed_pubkey,
                                    comment,
                                });
                            }
                        }
                    }
                }
            }
        }

        log::info!("Returning {} identities", identities.len());
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        log::debug!("sign request for pubkey {:?}", request.pubkey.algorithm());

        // Look up card_ident from cache (zero card I/O)
        let card_match = {
            let card_ids = self.card_identities.lock().map_err(|_| AgentError::Failure)?;
            card_ids
                .iter()
                .find(|id| id.ssh_key_data == request.pubkey)
                .cloned()
        };

        if let Some(card_id) = card_match {
            return self
                .sign_with_card(
                    &card_id.card_ident,
                    card_id.cardholder_name.as_deref(),
                    &request,
                )
                .await;
        }

        // Cache miss — maybe a new card was just plugged in.
        // Re-enumerate and try again.
        self.refresh_card_identities();
        let card_match = {
            let card_ids = self.card_identities.lock().map_err(|_| AgentError::Failure)?;
            card_ids
                .iter()
                .find(|id| id.ssh_key_data == request.pubkey)
                .cloned()
        };

        if let Some(card_id) = card_match {
            return self
                .sign_with_card(
                    &card_id.card_ident,
                    card_id.cardholder_name.as_deref(),
                    &request,
                )
                .await;
        }

        // No card match — try software keys from keystore
        if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
            if let Ok(secret_keys) = keystore.list_secret_keys() {
                for key_info in &secret_keys {
                    if key_info.is_revoked {
                        continue;
                    }
                    if let Ok(key_data) = keystore.export_key(&key_info.fingerprint) {
                        let comment = key_info
                            .user_ids
                            .first()
                            .map(|u| u.value.as_str())
                            .unwrap_or(&key_info.fingerprint);
                        if let Ok(ssh_pubkey_line) =
                            wecanencrypt::get_ssh_pubkey(&key_data, Some(comment))
                        {
                            if let Ok(parsed_pubkey) = parse_ssh_pubkey_line(&ssh_pubkey_line) {
                                if parsed_pubkey == request.pubkey {
                                    return self
                                        .sign_with_software_key(
                                            &key_data,
                                            &key_info.fingerprint,
                                            comment,
                                            &request,
                                        )
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
        }

        log::debug!("No matching key found for sign request");
        Err(AgentError::Failure)
    }
}

impl TumpaBackend {
    /// Sign an SSH authentication request using a hardware OpenPGP card.
    ///
    /// Retries up to 3 times if the PIN is wrong, prompting via pinentry
    /// each time.
    async fn sign_with_card(
        &self,
        card_ident: &str,
        cardholder_name: Option<&str>,
        request: &SignRequest,
    ) -> Result<Signature, AgentError> {
        log::info!("Signing with card {}", card_ident);

        const MAX_PIN_RETRIES: u32 = 3;
        let sign_data = prepare_sign_data(request).ok_or(AgentError::Failure)?;

        let mut last_error = String::new();

        for attempt in 0..MAX_PIN_RETRIES {
            let pin = if attempt == 0 {
                let cached = {
                    let cache = self.cache.lock().map_err(|_| AgentError::Failure)?;
                    cache.get(card_ident).cloned()
                };
                match cached {
                    Some(p) => p,
                    None => {
                        let holder = cardholder_name.filter(|n| !n.is_empty());
                        let desc = if let Some(name) = holder {
                            format!("Please unlock the card\n\n{}\n\nSSH authentication", name)
                        } else {
                            "Please unlock the card\n\nSSH authentication".to_string()
                        };
                        pinentry::get_passphrase(&desc, "PIN", None).map_err(|e| {
                            log::error!("Failed to get card PIN: {}", e);
                            AgentError::Failure
                        })?
                    }
                }
            } else {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.remove(card_ident);
                }
                let desc = format!(
                    "Wrong PIN for card {} (attempt {}/{}). Try again",
                    card_ident,
                    attempt + 1,
                    MAX_PIN_RETRIES
                );
                pinentry::get_passphrase(&desc, "PIN", None).map_err(|e| {
                    log::error!("Failed to get card PIN: {}", e);
                    AgentError::Failure
                })?
            };

            let result = match &request.pubkey {
                KeyData::Rsa(_) => {
                    let hash = match sign_data.hash_alg {
                        wecanencrypt::SshHashAlgorithm::Sha256 => {
                            wecanencrypt::card::CardHash::SHA256(
                                sign_data
                                    .data
                                    .clone()
                                    .try_into()
                                    .map_err(|_| AgentError::Failure)?,
                            )
                        }
                        wecanencrypt::SshHashAlgorithm::Sha512 => {
                            wecanencrypt::card::CardHash::SHA512(
                                sign_data
                                    .data
                                    .clone()
                                    .try_into()
                                    .map_err(|_| AgentError::Failure)?,
                            )
                        }
                    };
                    wecanencrypt::card::ssh_authenticate_for_hash_on_card(
                        hash,
                        pin.as_bytes(),
                        Some(card_ident),
                    )
                }
                _ => wecanencrypt::card::ssh_authenticate_on_card(
                    &sign_data.data,
                    pin.as_bytes(),
                    Some(card_ident),
                ),
            };

            match result {
                Ok(raw_sig) => {
                    if let Ok(mut cache) = self.cache.lock() {
                        cache.store(card_ident, pin);
                    }
                    return self.card_sig_to_ssh(&request.pubkey, &raw_sig, &sign_data);
                }
                Err(e) => {
                    last_error = e.to_string();
                    log::warn!(
                        "Card auth attempt {}/{} failed: {}",
                        attempt + 1,
                        MAX_PIN_RETRIES,
                        last_error
                    );
                }
            }
        }

        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(card_ident);
        }
        log::error!(
            "Card auth failed after {} attempts: {}",
            MAX_PIN_RETRIES,
            last_error
        );
        Err(AgentError::Failure)
    }

    /// Convert raw card signature bytes to an SSH `Signature`.
    fn card_sig_to_ssh(
        &self,
        pubkey: &KeyData,
        raw_sig: &[u8],
        sign_data: &SignData,
    ) -> Result<Signature, AgentError> {
        match pubkey {
            KeyData::Ed25519(_) => {
                Signature::new(Algorithm::Ed25519, raw_sig.to_vec()).map_err(AgentError::other)
            }
            KeyData::Rsa(_) => Signature::new(sign_data.algorithm.clone(), raw_sig.to_vec())
                .map_err(AgentError::other),
            KeyData::Ecdsa(ecdsa) => {
                let (curve, field_size) = match ecdsa {
                    ssh_key::public::EcdsaPublicKey::NistP256(_) => {
                        (ssh_key::EcdsaCurve::NistP256, 32)
                    }
                    ssh_key::public::EcdsaPublicKey::NistP384(_) => {
                        (ssh_key::EcdsaCurve::NistP384, 48)
                    }
                    ssh_key::public::EcdsaPublicKey::NistP521(_) => {
                        (ssh_key::EcdsaCurve::NistP521, 66)
                    }
                };

                let len = raw_sig.len();
                let r = &raw_sig[0..len / 2];
                let r = &r[r.len().saturating_sub(field_size)..];
                let s = &raw_sig[len / 2..];
                let s = &s[s.len().saturating_sub(field_size)..];

                use sha2::digest::generic_array::GenericArray;
                let sig: Signature = match curve {
                    ssh_key::EcdsaCurve::NistP256 => p256::ecdsa::Signature::from_scalars(
                        GenericArray::clone_from_slice(r),
                        GenericArray::clone_from_slice(s),
                    )
                    .map_err(AgentError::other)?
                    .try_into()
                    .map_err(AgentError::other)?,
                    ssh_key::EcdsaCurve::NistP384 => p384::ecdsa::Signature::from_scalars(
                        GenericArray::clone_from_slice(r),
                        GenericArray::clone_from_slice(s),
                    )
                    .map_err(AgentError::other)?
                    .try_into()
                    .map_err(AgentError::other)?,
                    ssh_key::EcdsaCurve::NistP521 => p521::ecdsa::Signature::from_scalars(
                        GenericArray::clone_from_slice(r),
                        GenericArray::clone_from_slice(s),
                    )
                    .map_err(AgentError::other)?
                    .try_into()
                    .map_err(AgentError::other)?,
                };
                Ok(sig)
            }
            _ => {
                log::error!("Unsupported key type for card signing");
                Err(AgentError::Failure)
            }
        }
    }

    async fn sign_with_software_key(
        &self,
        key_data: &[u8],
        fingerprint: &str,
        key_description: &str,
        request: &SignRequest,
    ) -> Result<Signature, AgentError> {
        let passphrase = {
            let cache = self.cache.lock().map_err(|_| AgentError::Failure)?;
            cache.get(fingerprint).cloned()
        };

        let passphrase = match passphrase {
            Some(p) => p,
            None => {
                let desc = format!("Enter passphrase for SSH key {}", key_description);
                let pass = pinentry::get_passphrase(&desc, "Passphrase", None).map_err(|e| {
                    log::error!("Failed to get passphrase: {}", e);
                    AgentError::Failure
                })?;

                let mut cache = self.cache.lock().map_err(|_| AgentError::Failure)?;
                cache.store(fingerprint, pass.clone());
                pass
            }
        };

        let sign_data = prepare_sign_data(request).ok_or(AgentError::Failure)?;

        let result = wecanencrypt::ssh_sign_raw(
            key_data,
            &sign_data.data,
            &passphrase,
            sign_data.hash_alg,
        )
        .map_err(|e| {
            log::error!("SSH signing failed: {}", e);
            if let Ok(mut cache) = self.cache.lock() {
                cache.remove(fingerprint);
            }
            AgentError::Failure
        })?;

        match result {
            wecanencrypt::SshSignResult::Ed25519(sig_bytes) => {
                Signature::new(Algorithm::Ed25519, sig_bytes).map_err(AgentError::other)
            }
            wecanencrypt::SshSignResult::Ecdsa { curve, r, s } => {
                let ssh_curve = match curve.as_str() {
                    "nistp256" => ssh_key::EcdsaCurve::NistP256,
                    "nistp384" => ssh_key::EcdsaCurve::NistP384,
                    "nistp521" => ssh_key::EcdsaCurve::NistP521,
                    _ => return Err(AgentError::Failure),
                };

                let sig = match ssh_curve {
                    ssh_key::EcdsaCurve::NistP256 => {
                        use sha2::digest::generic_array::GenericArray;
                        p256::ecdsa::Signature::from_scalars(
                            GenericArray::clone_from_slice(&r),
                            GenericArray::clone_from_slice(&s),
                        )
                        .map_err(AgentError::other)?
                        .try_into()
                        .map_err(AgentError::other)?
                    }
                    ssh_key::EcdsaCurve::NistP384 => {
                        use sha2::digest::generic_array::GenericArray;
                        p384::ecdsa::Signature::from_scalars(
                            GenericArray::clone_from_slice(&r),
                            GenericArray::clone_from_slice(&s),
                        )
                        .map_err(AgentError::other)?
                        .try_into()
                        .map_err(AgentError::other)?
                    }
                    ssh_key::EcdsaCurve::NistP521 => {
                        use sha2::digest::generic_array::GenericArray;
                        p521::ecdsa::Signature::from_scalars(
                            GenericArray::clone_from_slice(&r),
                            GenericArray::clone_from_slice(&s),
                        )
                        .map_err(AgentError::other)?
                        .try_into()
                        .map_err(AgentError::other)?
                    }
                };
                Ok(sig)
            }
            wecanencrypt::SshSignResult::Rsa(sig_bytes) => {
                Signature::new(sign_data.algorithm, sig_bytes).map_err(AgentError::other)
            }
        }
    }
}

/// Prepared data for an SSH signing operation.
struct SignData {
    algorithm: Algorithm,
    data: Vec<u8>,
    hash_alg: wecanencrypt::SshHashAlgorithm,
}

fn prepare_sign_data(request: &SignRequest) -> Option<SignData> {
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    match &request.pubkey {
        KeyData::Ed25519(_) => Some(SignData {
            algorithm: Algorithm::Ed25519,
            data: request.data.clone(),
            hash_alg: wecanencrypt::SshHashAlgorithm::Sha256,
        }),
        KeyData::Rsa(_) => {
            if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                let digest = sha2::Sha256::digest(&request.data).to_vec();
                Some(SignData {
                    algorithm: Algorithm::Rsa {
                        hash: Some(ssh_key::HashAlg::Sha256),
                    },
                    data: digest,
                    hash_alg: wecanencrypt::SshHashAlgorithm::Sha256,
                })
            } else if request.flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                let digest = sha2::Sha512::digest(&request.data).to_vec();
                Some(SignData {
                    algorithm: Algorithm::Rsa {
                        hash: Some(ssh_key::HashAlg::Sha512),
                    },
                    data: digest,
                    hash_alg: wecanencrypt::SshHashAlgorithm::Sha512,
                })
            } else {
                log::error!("Unsupported RSA hash flags");
                None
            }
        }
        KeyData::Ecdsa(ecdsa) => {
            let (alg, digest) = match ecdsa {
                ssh_key::public::EcdsaPublicKey::NistP256(_) => (
                    Algorithm::Ecdsa {
                        curve: ssh_key::EcdsaCurve::NistP256,
                    },
                    sha2::Sha256::digest(&request.data).to_vec(),
                ),
                ssh_key::public::EcdsaPublicKey::NistP384(_) => (
                    Algorithm::Ecdsa {
                        curve: ssh_key::EcdsaCurve::NistP384,
                    },
                    sha2::Sha384::digest(&request.data).to_vec(),
                ),
                ssh_key::public::EcdsaPublicKey::NistP521(_) => (
                    Algorithm::Ecdsa {
                        curve: ssh_key::EcdsaCurve::NistP521,
                    },
                    sha2::Sha512::digest(&request.data).to_vec(),
                ),
            };
            Some(SignData {
                algorithm: alg,
                data: digest,
                hash_alg: wecanencrypt::SshHashAlgorithm::Sha256,
            })
        }
        _ => {
            log::error!("Unsupported key type for SSH signing");
            None
        }
    }
}

/// Parse an SSH public key line ("ssh-ed25519 AAAA... comment") into KeyData.
fn parse_ssh_pubkey_line(line: &str) -> Result<KeyData, String> {
    let line = line.trim();
    let pubkey = ssh_key::PublicKey::from_openssh(line)
        .map_err(|e| format!("Failed to parse SSH public key: {}", e))?;
    Ok(pubkey.key_data().clone())
}
