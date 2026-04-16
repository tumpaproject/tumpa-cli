use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::Digest;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Extension, Identity, SignRequest};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Signature};

use crate::cache::CredentialCache;
use crate::pinentry;
use crate::store;

/// SSH agent backend serving keys from the tumpa keystore and OpenPGP cards.
///
/// Tracks connected card state between requests to detect card
/// removal/reconnection and clear stale cached PINs.
#[derive(Clone)]
pub struct TumpaBackend {
    keystore_path: Option<PathBuf>,
    cache: Arc<Mutex<CredentialCache>>,
    /// Maps card ident -> auth key fingerprint last seen on that card.
    /// Used to detect card removal and key changes between requests.
    card_state: Arc<Mutex<HashMap<String, String>>>,
    /// Cached card enumeration results with timestamp.
    /// Reused if the last enumeration was less than 1 second ago,
    /// avoiding redundant card SELECTs between identities() and sign().
    cached_cards: Arc<Mutex<(Instant, Vec<(wecanencrypt::card::CardSummary, wecanencrypt::card::CardInfo)>)>>,
}

impl TumpaBackend {
    pub fn new(keystore_path: Option<PathBuf>) -> Self {
        Self {
            keystore_path,
            cache: Arc::new(Mutex::new(CredentialCache::new())),
            card_state: Arc::new(Mutex::new(HashMap::new())),
            cached_cards: Arc::new(Mutex::new((Instant::now(), Vec::new()))),
        }
    }

    /// Create a backend with a shared credential cache.
    /// Used when the SSH agent runs alongside the GPG cache agent.
    pub fn with_cache(
        keystore_path: Option<PathBuf>,
        cache: Arc<Mutex<CredentialCache>>,
    ) -> Self {
        Self {
            keystore_path,
            cache,
            card_state: Arc::new(Mutex::new(HashMap::new())),
            cached_cards: Arc::new(Mutex::new((Instant::now(), Vec::new()))),
        }
    }

    /// Maximum age of cached card enumeration before re-querying.
    /// Avoids redundant card SELECTs when identities() and sign()
    /// are called in quick succession (typical SSH flow).
    const CARD_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(1);

    /// Detect card removal or key changes since the last request, and
    /// return the current card list with full details.
    ///
    /// If the last enumeration was less than 1 second ago, returns
    /// the cached results without touching the card. Otherwise
    /// re-enumerates and updates the cache.
    ///
    /// Compares the currently connected cards against the previously
    /// seen state. If a card was removed or its auth key fingerprint
    /// changed, the cached PIN for that card is cleared so the user
    /// is prompted again via pinentry on next use.
    ///
    /// Returns the enumerated cards so callers don't need to re-query.
    fn detect_card_changes(
        &self,
    ) -> Vec<(wecanencrypt::card::CardSummary, wecanencrypt::card::CardInfo)> {
        // Return cached results if fresh enough
        if let Ok(cached) = self.cached_cards.lock() {
            if cached.0.elapsed() < Self::CARD_CACHE_TTL && !cached.1.is_empty() {
                return cached.1.clone();
            }
        }

        let current_cards = wecanencrypt::card::list_all_cards().unwrap_or_default();

        // Fetch full details for each card (one SELECT per card)
        let mut cards_with_info = Vec::new();
        for card in &current_cards {
            if let Ok(info) = wecanencrypt::card::get_card_details(Some(&card.ident)) {
                cards_with_info.push((card.clone(), info));
            }
        }

        // Update the cache
        if let Ok(mut cached) = self.cached_cards.lock() {
            *cached = (Instant::now(), cards_with_info.clone());
        }

        let Ok(mut state) = self.card_state.lock() else {
            return cards_with_info;
        };
        let Ok(mut cache) = self.cache.lock() else {
            return cards_with_info;
        };

        // Build current map: ident -> auth_fp
        let current: HashMap<String, String> = cards_with_info
            .iter()
            .filter_map(|(summary, info)| {
                info.authentication_fingerprint
                    .as_ref()
                    .map(|fp| (summary.ident.clone(), fp.clone()))
            })
            .collect();

        // Check for removed or changed cards
        let previous_idents: Vec<String> = state.keys().cloned().collect();
        for ident in &previous_idents {
            match current.get(ident) {
                None => {
                    // Card was removed
                    log::info!("Card {} removed, clearing cached PIN", ident);
                    cache.remove(ident);
                    state.remove(ident);
                }
                Some(new_fp) => {
                    if let Some(old_fp) = state.get(ident) {
                        if old_fp != new_fp {
                            // Auth key changed (card swapped in same reader)
                            log::info!(
                                "Card {} auth key changed ({} -> {}), clearing cached PIN",
                                ident, old_fp, new_fp
                            );
                            cache.remove(ident);
                        }
                    }
                }
            }
        }

        // Update state to current
        *state = current;

        cards_with_info
    }
}

#[ssh_agent_lib::async_trait]
impl Session for TumpaBackend {
    async fn extension(&mut self, _extension: Extension) -> Result<Option<Extension>, AgentError> {
        // OpenSSH probes for agent extensions; we don't support any.
        // Return Ok(None) instead of the default error to avoid noisy logs.
        Ok(None)
    }

    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        log::debug!("request_identities");

        let cards = self.detect_card_changes();

        let mut identities = Vec::new();

        // 1. Collect card identities (using data already fetched by detect_card_changes)
        log::info!("Found {} card(s)", cards.len());
        for (card_summary, card_info) in &cards {
            log::info!("Card: {} ({})", card_summary.ident, card_summary.manufacturer_name);
            log::info!("  sig_fp: {:?}, auth_fp: {:?}", card_info.signature_fingerprint, card_info.authentication_fingerprint);
            if let Some(ref auth_fp) = card_info.authentication_fingerprint {
                let auth_fp_upper = auth_fp.to_uppercase();
                match store::open_keystore(self.keystore_path.as_ref()) {
                    Ok(keystore) => {
                        match keystore.find_by_subkey_fingerprint(&auth_fp_upper) {
                            Ok(Some(cert_data)) => {
                                match wecanencrypt::get_ssh_pubkey(&cert_data, Some(&card_summary.ident)) {
                                    Ok(ssh_pubkey) => {
                                        match parse_ssh_pubkey_line(&ssh_pubkey) {
                                            Ok(key_data) => {
                                                log::info!("  Added card SSH identity");
                                                identities.push(Identity {
                                                    pubkey: key_data,
                                                    comment: format!("card:{}", card_summary.ident),
                                                });
                                            }
                                            Err(e) => log::warn!("  Failed to parse SSH pubkey: {}", e),
                                        }
                                    }
                                    Err(e) => log::warn!("  Failed to get SSH pubkey from cert: {}", e),
                                }
                            }
                            Ok(None) => log::warn!("  Auth subkey {} not found in keystore", auth_fp_upper),
                            Err(e) => log::warn!("  Keystore lookup failed: {}", e),
                        }
                    }
                    Err(e) => log::warn!("  Failed to open keystore: {}", e),
                }
            } else {
                log::info!("  No authentication fingerprint on card");
            }
        }

        // 2. Collect keystore identities (software keys with auth subkeys)
        if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
            if let Ok(secret_keys) = keystore.list_secret_keys() {
                for cert_info in &secret_keys {
                    // Skip revoked keys
                    if cert_info.is_revoked {
                        continue;
                    }

                    // Check if this key has a non-revoked authentication subkey
                    let has_auth = cert_info.subkeys.iter().any(|sk| {
                        matches!(sk.key_type, wecanencrypt::KeyType::Authentication) && !sk.is_revoked
                    });
                    if !has_auth {
                        continue;
                    }

                    if let Ok(cert_data) = keystore.export_cert(&cert_info.fingerprint) {
                        if let Ok(ssh_pubkey) = wecanencrypt::get_ssh_pubkey(
                            &cert_data,
                            Some(
                                cert_info
                                    .user_ids
                                    .first()
                                    .map(|u| u.value.as_str())
                                    .unwrap_or(&cert_info.fingerprint),
                            ),
                        ) {
                            if let Ok(key_data) = parse_ssh_pubkey_line(&ssh_pubkey) {
                                let comment = cert_info
                                    .user_ids
                                    .first()
                                    .map(|u| u.value.clone())
                                    .unwrap_or_else(|| cert_info.fingerprint.clone());
                                identities.push(Identity {
                                    pubkey: key_data,
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

        let cards = self.detect_card_changes();

        // Check if a card holds this authentication key (using already-fetched data)
        for (card_summary, card_info) in &cards {
            if let Some(ref auth_fp) = card_info.authentication_fingerprint {
                let auth_fp_upper = auth_fp.to_uppercase();
                if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
                    if let Ok(Some(cert_data)) =
                        keystore.find_by_subkey_fingerprint(&auth_fp_upper)
                    {
                        if let Ok(ssh_pubkey) = wecanencrypt::get_ssh_pubkey(
                            &cert_data,
                            Some(&card_summary.ident),
                        ) {
                            if let Ok(key_data) = parse_ssh_pubkey_line(&ssh_pubkey) {
                                if key_data == request.pubkey {
                                    let holder = card_info.cardholder_name.as_deref();
                                    return self
                                        .sign_with_card(
                                            &card_summary.ident,
                                            holder,
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

        // No card match -- try software keys from keystore
        if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
            if let Ok(secret_keys) = keystore.list_secret_keys() {
                for cert_info in &secret_keys {
                    if cert_info.is_revoked {
                        continue;
                    }
                    if let Ok(cert_data) = keystore.export_cert(&cert_info.fingerprint) {
                        let comment = cert_info
                            .user_ids
                            .first()
                            .map(|u| u.value.as_str())
                            .unwrap_or(&cert_info.fingerprint);
                        if let Ok(ssh_pubkey_line) =
                            wecanencrypt::get_ssh_pubkey(&cert_data, Some(comment))
                        {
                            if let Ok(key_data) = parse_ssh_pubkey_line(&ssh_pubkey_line) {
                                if key_data == request.pubkey {
                                    return self
                                        .sign_with_software_key(
                                            &cert_data,
                                            &cert_info.fingerprint,
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
            // Get PIN -- check cache on first attempt, always prompt on retries
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
                // Clear bad PIN and re-prompt
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

            // Try the card operation
            let result = match &request.pubkey {
                KeyData::Rsa(_) => {
                    let hash = match sign_data.hash_alg {
                        wecanencrypt::SshHashAlgorithm::Sha256 => {
                            wecanencrypt::card::CardHash::SHA256(
                                sign_data.data.clone().try_into().map_err(|_| {
                                    AgentError::Failure
                                })?,
                            )
                        }
                        wecanencrypt::SshHashAlgorithm::Sha512 => {
                            wecanencrypt::card::CardHash::SHA512(
                                sign_data.data.clone().try_into().map_err(|_| {
                                    AgentError::Failure
                                })?,
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
                    // PIN worked -- cache it and return the signature
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

        // All retries exhausted
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
            KeyData::Rsa(_) => {
                Signature::new(sign_data.algorithm.clone(), raw_sig.to_vec()).map_err(AgentError::other)
            }
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

                // Card returns r || s concatenated; extract and build SSH signature
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
        cert_data: &[u8],
        fingerprint: &str,
        key_description: &str,
        request: &SignRequest,
    ) -> Result<Signature, AgentError> {
        // Get passphrase - check cache first
        let passphrase = {
            let cache = self.cache.lock().map_err(|_| AgentError::Failure)?;
            cache.get(fingerprint).cloned()
        };

        let passphrase = match passphrase {
            Some(p) => p,
            None => {
                let desc = format!("Enter passphrase for SSH key {}", key_description);
                let pass = pinentry::get_passphrase(&desc, "Passphrase", None)
                    .map_err(|e| {
                        log::error!("Failed to get passphrase: {}", e);
                        AgentError::Failure
                    })?;

                // Cache it
                let mut cache = self.cache.lock().map_err(|_| AgentError::Failure)?;
                cache.store(fingerprint, pass.clone());
                pass
            }
        };

        // Determine what data to pass to ssh_sign_raw based on the algorithm
        let sign_data = prepare_sign_data(request).ok_or(AgentError::Failure)?;

        let result = wecanencrypt::ssh_sign_raw(
            cert_data,
            &sign_data.data,
            &passphrase,
            sign_data.hash_alg,
        )
            .map_err(|e| {
                log::error!("SSH signing failed: {}", e);
                // Clear cached passphrase on failure (might be wrong password)
                if let Ok(mut cache) = self.cache.lock() {
                    cache.remove(fingerprint);
                }
                AgentError::Failure
            })?;

        // Convert wecanencrypt's result to ssh_key::Signature
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

                // Construct the ECDSA signature from r and s scalars
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
    /// SSH algorithm for the result signature.
    algorithm: Algorithm,
    /// Data to pass to ssh_sign_raw (raw message for Ed25519, digest for others).
    data: Vec<u8>,
    /// Hash algorithm hint for RSA signing.
    hash_alg: wecanencrypt::SshHashAlgorithm,
}

/// Determine the SSH algorithm and prepare data for signing based on the request.
fn prepare_sign_data(request: &SignRequest) -> Option<SignData> {
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;
    const SSH_AGENT_RSA_SHA2_512: u32 = 4;

    match &request.pubkey {
        KeyData::Ed25519(_) => {
            // Ed25519: pass raw message (ed25519 does internal hashing)
            Some(SignData {
                algorithm: Algorithm::Ed25519,
                data: request.data.clone(),
                hash_alg: wecanencrypt::SshHashAlgorithm::Sha256, // unused for Ed25519
            })
        }
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
                hash_alg: wecanencrypt::SshHashAlgorithm::Sha256, // unused for ECDSA
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
