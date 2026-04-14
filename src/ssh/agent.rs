use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sha2::Digest;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Signature};

use crate::cache::CredentialCache;
use crate::pinentry;
use crate::store;

/// SSH agent backend serving keys from the tumpa keystore and OpenPGP cards.
#[derive(Clone)]
pub struct TumpaBackend {
    keystore_path: Option<PathBuf>,
    cache: Arc<Mutex<CredentialCache>>,
}

impl TumpaBackend {
    pub fn new(keystore_path: Option<PathBuf>) -> Self {
        Self {
            keystore_path,
            cache: Arc::new(Mutex::new(CredentialCache::new())),
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for TumpaBackend {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        log::debug!("request_identities");

        let mut identities = Vec::new();

        // 1. Collect card identities via wecanencrypt
        if let Ok(cards) = wecanencrypt::card::list_all_cards() {
            for card_summary in &cards {
                // Get full card details to read the auth key
                if let Ok(card_info) = wecanencrypt::card::get_card_details(Some(&card_summary.ident)) {
                    if let Some(ref auth_fp) = card_info.authentication_fingerprint {
                        log::debug!("Card {} has auth key {}", card_summary.ident, auth_fp);
                        // We need the public key from the card - try to find it in keystore
                        if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
                            if let Ok(Some(cert_data)) = keystore.find_by_subkey_fingerprint(auth_fp) {
                                if let Ok(ssh_pubkey) = wecanencrypt::get_ssh_pubkey(&cert_data, Some(&card_summary.ident)) {
                                    if let Ok(key_data) = parse_ssh_pubkey_line(&ssh_pubkey) {
                                        identities.push(Identity {
                                            pubkey: key_data,
                                            comment: format!("card:{}", card_summary.ident),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Collect keystore identities (software keys with auth subkeys)
        if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
            if let Ok(secret_keys) = keystore.list_secret_keys() {
                for cert_info in &secret_keys {
                    // Check if this key has an authentication subkey
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

        // Try to find the matching key in the keystore
        if let Ok(keystore) = store::open_keystore(self.keystore_path.as_ref()) {
            if let Ok(secret_keys) = keystore.list_secret_keys() {
                for cert_info in &secret_keys {
                    if let Ok(cert_data) = keystore.export_cert(&cert_info.fingerprint) {
                        // Check if this key's SSH pubkey matches the request
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
                let pass = pinentry::get_passphrase(&desc, "Passphrase")
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
