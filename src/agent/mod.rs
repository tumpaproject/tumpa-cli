pub mod protocol;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::cache::CredentialCache;

/// Default agent socket path: ~/.tumpa/agent.sock
pub fn default_socket_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    let tumpa_dir = home.join(".tumpa");
    std::fs::create_dir_all(&tumpa_dir)?;
    Ok(tumpa_dir.join("agent.sock"))
}

/// Run the unified agent.
///
/// Always starts the GPG passphrase cache on `~/.tumpa/agent.sock`.
/// If `ssh` is true, also starts the SSH agent.
pub async fn run_agent(
    ssh: bool,
    ssh_host: Option<String>,
    cache_ttl: u64,
    keystore_path: Option<PathBuf>,
) -> Result<()> {
    let cache = Arc::new(Mutex::new(CredentialCache::new()));
    let socket_path = default_socket_path()?;

    // Remove stale socket
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }

    // Set restrictive umask for socket creation
    let old_umask = unsafe { libc::umask(0o177) };

    let listener = UnixListener::bind(&socket_path)
        .context(format!("Failed to bind {:?}", socket_path))?;

    // Restore umask
    unsafe {
        libc::umask(old_umask);
    }

    eprintln!("Agent listening on {:?}", socket_path);
    eprintln!("Cache TTL: {} seconds", cache_ttl);

    // Start background cache sweep task
    let sweep_cache = cache.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            if let Ok(mut c) = sweep_cache.lock() {
                let removed = c.sweep(cache_ttl);
                if removed > 0 {
                    log::info!("Cache sweep: removed {} expired entries", removed);
                }
            }
        }
    });

    // Start SSH agent if requested
    if ssh {
        let ssh_cache = cache.clone();
        let ssh_host = ssh_host.unwrap_or_else(|| {
            let runtime = format!("/run/user/{}", unsafe { libc::getuid() });
            let dir = if std::path::Path::new(&runtime).exists() {
                runtime
            } else {
                dirs::home_dir()
                    .map(|h| h.join(".tumpa").to_string_lossy().to_string())
                    .unwrap_or_else(|| "/tmp".to_string())
            };
            format!("unix://{}/tcli-ssh.sock", dir)
        });

        let ks_path = keystore_path.clone();
        tokio::spawn(async move {
            if let Err(e) =
                crate::ssh::run_agent_with_cache(&ssh_host, ks_path, ssh_cache).await
            {
                eprintln!("SSH agent error: {}", e);
            }
        });
    }

    // GPG cache protocol listener
    let gpg_cache = cache.clone();
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let client_cache = gpg_cache.clone();
                let ttl = cache_ttl;
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, client_cache, ttl).await {
                        log::debug!("Client error: {}", e);
                    }
                });
            }
            Err(e) => {
                log::warn!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    cache: Arc<Mutex<CredentialCache>>,
    _ttl: u64,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let response = if let Some(request) = protocol::parse_request(&line) {
            match request {
                protocol::Request::Get { fingerprint } => {
                    let cache = cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                    match cache.get(&fingerprint) {
                        Some(pass) => protocol::Response::Passphrase(pass.clone()),
                        None => protocol::Response::NotFound,
                    }
                }
                protocol::Request::Put {
                    fingerprint,
                    passphrase,
                } => {
                    let mut cache =
                        cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                    cache.store(&fingerprint, passphrase);
                    protocol::Response::Ok
                }
                protocol::Request::Clear { fingerprint } => {
                    let mut cache =
                        cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                    cache.remove(&fingerprint);
                    protocol::Response::Ok
                }
            }
        } else {
            protocol::Response::NotFound
        };

        let response_str = protocol::format_response(&response);
        writer.write_all(response_str.as_bytes()).await?;
        line.clear();
    }

    Ok(())
}
