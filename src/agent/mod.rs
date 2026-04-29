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
    Ok(home.join(".tumpa").join("agent.sock"))
}

/// Default SSH agent socket path.
/// Linux: /run/user/<UID>/tcli-ssh.sock
/// macOS / fallback: ~/.tumpa/tcli-ssh.sock
pub fn default_ssh_socket_path() -> Result<String> {
    let runtime = format!("/run/user/{}", unsafe { libc::getuid() });
    let dir = if std::path::Path::new(&runtime).exists() {
        runtime
    } else {
        dirs::home_dir()
            .map(|h| h.join(".tumpa").to_string_lossy().to_string())
            .unwrap_or_else(|| "/tmp".to_string())
    };
    Ok(format!("{}/tcli-ssh.sock", dir))
}

/// PID file path: ~/.tumpa/agent.pid
fn pid_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".tumpa").join("agent.pid"))
}

/// Check if a previous agent is still running by reading the PID file.
/// Returns true if a process with the stored PID is alive.
fn is_agent_running() -> bool {
    let pid_path = match pid_file_path() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pid_str = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pid: i32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Check if process is alive (signal 0 = existence check)
    unsafe { libc::kill(pid, 0) == 0 }
}

fn write_pid_file() -> Result<()> {
    let pid_path = pid_file_path()?;
    std::fs::write(&pid_path, format!("{}\n", std::process::id()))?;
    Ok(())
}

#[allow(dead_code)]
fn remove_pid_file() {
    if let Ok(path) = pid_file_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Run the unified agent.
///
/// Always starts the GPG passphrase cache on `~/.tumpa/agent.sock`.
/// If `ssh` is true, also starts the SSH agent.
///
/// # Security model
///
/// The agent socket is created with 0600 permissions (owner-only).
/// Any process running as the same UID can connect and read cached
/// passphrases. This is the same trust model as gpg-agent and
/// ssh-agent — security relies on Unix file permissions, not on
/// protocol-level authentication. Passphrases are transmitted in
/// base64 encoding (not encrypted) over the socket.
pub async fn run_agent(
    ssh: bool,
    ssh_host: Option<String>,
    cache_ttl: u64,
    keystore_path: Option<PathBuf>,
) -> Result<()> {
    let cache = Arc::new(Mutex::new(CredentialCache::new()));
    let socket_path = default_socket_path()?;

    // Ensure ~/.tumpa/ exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Check if another agent is already running
    if socket_path.exists() {
        if is_agent_running() {
            anyhow::bail!(
                "Another agent is already running (PID file: {:?}). \
                 Stop it first or remove the stale socket.",
                pid_file_path()?
            );
        }
        // Stale socket from a crashed agent — safe to remove
        std::fs::remove_file(&socket_path)?;
    }

    write_pid_file()?;

    // Set restrictive umask for socket creation
    let old_umask = unsafe { libc::umask(0o177) };

    let listener =
        UnixListener::bind(&socket_path).context(format!("Failed to bind {:?}", socket_path))?;

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
            default_ssh_socket_path()
                .map(|p| format!("unix://{}", p))
                .unwrap_or_else(|_| "unix:///tmp/tcli-ssh.sock".to_string())
        });

        let ks_path = keystore_path.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::ssh::run_agent_with_cache(&ssh_host, ks_path, ssh_cache).await {
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
                protocol::Request::Get { cache_key } => {
                    let cache = cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                    match cache.get(&cache_key) {
                        Some(pass) => protocol::Response::Passphrase(pass.clone()),
                        None => protocol::Response::NotFound,
                    }
                }
                protocol::Request::Put {
                    cache_key,
                    passphrase,
                } => {
                    let mut cache = cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                    cache.store(&cache_key, passphrase);
                    protocol::Response::Ok
                }
                protocol::Request::Clear { cache_key } => {
                    let mut cache = cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                    cache.remove(&cache_key);
                    protocol::Response::Ok
                }
                protocol::Request::ClearAll => {
                    let mut cache = cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                    // sweep(0) drops every entry: cutoff = now, no entry's
                    // stored_at can be strictly greater than now.
                    let removed = cache.sweep(0);
                    log::info!("Cache cleared by client: {} entries removed", removed);
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
