pub mod pinentry;
pub mod protocol;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::cache::CredentialCache;
use pinentry::{is_desktop_session, PromptDeduper, SharedOutcome};

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

/// Check if a previous tcli agent is still running by reading the PID
/// file.
///
/// `kill(pid, 0) == 0` alone is not enough: macOS recycles PIDs quickly
/// (~30s in heavy churn), and a kill check on a PID that's been reused
/// by an unrelated process returns success — the previous behavior
/// silently bailed at startup with "Another agent is already running"
/// even when the original tcli was long dead. Verify the PID's
/// executable matches our binary name before treating the file as
/// authoritative; treat any mismatch (or lookup failure) as stale.
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
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    // PID exists. Verify it's actually a tcli process — if it's
    // anything else, the PID file is stale (PID was recycled).
    match pid_executable_name(pid) {
        Some(name) if name == "tcli" => true,
        Some(other) => {
            log::debug!(
                "agent.pid points at PID {} which is now {:?}, not tcli; treating as stale",
                pid,
                other
            );
            false
        }
        None => {
            log::debug!(
                "agent.pid points at PID {} but its executable is unidentifiable; treating as stale",
                pid
            );
            false
        }
    }
}

/// Look up the file-name of the executable for `pid`.
///
/// Returns `None` if the PID is gone, the kernel denies us access, or
/// we're on a platform without a portable lookup. Callers should treat
/// `None` as "can't confirm this PID is ours" — i.e. stale.
#[cfg(target_os = "macos")]
fn pid_executable_name(pid: i32) -> Option<String> {
    // libc::proc_pidpath is in the libproc API exposed via libc on
    // macOS. Buffer size must be at least PROC_PIDPATHINFO_MAXSIZE
    // (4096) per <sys/proc_info.h>.
    const MAX_PATH: usize = 4096;
    let mut buf = vec![0u8; MAX_PATH];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let path = std::str::from_utf8(&buf).ok()?;
    std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn pid_executable_name(pid: i32) -> Option<String> {
    let exe = std::fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    exe.file_name().map(|s| s.to_string_lossy().into_owned())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn pid_executable_name(_pid: i32) -> Option<String> {
    None
}

/// Are we running under a process supervisor (launchd on macOS,
/// systemd on Linux)?
///
/// When supervised, the PID-file mutex is both unnecessary and
/// counterproductive: the supervisor guarantees a single live
/// instance per service label, but the file outlives ungraceful
/// exits and `is_agent_running()` (even tightened) can't always
/// disambiguate stale-from-PID-reuse cases — the supervisor handles
/// it for us. Detection is best-effort:
///   - macOS launchd: per-user agents are reparented to launchd
///     (PID 1) immediately after exec.
///   - systemd: every unit invocation gets `INVOCATION_ID` in the env.
fn is_supervised() -> bool {
    if cfg!(target_os = "macos") && unsafe { libc::getppid() } == 1 {
        return true;
    }
    if std::env::var("INVOCATION_ID").is_ok() {
        return true;
    }
    false
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

    // PID-file-based "is another agent running" check is only safe
    // for self-managed startup (cargo install / running from a shell).
    // Under launchd / systemd the supervisor enforces single-instance
    // and the PID file becomes a flake source: stale PIDs that get
    // reused by unrelated processes trip the liveness check, and the
    // ungraceful-exit-cleanup gap (no Drop / signal handler runs on
    // SIGKILL) leaves stale entries behind. Skip the mutex when
    // supervised; the socket cleanup below handles the residue.
    let supervised = is_supervised();
    if !supervised && socket_path.exists() && is_agent_running() {
        anyhow::bail!(
            "Another agent is already running (PID file: {:?}). \
             Stop it first or remove the stale socket.",
            pid_file_path()?
        );
    }
    if socket_path.exists() {
        // Stale socket from a previous instance (crashed self-managed
        // agent, or any prior supervised invocation). Safe to remove.
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

    // Probe pinentry availability and headless state at startup.
    // Logging only — per-request behaviour is decided in handle_client.
    match crate::pinentry::resolve_pinentry() {
        Some((name, path)) => eprintln!("Pinentry: {} at {}", name, path.display()),
        None => eprintln!(
            "Pinentry: not found (tried: {})",
            crate::pinentry::pinentry_candidates().join(", ")
        ),
    }
    if !is_desktop_session() {
        eprintln!("Pinentry: headless session — agent will return PINENTRY_UNAVAILABLE");
    }

    let deduper = Arc::new(PromptDeduper::new());

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
                let client_deduper = deduper.clone();
                let ttl = cache_ttl;
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, client_cache, client_deduper, ttl).await {
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
    deduper: Arc<PromptDeduper>,
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
                protocol::Request::GetOrPrompt {
                    cache_key,
                    description,
                    prompt,
                    keyinfo,
                } => {
                    // 1. Cache hit short-circuits — no pinentry, no
                    //    deduper involvement.
                    let cached = {
                        let cache = cache.lock().map_err(|_| anyhow::anyhow!("Lock poisoned"))?;
                        cache.get(&cache_key).cloned()
                    };
                    if let Some(pass) = cached {
                        protocol::Response::Passphrase(pass)
                    } else if !is_desktop_session() {
                        // 2. Headless: no pinentry possible, tell the
                        //    client to use its own fallback path.
                        protocol::Response::PinentryUnavailable
                    } else {
                        // 3. Desktop session, cache miss: ask the
                        //    deduper to prompt (or join an in-flight
                        //    prompt for the same key).
                        let outcome = deduper
                            .prompt(&cache_key, description, prompt, keyinfo)
                            .await;
                        match outcome {
                            SharedOutcome::Got(pass) => protocol::Response::Passphrase(pass),
                            SharedOutcome::Cancelled => protocol::Response::Cancelled,
                            SharedOutcome::Unavailable => protocol::Response::PinentryUnavailable,
                            SharedOutcome::Err(msg) => protocol::Response::Err(msg),
                        }
                    }
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
