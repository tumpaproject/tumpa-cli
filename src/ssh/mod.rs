pub mod agent;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use ssh_agent_lib::agent::bind;
use ssh_agent_lib::agent::service_binding::Binding;

use crate::cache::CredentialCache;
use agent::TumpaBackend;

/// Run the SSH agent, listening on the given binding.
pub async fn run_agent(host: &str, keystore_path: Option<PathBuf>) -> Result<()> {
    let binding: Binding = host
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid binding '{}': {}", host, e))?;

    // Warn if binding over TCP -- the SSH agent protocol has no authentication
    if host.starts_with("tcp://") {
        eprintln!(
            "WARNING: Binding SSH agent to a TCP socket exposes it to the network.\n\
             The SSH agent protocol has no authentication -- any host that can\n\
             connect will be able to request signatures. Use unix:// instead."
        );
    }

    let backend = TumpaBackend::new(keystore_path);

    if let Some(socket_path) = host.strip_prefix("unix://") {
        eprintln!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path);
    }

    log::info!("SSH agent listening on {}", host);

    // Set restrictive umask so the socket is created with 0600 permissions.
    // This prevents other users from connecting to the agent.
    #[cfg(unix)]
    let _old_umask = if host.starts_with("unix://") {
        Some(unsafe { libc::umask(0o177) })
    } else {
        None
    };

    let result = bind(binding.try_into()?, backend).await;

    // Restore umask
    #[cfg(unix)]
    if let Some(old) = _old_umask {
        unsafe { libc::umask(old); }
    }

    result.map_err(|e| anyhow::anyhow!("SSH agent error: {:?}", e))?;

    Ok(())
}

/// Run the SSH agent with a shared credential cache from the unified agent.
pub async fn run_agent_with_cache(
    host: &str,
    keystore_path: Option<PathBuf>,
    cache: Arc<Mutex<CredentialCache>>,
) -> Result<()> {
    let binding: Binding = host
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid binding '{}': {}", host, e))?;

    let backend = TumpaBackend::with_cache(keystore_path, cache);

    if let Some(socket_path) = host.strip_prefix("unix://") {
        eprintln!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path);
    }

    log::info!("SSH agent listening on {}", host);

    #[cfg(unix)]
    let _old_umask = if host.starts_with("unix://") {
        Some(unsafe { libc::umask(0o177) })
    } else {
        None
    };

    let result = bind(binding.try_into()?, backend).await;

    #[cfg(unix)]
    if let Some(old) = _old_umask {
        unsafe { libc::umask(old); }
    }

    result.map_err(|e| anyhow::anyhow!("SSH agent error: {:?}", e))?;

    Ok(())
}
