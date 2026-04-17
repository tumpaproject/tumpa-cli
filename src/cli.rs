use std::convert::TryFrom;
use std::path::PathBuf;

use clap::Parser;
use clap_complete::Shell;

/// tcli — key management and SSH agent for the tumpa keystore.
///
/// Human-facing commands: import, export, describe, search, fetch,
/// list, delete, card status, agent daemons, SSH pubkey export.
/// For the GPG drop-in that git and pass invoke, see `tclig`.
#[derive(Parser, Debug)]
#[clap(name = "tcli", version)]
pub struct Args {
    // --- Key listing ---

    /// List keys in the tumpa keystore (human-readable).
    #[clap(long)]
    pub list_keys: bool,

    // --- Key management ---

    /// Import keys from files or directories.
    #[clap(long)]
    pub import: bool,

    /// Export a key from the keystore.
    #[clap(long, value_name = "FINGERPRINT_OR_KEYID")]
    pub export: Option<String>,

    /// Show detailed information about a key.
    #[clap(long, value_name = "FINGERPRINT_OR_KEYID")]
    pub info: Option<String>,

    /// Show detailed information about a key file without importing it.
    #[clap(long, value_name = "FILE")]
    pub desc: Option<PathBuf>,

    /// Delete a key from the keystore.
    #[clap(long, value_name = "FINGERPRINT_OR_KEYID")]
    pub delete: Option<String>,

    /// Search for keys by name or email.
    #[clap(long, value_name = "QUERY")]
    pub search: Option<String>,

    /// Fetch and import a key via WKD (Web Key Directory).
    #[clap(long, value_name = "EMAIL")]
    pub fetch: Option<String>,

    /// Show agent socket path. Use `--show-socket` for the GPG agent socket,
    /// `--show-socket ssh` for the SSH agent socket.
    #[clap(long, value_name = "TYPE", num_args = 0..=1, default_missing_value = "gpg")]
    pub show_socket: Option<String>,

    /// Show status of connected OpenPGP smart card.
    #[clap(long)]
    pub card_status: bool,

    // --- Output ---

    /// Output ASCII-armored data (for --export).
    #[clap(long, short = 'a')]
    pub armor: bool,

    /// Output file (for --export). Stdout if omitted.
    #[clap(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Output in binary format (for --export).
    #[clap(long)]
    pub binary: bool,

    /// Recurse into subdirectories (for --import with directories).
    #[clap(long)]
    pub recursive: bool,

    /// Force operation without confirmation (for --delete).
    #[clap(short = 'f', long, hide = true)]
    pub force: bool,

    /// Fetch without importing — show key info only (for --fetch).
    #[clap(long)]
    pub dry_run: bool,

    /// Search by email (exact, case-insensitive) instead of UID substring.
    #[clap(long)]
    pub email: bool,

    // --- Positional ---

    /// Positional arguments (input files for --import).
    pub input_files: Vec<String>,

    // --- Keystore ---

    /// Path to tumpa keystore database. Defaults to ~/.tumpa/keys.db.
    #[clap(long, env = "TUMPA_KEYSTORE")]
    pub keystore: Option<PathBuf>,

    // --- SSH agent ---

    /// SSH agent subcommand.
    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,

    // --- Shell completions ---

    /// Generate shell completions and print to stdout.
    #[clap(long, value_name = "SHELL", value_enum)]
    pub completions: Option<Shell>,
}

#[derive(Parser, Debug)]
pub enum SubCommand {
    /// Run the agent daemon (GPG passphrase cache + optional SSH agent).
    Agent {
        /// Also serve as an SSH agent.
        #[clap(long)]
        ssh: bool,

        /// SSH agent binding (e.g., unix:///tmp/tcli.sock).
        #[clap(short = 'H', long)]
        host: Option<String>,

        /// Passphrase cache TTL in seconds (default: 1800 = 30 min).
        #[clap(long, default_value = "1800")]
        cache_ttl: u64,
    },

    /// Run as an SSH agent daemon (alias for 'agent --ssh').
    #[clap(hide = true)]
    SshAgent {
        /// Binding host (e.g., unix:///tmp/tcli.sock).
        #[clap(short = 'H', long)]
        host: String,
    },

    /// Export the SSH public key for a given OpenPGP key.
    ///
    /// Extracts the authentication subkey and writes it in SSH
    /// authorized_keys format.
    ///
    /// Example: tcli ssh-export FINGERPRINT ~/.ssh/id_openpgp.pub
    SshExport {
        /// Key fingerprint or key ID to export.
        key_id: String,

        /// Output file for the SSH public key.
        ssh_pubkey_file: PathBuf,
    },
}

pub enum Mode {
    ListKeys,
    Agent {
        ssh: bool,
        ssh_host: Option<String>,
        cache_ttl: u64,
    },
    SshAgent {
        host: String,
    },
    SshExport {
        key_id: String,
        ssh_pubkey_file: PathBuf,
    },
    Import {
        paths: Vec<PathBuf>,
        recursive: bool,
    },
    Export {
        key_id: String,
        armor: bool,
        binary: bool,
        output: Option<PathBuf>,
    },
    Info {
        key_id: String,
    },
    Desc {
        path: PathBuf,
    },
    Delete {
        key_id: String,
        force: bool,
    },
    Search {
        query: String,
        email: bool,
    },
    Fetch {
        email: String,
        dry_run: bool,
    },
    ShowSocket {
        ssh: bool,
    },
    CardStatus,
    Completions {
        shell: Shell,
    },
    None,
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        // Subcommands
        match value.subcmd {
            Some(SubCommand::Agent {
                ssh,
                host,
                cache_ttl,
            }) => {
                return Ok(Mode::Agent {
                    ssh,
                    ssh_host: host,
                    cache_ttl,
                })
            }
            Some(SubCommand::SshAgent { host }) => return Ok(Mode::SshAgent { host }),
            Some(SubCommand::SshExport {
                key_id,
                ssh_pubkey_file,
            }) => {
                return Ok(Mode::SshExport {
                    key_id,
                    ssh_pubkey_file,
                })
            }
            None => {}
        }

        // --- Shell completions ---

        if let Some(shell) = value.completions {
            return Ok(Mode::Completions { shell });
        }

        // --- Card and socket info ---

        if value.card_status {
            return Ok(Mode::CardStatus);
        }

        if let Some(socket_type) = value.show_socket {
            return Ok(Mode::ShowSocket {
                ssh: socket_type == "ssh",
            });
        }

        // --- Key management flags ---

        if value.import {
            let paths = value.input_files.iter().map(PathBuf::from).collect();
            return Ok(Mode::Import {
                paths,
                recursive: value.recursive,
            });
        }

        if let Some(key_id) = value.export {
            return Ok(Mode::Export {
                key_id,
                armor: value.armor,
                binary: value.binary,
                output: value.output.clone(),
            });
        }

        if let Some(key_id) = value.info {
            return Ok(Mode::Info { key_id });
        }

        if let Some(path) = value.desc {
            return Ok(Mode::Desc { path });
        }

        if let Some(key_id) = value.delete {
            return Ok(Mode::Delete {
                key_id,
                force: value.force,
            });
        }

        if let Some(query) = value.search {
            return Ok(Mode::Search {
                query,
                email: value.email,
            });
        }

        if let Some(email) = value.fetch {
            return Ok(Mode::Fetch {
                email,
                dry_run: value.dry_run,
            });
        }

        // --- Key listing (human-readable; --with-colons form lives in tclig) ---

        if value.list_keys {
            return Ok(Mode::ListKeys);
        }

        Ok(Mode::None)
    }
}
