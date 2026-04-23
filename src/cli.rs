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

    // --- Experimental (compile-time gated behind the `experimental`
    // Cargo feature; the flags below only exist on feature builds).

    /// **Experimental.** Upload a secret key from the keystore to the
    /// signing slot of a connected OpenPGP smart card. If the key has
    /// both a sign-capable primary key and a sign-capable subkey,
    /// pass `--which primary|sub` to disambiguate.
    #[cfg(feature = "experimental")]
    #[clap(long, value_name = "FINGERPRINT_OR_KEYID", hide = true)]
    pub upload_to_card: Option<String>,

    /// Select which sign-capable component of a certificate to upload
    /// (for `--upload-to-card`). Values: `primary`, `sub`.
    #[cfg(feature = "experimental")]
    #[clap(long, value_name = "primary|sub", hide = true)]
    pub which: Option<String>,

    /// **Experimental.** Factory-reset the connected OpenPGP card:
    /// block all PINs, wipe all slots, restore defaults (user PIN
    /// `123456`, admin PIN `12345678`).
    #[cfg(feature = "experimental")]
    #[clap(long, hide = true)]
    pub reset_card: bool,

    /// List all connected OpenPGP smart cards with their ident,
    /// manufacturer, serial, and cardholder name. Mutually exclusive
    /// with every other flag; prints the table to stdout and exits.
    #[clap(long)]
    pub list_cards: bool,

    /// **Experimental.** Target card ident (e.g. `000F:CB9A5355`) for
    /// `--upload-to-card` and `--reset-card`. Use `--list-cards` to see
    /// idents of attached cards. If omitted, there must be exactly one
    /// OpenPGP card connected.
    #[cfg(feature = "experimental")]
    #[clap(long, value_name = "IDENT", hide = true)]
    pub card_ident: Option<String>,

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

#[cfg(feature = "experimental")]
pub use tumpa_cli::upload_card::WhichKey;

#[derive(Debug)]
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
    ListCards,
    #[cfg(feature = "experimental")]
    UploadToCard {
        key_id: String,
        which: Option<WhichKey>,
        card_ident: Option<String>,
    },
    #[cfg(feature = "experimental")]
    ResetCard {
        card_ident: Option<String>,
    },
    Completions {
        shell: Shell,
    },
    None,
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        // `--list-cards` must win over subcommands (agent / ssh-agent /
        // ssh-export), otherwise clap's subcommand match below would
        // silently consume the invocation and ignore --list-cards.
        if value.list_cards && value.subcmd.is_some() {
            return Err("--list-cards cannot be combined with other flags".to_string());
        }

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

        // `--list-cards` is read-only and must be the only flag on the
        // command line. It ignores --keystore (doesn't touch the
        // keystore at all) but rejects every other flag — action
        // flags, positionals, and modifiers like --armor / --binary /
        // --output / --recursive / --force / --dry-run / --email that
        // only make sense with another action — so users aren't
        // surprised by silently-dropped arguments.
        if value.list_cards {
            if value.list_keys
                || value.import
                || value.export.is_some()
                || value.info.is_some()
                || value.desc.is_some()
                || value.delete.is_some()
                || value.search.is_some()
                || value.fetch.is_some()
                || value.show_socket.is_some()
                || value.card_status
                || value.completions.is_some()
                || !value.input_files.is_empty()
                || value.armor
                || value.binary
                || value.output.is_some()
                || value.recursive
                || value.force
                || value.dry_run
                || value.email
            {
                return Err("--list-cards cannot be combined with other flags".to_string());
            }
            #[cfg(feature = "experimental")]
            {
                if value.upload_to_card.is_some()
                    || value.which.is_some()
                    || value.reset_card
                    || value.card_ident.is_some()
                {
                    return Err(
                        "--list-cards cannot be combined with other flags".to_string(),
                    );
                }
            }
            return Ok(Mode::ListCards);
        }

        // --- Experimental card ops (only compiled in with
        // `--features experimental`) ---
        #[cfg(feature = "experimental")]
        {
            if let Some(key_id) = value.upload_to_card.clone() {
                let which = match value.which.as_deref() {
                    None => None,
                    Some("primary") => Some(WhichKey::Primary),
                    Some("sub") | Some("subkey") => Some(WhichKey::Sub),
                    Some(other) => {
                        return Err(format!(
                            "invalid --which value {:?}: expected `primary` or `sub`",
                            other
                        ))
                    }
                };
                return Ok(Mode::UploadToCard {
                    key_id,
                    which,
                    card_ident: value.card_ident.clone(),
                });
            }

            if value.which.is_some() {
                return Err("--which only applies to --upload-to-card".to_string());
            }

            if value.reset_card {
                return Ok(Mode::ResetCard {
                    card_ident: value.card_ident.clone(),
                });
            }

            if value.card_ident.is_some() {
                return Err(
                    "--card-ident only applies to --upload-to-card or --reset-card".to_string(),
                );
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(argv: &[&str]) -> Result<Mode, String> {
        let args = Args::try_parse_from(
            std::iter::once("tcli").chain(argv.iter().copied()),
        )
        .map_err(|e| e.to_string())?;
        Mode::try_from(args)
    }

    #[test]
    fn list_cards_alone_parses() {
        assert!(matches!(parse(&["--list-cards"]), Ok(Mode::ListCards)));
    }

    #[test]
    fn list_cards_rejects_other_action_flags() {
        let err = parse(&["--list-cards", "--list-keys"]).unwrap_err();
        assert!(
            err.contains("--list-cards cannot be combined"),
            "got: {err}"
        );
    }

    #[test]
    fn list_cards_rejects_positional_inputs() {
        let err = parse(&["--list-cards", "some-key.asc"]).unwrap_err();
        assert!(
            err.contains("--list-cards cannot be combined"),
            "got: {err}"
        );
    }

    #[test]
    fn list_cards_rejects_modifier_flags() {
        // Spot-check one modifier from each family (bool and Option).
        for extra in [&["--armor"][..], &["--output", "/tmp/x"][..], &["--email"][..]] {
            let mut argv = vec!["--list-cards"];
            argv.extend_from_slice(extra);
            let err = parse(&argv).unwrap_err();
            assert!(
                err.contains("--list-cards cannot be combined"),
                "for {extra:?} got: {err}"
            );
        }
    }

    #[test]
    fn list_cards_rejects_subcommand() {
        let err = parse(&["--list-cards", "ssh-agent", "-H", "unix:///tmp/s"])
            .unwrap_err();
        assert!(
            err.contains("--list-cards cannot be combined"),
            "got: {err}"
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn list_cards_rejects_card_ident() {
        let err =
            parse(&["--list-cards", "--card-ident", "000F:ABCD"]).unwrap_err();
        assert!(
            err.contains("--list-cards cannot be combined"),
            "got: {err}"
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn card_ident_without_upload_or_reset_errors() {
        let err = parse(&["--card-ident", "000F:ABCD"]).unwrap_err();
        assert!(
            err.contains("--card-ident only applies to"),
            "got: {err}"
        );
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn upload_to_card_threads_card_ident() {
        let mode =
            parse(&["--upload-to-card", "ABCDEF", "--card-ident", "000F:ABCD"])
                .unwrap();
        match mode {
            Mode::UploadToCard {
                key_id,
                card_ident,
                which,
            } => {
                assert_eq!(key_id, "ABCDEF");
                assert_eq!(card_ident.as_deref(), Some("000F:ABCD"));
                assert!(which.is_none());
            }
            other => panic!("expected UploadToCard, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn reset_card_threads_card_ident() {
        let mode = parse(&["--reset-card", "--card-ident", "000F:ABCD"]).unwrap();
        match mode {
            Mode::ResetCard { card_ident } => {
                assert_eq!(card_ident.as_deref(), Some("000F:ABCD"));
            }
            other => panic!("expected ResetCard, got {:?}", std::mem::discriminant(&other)),
        }
    }
}
