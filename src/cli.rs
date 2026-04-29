use std::convert::TryFrom;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;

/// tcli — key management and SSH agent for the tumpa keystore.
///
/// Human-facing commands: list, import, export, describe, search,
/// fetch, delete, sign, verify, card, agent, ssh-agent, ssh-export.
/// For the GPG drop-in that git and pass invoke, see `tclig`.
#[derive(Parser, Debug)]
#[clap(name = "tcli", version)]
pub struct Args {
    /// Path to tumpa keystore database. Defaults to ~/.tumpa/keys.db.
    #[clap(long, env = "TUMPA_KEYSTORE", global = true)]
    pub keystore: Option<PathBuf>,

    #[clap(subcommand)]
    pub subcmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List keys in the tumpa keystore (human-readable).
    List,

    /// Import keys from files or directories. Use `-` for stdin.
    Import {
        /// File or directory paths. Use `-` for stdin.
        #[clap(value_name = "FILE")]
        files: Vec<String>,

        /// Recurse into subdirectories.
        #[clap(short = 'r', long)]
        recursive: bool,
    },

    /// Export a key from the keystore (default: ASCII-armored to stdout).
    Export {
        /// Key fingerprint or key ID.
        #[clap(value_name = "FINGERPRINT_OR_KEYID")]
        key_id: String,

        /// Output file. Defaults to stdout.
        #[clap(short = 'o', long)]
        output: Option<PathBuf>,

        /// Export as binary OpenPGP packets instead of ASCII-armored.
        #[clap(long)]
        binary: bool,
    },

    /// Show detailed information about a key.
    ///
    /// 40 or 16 hex characters are treated as a keystore lookup
    /// (fingerprint or key ID). Anything else is treated as a path
    /// to a key file. To force file mode for a path that happens to
    /// be all-hex, prefix it with `./`.
    Describe {
        /// A fingerprint, key ID, or path to a key file.
        #[clap(value_name = "FINGERPRINT_OR_FILE")]
        target: String,
    },

    /// Delete a key from the keystore.
    Delete {
        /// Key fingerprint or key ID.
        #[clap(value_name = "FINGERPRINT_OR_KEYID")]
        key_id: String,

        /// Skip confirmation prompt.
        #[clap(short = 'f', long)]
        force: bool,
    },

    /// Search for keys in the keystore.
    Search {
        /// Search query.
        query: String,

        /// Match by email exactly (case-insensitive) instead of UID substring.
        #[clap(long)]
        email: bool,
    },

    /// Fetch and import a key via WKD (Web Key Directory).
    Fetch {
        /// Email address to look up.
        email: String,

        /// Show key info but don't import.
        #[clap(long)]
        dry_run: bool,
    },

    /// Create a detached signature for FILE (use `-` for stdin).
    /// Default output is `<FILE>.asc` (ASCII-armored).
    Sign {
        /// Input file. Use `-` for stdin (then `-o`/`--output` is required).
        #[clap(value_name = "FILE")]
        input: PathBuf,

        /// Signer identifier: fingerprint, key ID, or exact email.
        #[clap(long, value_name = "FP|KEYID|EMAIL")]
        signer: String,

        /// Output file. Defaults to `<FILE>.asc` (or `<FILE>.sig` with --binary).
        #[clap(short = 'o', long)]
        output: Option<PathBuf>,

        /// Binary signature instead of ASCII-armored.
        #[clap(long)]
        binary: bool,
    },

    /// Create an inline (cleartext) signature.
    SignInline {
        /// Input file. Use `-` for stdin (then `-o`/`--output` is required).
        #[clap(value_name = "FILE")]
        input: PathBuf,

        /// Signer identifier: fingerprint, key ID, or exact email.
        #[clap(long, value_name = "FP|KEYID|EMAIL")]
        signer: String,

        /// Output file. Defaults to `<FILE>.asc`.
        #[clap(short = 'o', long)]
        output: Option<PathBuf>,
    },

    /// Verify a signature on FILE.
    Verify {
        /// Input file. Use `-` for stdin (requires --signature).
        #[clap(value_name = "FILE")]
        input: PathBuf,

        /// Detached signature file. Without this, the input must be a
        /// cleartext-signed message.
        #[clap(long, value_name = "SIG_FILE")]
        signature: Option<PathBuf>,

        /// Verify against an external public-key file (skip keystore lookup).
        #[clap(long, value_name = "PUBKEY_FILE")]
        key_file: Option<PathBuf>,
    },

    /// OpenPGP smart card operations.
    #[clap(subcommand)]
    Card(CardCommand),

    /// Manage the running agent's in-memory credential cache.
    #[clap(subcommand)]
    Cache(CacheCommand),

    /// Print an agent socket path. Default `gpg`; pass `ssh` for the SSH socket.
    Socket {
        /// Which socket to print.
        #[clap(value_name = "TYPE", default_value = "gpg")]
        kind: SocketKind,
    },

    /// Run the agent daemon (GPG passphrase cache + optional SSH agent).
    Agent {
        /// Also serve as an SSH agent (binds the SSH socket alongside the GPG cache).
        #[clap(long)]
        ssh: bool,

        /// SSH agent binding (e.g., unix:///tmp/tcli.sock).
        #[clap(short = 'H', long)]
        host: Option<String>,

        /// Passphrase cache TTL in seconds (default 1800 = 30 min).
        #[clap(long, default_value = "1800")]
        cache_ttl: u64,
    },

    /// Run only the SSH agent daemon (no GPG passphrase cache socket).
    ///
    /// Use this when you want SSH-only and don't want the GPG cache
    /// listener bound (`~/.tumpa/agent.sock`). For the combined
    /// GPG cache + SSH agent process, use `tcli agent --ssh` instead.
    SshAgent {
        /// SSH agent binding (e.g., unix:///tmp/tcli-ssh.sock).
        #[clap(short = 'H', long)]
        host: String,
    },

    /// Export the SSH public key for a given OpenPGP key.
    SshExport {
        /// Key fingerprint or key ID to export.
        key_id: String,

        /// Output file for the SSH public key.
        ssh_pubkey_file: PathBuf,
    },

    /// Generate shell completions for tcli and print to stdout.
    Completions {
        /// Target shell.
        #[clap(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
pub enum CardCommand {
    /// Show status of the connected OpenPGP card.
    Status,

    /// List all connected OpenPGP cards.
    List,

    /// (Experimental) Upload a secret key to the card's signing slot,
    /// optionally also to the encryption / authentication slots.
    ///
    /// `--signing-from` has no default: when the certificate carries
    /// both a sign-capable primary and a signing subkey, the upload
    /// fails closed and asks for an explicit choice. Pass
    /// `--signing-from primary` or `--signing-from sub` to disambiguate.
    #[cfg(feature = "experimental")]
    Upload {
        /// Key fingerprint or key ID to upload.
        #[clap(value_name = "FINGERPRINT_OR_KEYID")]
        key_id: String,

        /// Target card ident. If omitted, exactly one card must be connected.
        #[clap(long, value_name = "IDENT")]
        card_ident: Option<String>,

        /// Which component fills the signing slot. Required when the
        /// certificate carries both a sign-capable primary and a
        /// signing subkey; optional otherwise.
        #[clap(long, value_enum, value_name = "primary|sub")]
        signing_from: Option<SigningFrom>,

        /// Comma-separated list of additional slots to fill from
        /// matching subkeys: `encryption`, `authentication`. May be
        /// repeated.
        #[clap(long, value_name = "SLOTS", value_delimiter = ',')]
        with: Vec<Slot>,
    },

    /// (Experimental) Factory-reset a card (clears all PINs and slots).
    #[cfg(feature = "experimental")]
    Reset {
        /// Target card ident. If omitted, exactly one card must be connected.
        #[clap(long, value_name = "IDENT")]
        card_ident: Option<String>,

        /// Skip confirmation prompt.
        #[clap(short = 'y', long)]
        yes: bool,
    },

    /// Link cards already provisioned with keys whose certs are in the keystore.
    ///
    /// Walks every connected card and writes a `card_keys` row for each
    /// slot whose fingerprint matches a key in the keystore. Required for
    /// the SSH agent to find card-backed authentication keys.
    Link {
        /// Print the matches that would be written and exit; touch nothing.
        #[clap(long)]
        dry_run: bool,

        /// Restrict linking to one card. Accepts the IDENT shown by `tcli card list`.
        #[clap(long, value_name = "IDENT")]
        card_ident: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum CacheCommand {
    /// Drop cached credentials from the running agent.
    ///
    /// With no argument, every entry is cleared. With a fingerprint
    /// (40 or 16 hex chars), only that key's cached passphrase and PIN
    /// are dropped. The agent must be running.
    Clear {
        /// Optional fingerprint or key ID. Omit to clear every entry.
        #[clap(value_name = "FINGERPRINT_OR_KEYID")]
        target: Option<String>,
    },
}

#[derive(Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum SocketKind {
    Gpg,
    Ssh,
}

#[cfg(feature = "experimental")]
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum SigningFrom {
    Primary,
    Sub,
}

#[cfg(feature = "experimental")]
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Slot {
    Encryption,
    Authentication,
}

#[cfg(feature = "experimental")]
pub use crate::upload_card::WhichKey;

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
        include_signing: bool,
        include_encryption: bool,
        include_authentication: bool,
    },
    #[cfg(feature = "experimental")]
    ResetCard {
        card_ident: Option<String>,
    },
    Completions {
        shell: Shell,
    },
    Sign {
        input: PathBuf,
        with_key: String,
        binary: bool,
        output: Option<PathBuf>,
    },
    SignInline {
        input: PathBuf,
        with_key: String,
        output: Option<PathBuf>,
    },
    Verify {
        input: PathBuf,
        signature: Option<PathBuf>,
        with_key_file: Option<PathBuf>,
    },
    CacheClear {
        target: Option<String>,
    },
    CardLink {
        dry_run: bool,
        card_ident: Option<String>,
    },
    None,
}

/// Returns true if `path` is the literal `-` stdin/stdout sentinel.
pub fn is_stdio(path: &std::path::Path) -> bool {
    path.as_os_str() == "-"
}

/// True if the argument matches a 40-hex fingerprint or 16-hex key ID
/// (case-insensitive). Used by `Describe` to decide between keystore
/// lookup and file path.
fn looks_like_keystore_id(s: &str) -> bool {
    matches!(s.len(), 40 | 16) && s.chars().all(|c| c.is_ascii_hexdigit())
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        match value.subcmd {
            Some(cmd) => mode_from_subcommand(cmd),
            None => Ok(Mode::None),
        }
    }
}

fn mode_from_subcommand(cmd: Command) -> Result<Mode, String> {
    match cmd {
        Command::List => Ok(Mode::ListKeys),

        Command::Import { files, recursive } => {
            let paths = files.iter().map(PathBuf::from).collect();
            Ok(Mode::Import { paths, recursive })
        }

        Command::Export {
            key_id,
            output,
            binary,
        } => Ok(Mode::Export {
            key_id,
            binary,
            output,
        }),

        Command::Describe { target } => {
            if looks_like_keystore_id(&target) {
                Ok(Mode::Info { key_id: target })
            } else {
                Ok(Mode::Desc {
                    path: PathBuf::from(target),
                })
            }
        }

        Command::Delete { key_id, force } => Ok(Mode::Delete { key_id, force }),

        Command::Search { query, email } => Ok(Mode::Search { query, email }),

        Command::Fetch { email, dry_run } => Ok(Mode::Fetch { email, dry_run }),

        Command::Sign {
            input,
            signer,
            output,
            binary,
        } => {
            if is_stdio(&input) && output.is_none() {
                return Err(
                    "sign reading from stdin requires -o/--output (no input file to derive a default path from)"
                        .to_string(),
                );
            }
            Ok(Mode::Sign {
                input,
                with_key: signer,
                binary,
                output,
            })
        }

        Command::SignInline {
            input,
            signer,
            output,
        } => {
            if is_stdio(&input) && output.is_none() {
                return Err(
                    "sign-inline reading from stdin requires -o/--output (no input file to derive a default path from)"
                        .to_string(),
                );
            }
            Ok(Mode::SignInline {
                input,
                with_key: signer,
                output,
            })
        }

        Command::Verify {
            input,
            signature,
            key_file,
        } => {
            if signature.is_none() && is_stdio(&input) {
                return Err(
                    "verify reading from stdin requires --signature SIG_FILE (cannot read both data and inline signature from stdin)"
                        .to_string(),
                );
            }
            Ok(Mode::Verify {
                input,
                signature,
                with_key_file: key_file,
            })
        }

        Command::Card(card) => mode_from_card(card),

        Command::Cache(cache) => mode_from_cache(cache),

        Command::Socket { kind } => Ok(Mode::ShowSocket {
            ssh: kind == SocketKind::Ssh,
        }),

        Command::Agent {
            ssh,
            host,
            cache_ttl,
        } => Ok(Mode::Agent {
            ssh,
            ssh_host: host,
            cache_ttl,
        }),

        Command::SshAgent { host } => Ok(Mode::SshAgent { host }),

        Command::SshExport {
            key_id,
            ssh_pubkey_file,
        } => Ok(Mode::SshExport {
            key_id,
            ssh_pubkey_file,
        }),

        Command::Completions { shell } => Ok(Mode::Completions { shell }),
    }
}

fn mode_from_card(cmd: CardCommand) -> Result<Mode, String> {
    match cmd {
        CardCommand::Status => Ok(Mode::CardStatus),
        CardCommand::List => Ok(Mode::ListCards),
        CardCommand::Link {
            dry_run,
            card_ident,
        } => Ok(Mode::CardLink {
            dry_run,
            card_ident,
        }),

        #[cfg(feature = "experimental")]
        CardCommand::Upload {
            key_id,
            card_ident,
            signing_from,
            with,
        } => {
            // None → None preserves the ambiguity-fails-closed property
            // of `select_sign_target`: when the cert carries both a
            // sign-capable primary and a signing subkey and the user
            // hasn't picked, the upload errors instead of silently
            // choosing the primary.
            let which = signing_from.map(|s| match s {
                SigningFrom::Primary => WhichKey::Primary,
                SigningFrom::Sub => WhichKey::Sub,
            });
            let include_encryption = with.contains(&Slot::Encryption);
            let include_authentication = with.contains(&Slot::Authentication);
            Ok(Mode::UploadToCard {
                key_id,
                which,
                card_ident,
                include_signing: false,
                include_encryption,
                include_authentication,
            })
        }

        #[cfg(feature = "experimental")]
        CardCommand::Reset { card_ident, yes } => {
            // `yes` is currently a no-op: cmd_reset_card() does not
            // prompt. Keeping the flag in the grammar so users can
            // pre-write scripts; if confirmation is added later, this
            // wires straight in.
            let _ = yes;
            Ok(Mode::ResetCard { card_ident })
        }
    }
}

fn mode_from_cache(cmd: CacheCommand) -> Result<Mode, String> {
    match cmd {
        CacheCommand::Clear { target } => Ok(Mode::CacheClear { target }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(argv: &[&str]) -> Result<Mode, String> {
        let args = Args::try_parse_from(std::iter::once("tcli").chain(argv.iter().copied()))
            .map_err(|e| e.to_string())?;
        Mode::try_from(args)
    }

    // ----- top-level subcommands -----

    #[test]
    fn list_subcommand() {
        assert!(matches!(parse(&["list"]), Ok(Mode::ListKeys)));
    }

    #[test]
    fn import_subcommand_collects_files() {
        match parse(&["import", "a.asc", "b.asc"]).unwrap() {
            Mode::Import { paths, recursive } => {
                assert_eq!(paths.len(), 2);
                assert!(!recursive);
            }
            other => panic!("expected Import, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn import_subcommand_recursive() {
        match parse(&["import", "keys/", "-r"]).unwrap() {
            Mode::Import { recursive, .. } => assert!(recursive),
            other => panic!("expected Import, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn export_subcommand_default_armored() {
        match parse(&["export", "ABCD"]).unwrap() {
            Mode::Export { binary, .. } => assert!(!binary),
            other => panic!("expected Export, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn export_subcommand_binary() {
        match parse(&["export", "ABCD", "--binary", "-o", "/tmp/x"]).unwrap() {
            Mode::Export { binary, output, .. } => {
                assert!(binary);
                assert_eq!(output.as_deref(), Some(std::path::Path::new("/tmp/x")));
            }
            other => panic!("expected Export, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn describe_with_fingerprint_routes_to_info() {
        let fp = "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"; // 40 hex
        match parse(&["describe", fp]).unwrap() {
            Mode::Info { key_id } => assert_eq!(key_id, fp),
            other => panic!("expected Info, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn describe_with_keyid_routes_to_info() {
        let kid = "ABCDABCDABCDABCD"; // 16 hex
        match parse(&["describe", kid]).unwrap() {
            Mode::Info { key_id } => assert_eq!(key_id, kid),
            other => panic!("expected Info, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn describe_with_path_routes_to_desc() {
        match parse(&["describe", "alice.asc"]).unwrap() {
            Mode::Desc { path } => assert_eq!(path, PathBuf::from("alice.asc")),
            other => panic!("expected Desc, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn describe_with_dotslash_forces_file_mode() {
        let argv = ["describe", "./ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"];
        match parse(&argv).unwrap() {
            Mode::Desc { path } => assert_eq!(
                path,
                PathBuf::from("./ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
            ),
            other => panic!("expected Desc, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn search_subcommand_email_is_a_modifier() {
        match parse(&["search", "alice@example.com", "--email"]).unwrap() {
            Mode::Search { query, email } => {
                assert_eq!(query, "alice@example.com");
                assert!(email);
            }
            other => panic!("expected Search, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn fetch_subcommand_dry_run() {
        match parse(&["fetch", "a@b.c", "--dry-run"]).unwrap() {
            Mode::Fetch { dry_run, .. } => assert!(dry_run),
            other => panic!("expected Fetch, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn delete_subcommand_force() {
        match parse(&["delete", "ABCD", "-f"]).unwrap() {
            Mode::Delete { force, .. } => assert!(force),
            other => panic!("expected Delete, got {:?}", std::mem::discriminant(&other)),
        }
    }

    // ----- sign / verify -----

    #[test]
    fn sign_subcommand_with_signer() {
        match parse(&["sign", "msg.txt", "--signer", "alice@example.com"]).unwrap() {
            Mode::Sign {
                input,
                with_key,
                binary,
                output,
            } => {
                assert_eq!(input, PathBuf::from("msg.txt"));
                assert_eq!(with_key, "alice@example.com");
                assert!(!binary);
                assert!(output.is_none());
            }
            other => panic!("expected Sign, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn sign_subcommand_binary_threads_through() {
        match parse(&[
            "sign",
            "msg.txt",
            "--signer",
            "alice@example.com",
            "--binary",
        ])
        .unwrap()
        {
            Mode::Sign { binary, .. } => assert!(binary),
            other => panic!("expected Sign, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn sign_inline_subcommand() {
        match parse(&["sign-inline", "msg.txt", "--signer", "alice@example.com"]).unwrap() {
            Mode::SignInline { with_key, .. } => assert_eq!(with_key, "alice@example.com"),
            other => panic!(
                "expected SignInline, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn sign_stdin_requires_output_subcommand() {
        let err = parse(&["sign", "-", "--signer", "alice@example.com"]).unwrap_err();
        assert!(err.contains("requires -o/--output"), "got: {err}");
    }

    #[test]
    fn verify_subcommand_inline() {
        match parse(&["verify", "msg.asc"]).unwrap() {
            Mode::Verify {
                input,
                signature,
                with_key_file,
            } => {
                assert_eq!(input, PathBuf::from("msg.asc"));
                assert!(signature.is_none());
                assert!(with_key_file.is_none());
            }
            other => panic!("expected Verify, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn verify_subcommand_detached() {
        match parse(&["verify", "msg.txt", "--signature", "msg.sig"]).unwrap() {
            Mode::Verify {
                input, signature, ..
            } => {
                assert_eq!(input, PathBuf::from("msg.txt"));
                assert_eq!(signature.as_deref(), Some(std::path::Path::new("msg.sig")));
            }
            other => panic!("expected Verify, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn verify_subcommand_with_external_pubkey() {
        match parse(&["verify", "msg.asc", "--key-file", "alice.pub"]).unwrap() {
            Mode::Verify { with_key_file, .. } => assert_eq!(
                with_key_file.as_deref(),
                Some(std::path::Path::new("alice.pub"))
            ),
            other => panic!("expected Verify, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn verify_stdin_requires_signature_subcommand() {
        let err = parse(&["verify", "-"]).unwrap_err();
        assert!(err.contains("--signature"), "got: {err}");
    }

    // ----- card / socket / agent / ssh-agent / ssh-export / completions -----

    #[test]
    fn card_status_subcommand() {
        assert!(matches!(parse(&["card", "status"]), Ok(Mode::CardStatus)));
    }

    #[test]
    fn card_list_subcommand() {
        assert!(matches!(parse(&["card", "list"]), Ok(Mode::ListCards)));
    }

    #[test]
    fn card_link_subcommand_defaults() {
        match parse(&["card", "link"]).unwrap() {
            Mode::CardLink {
                dry_run,
                card_ident,
            } => {
                assert!(!dry_run);
                assert!(card_ident.is_none());
            }
            other => panic!(
                "expected CardLink, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn card_link_subcommand_dry_run() {
        match parse(&["card", "link", "--dry-run"]).unwrap() {
            Mode::CardLink { dry_run, .. } => assert!(dry_run),
            other => panic!(
                "expected CardLink, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn card_link_subcommand_filter_card_ident() {
        match parse(&["card", "link", "--card-ident", "000F:CB9A5355"]).unwrap() {
            Mode::CardLink {
                dry_run,
                card_ident,
            } => {
                assert!(!dry_run);
                assert_eq!(card_ident.as_deref(), Some("000F:CB9A5355"));
            }
            other => panic!(
                "expected CardLink, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn card_link_subcommand_dry_run_with_card_ident() {
        match parse(&["card", "link", "--dry-run", "--card-ident", "0006:0001"]).unwrap() {
            Mode::CardLink {
                dry_run,
                card_ident,
            } => {
                assert!(dry_run);
                assert_eq!(card_ident.as_deref(), Some("0006:0001"));
            }
            other => panic!(
                "expected CardLink, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn socket_default_is_gpg() {
        match parse(&["socket"]).unwrap() {
            Mode::ShowSocket { ssh } => assert!(!ssh),
            other => panic!(
                "expected ShowSocket, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn socket_ssh_subcommand() {
        match parse(&["socket", "ssh"]).unwrap() {
            Mode::ShowSocket { ssh } => assert!(ssh),
            other => panic!(
                "expected ShowSocket, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn agent_subcommand_defaults() {
        match parse(&["agent"]).unwrap() {
            Mode::Agent {
                ssh,
                ssh_host,
                cache_ttl,
            } => {
                assert!(!ssh);
                assert!(ssh_host.is_none());
                assert_eq!(cache_ttl, 1800);
            }
            other => panic!("expected Agent, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn ssh_agent_subcommand_requires_host() {
        // `ssh-agent` is a distinct subcommand from `agent --ssh`
        // (no GPG cache socket). It requires a binding.
        let err = parse(&["ssh-agent"]).unwrap_err();
        assert!(err.contains("--host") || err.contains("-H"), "got: {err}");
    }

    #[test]
    fn ssh_agent_subcommand_with_host() {
        match parse(&["ssh-agent", "-H", "unix:///tmp/tcli-ssh.sock"]).unwrap() {
            Mode::SshAgent { host } => assert_eq!(host, "unix:///tmp/tcli-ssh.sock"),
            other => panic!(
                "expected SshAgent, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn ssh_export_subcommand() {
        match parse(&["ssh-export", "ABCD", "/tmp/id.pub"]).unwrap() {
            Mode::SshExport {
                key_id,
                ssh_pubkey_file,
            } => {
                assert_eq!(key_id, "ABCD");
                assert_eq!(ssh_pubkey_file, PathBuf::from("/tmp/id.pub"));
            }
            other => panic!(
                "expected SshExport, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn completions_subcommand() {
        assert!(matches!(
            parse(&["completions", "zsh"]),
            Ok(Mode::Completions { .. })
        ));
    }

    // ----- cache -----

    #[test]
    fn cache_clear_no_args_clears_all() {
        match parse(&["cache", "clear"]).unwrap() {
            Mode::CacheClear { target } => assert!(target.is_none()),
            other => panic!(
                "expected CacheClear, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[test]
    fn cache_clear_with_fingerprint() {
        match parse(&["cache", "clear", "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"]).unwrap() {
            Mode::CacheClear { target } => assert_eq!(
                target.as_deref(),
                Some("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD")
            ),
            other => panic!(
                "expected CacheClear, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    // ----- pre-0.4 flag forms are gone -----

    #[test]
    fn old_list_keys_flag_is_rejected() {
        let err = parse(&["--list-keys"]).unwrap_err();
        assert!(err.contains("unexpected argument"), "got: {err}");
    }

    #[test]
    fn old_card_status_flag_is_rejected() {
        let err = parse(&["--card-status"]).unwrap_err();
        assert!(err.contains("unexpected argument"), "got: {err}");
    }

    #[test]
    fn old_with_key_flag_is_rejected() {
        let err = parse(&["sign", "msg.txt", "--with-key", "alice@example.com"]).unwrap_err();
        assert!(err.contains("unexpected argument"), "got: {err}");
    }

    #[test]
    fn no_subcommand_is_mode_none() {
        assert!(matches!(parse(&[]), Ok(Mode::None)));
    }

    // ----- experimental: card upload / reset -----

    #[cfg(feature = "experimental")]
    #[test]
    fn card_upload_no_signing_from_yields_none() {
        // The fix for the silent-default regression: with no
        // --signing-from, `which` must be None so select_sign_target's
        // ambiguity check fires for certs with both sign-capable
        // primary and signing subkey.
        let mode = parse(&["card", "upload", "ABCDEF"]).unwrap();
        match mode {
            Mode::UploadToCard {
                key_id,
                which,
                card_ident,
                include_signing,
                include_encryption,
                include_authentication,
            } => {
                assert_eq!(key_id, "ABCDEF");
                assert!(which.is_none(), "no --signing-from must yield which=None");
                assert!(card_ident.is_none());
                assert!(!include_signing);
                assert!(!include_encryption);
                assert!(!include_authentication);
            }
            other => panic!(
                "expected UploadToCard, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn card_upload_signing_from_primary_explicit() {
        let mode = parse(&["card", "upload", "ABCDEF", "--signing-from", "primary"]).unwrap();
        match mode {
            Mode::UploadToCard { which, .. } => {
                assert_eq!(which, Some(WhichKey::Primary));
            }
            other => panic!(
                "expected UploadToCard, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn card_upload_signing_from_sub_with_extras() {
        let mode = parse(&[
            "card",
            "upload",
            "ABCDEF",
            "--signing-from",
            "sub",
            "--with",
            "encryption,authentication",
        ])
        .unwrap();
        match mode {
            Mode::UploadToCard {
                which,
                include_encryption,
                include_authentication,
                ..
            } => {
                assert_eq!(which, Some(WhichKey::Sub));
                assert!(include_encryption);
                assert!(include_authentication);
            }
            other => panic!(
                "expected UploadToCard, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn card_upload_positional_floats_after_flags() {
        let mode = parse(&[
            "card",
            "upload",
            "--signing-from",
            "sub",
            "--with",
            "encryption",
            "ABCDEF",
        ])
        .unwrap();
        match mode {
            Mode::UploadToCard {
                key_id,
                which,
                include_encryption,
                ..
            } => {
                assert_eq!(key_id, "ABCDEF");
                assert_eq!(which, Some(WhichKey::Sub));
                assert!(include_encryption);
            }
            other => panic!(
                "expected UploadToCard, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }

    #[cfg(feature = "experimental")]
    #[test]
    fn card_reset_subcommand() {
        let mode = parse(&["card", "reset", "--card-ident", "000F:ABCD"]).unwrap();
        match mode {
            Mode::ResetCard { card_ident } => {
                assert_eq!(card_ident.as_deref(), Some("000F:ABCD"));
            }
            other => panic!(
                "expected ResetCard, got {:?}",
                std::mem::discriminant(&other)
            ),
        }
    }
}
