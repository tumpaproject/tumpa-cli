use std::convert::TryFrom;
use std::path::PathBuf;

use clap::Parser;

/// A GPG-compatible CLI for signing, verification, encryption, decryption,
/// and SSH agent functionality, backed by the tumpa keystore.
///
/// Designed as a drop-in replacement for GnuPG in git and password-store
/// workflows. Tries hardware OpenPGP cards first, then falls back to
/// software keys from ~/.tumpa/keys.db.
#[derive(Parser, Debug)]
#[clap(name = "tcli")]
pub struct Args {
    // --- Signing ---
    /// Create a detached signature.
    #[clap(long, short = 'b')]
    pub detach_sign: bool,

    /// Sign mode (accepted alongside --detach-sign).
    #[clap(long, short = 's', hide = true)]
    pub sign: bool,

    /// Signing key fingerprint or key ID.
    #[clap(long, short = 'u', value_names = ["SIGNING_KEY"])]
    pub local_user: Option<String>,

    // --- Verification ---
    /// Verify a detached signature.
    #[clap(long, value_names = ["SIGNATURE_FILE"])]
    pub verify: Option<PathBuf>,

    // --- Encryption ---
    /// Encrypt mode.
    #[clap(short = 'e', long)]
    pub encrypt: bool,

    /// Recipient key ID or fingerprint (may be repeated).
    #[clap(short = 'r', long = "recipient")]
    pub recipients: Vec<String>,

    // --- Decryption ---
    /// Decrypt mode.
    #[clap(short = 'd', long)]
    pub decrypt: bool,

    // --- Output ---
    /// Output ASCII-armored data.
    #[clap(long, short = 'a')]
    pub armor: bool,

    /// Output file (for encrypt: required, for decrypt: optional, stdout if omitted).
    #[clap(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    // --- Key listing ---
    /// List keys in the tumpa keystore.
    #[clap(long)]
    pub list_keys: bool,

    /// List secret keys in the tumpa keystore.
    #[clap(long)]
    pub list_secret_keys: bool,

    /// Output in colon-delimited format (for --list-keys / --list-secret-keys).
    #[clap(long)]
    pub with_colons: bool,

    /// List only metadata (used with --decrypt to inspect encrypted file).
    #[clap(long)]
    pub list_only: bool,

    // --- Positional ---
    /// Positional arguments (input files, "-" for stdin in verify mode).
    pub input_files: Vec<String>,

    // --- Keystore ---
    /// Path to tumpa keystore database. Defaults to ~/.tumpa/keys.db.
    #[clap(long, env = "TUMPA_KEYSTORE")]
    pub keystore: Option<PathBuf>,

    // --- SSH agent ---
    /// SSH agent subcommand.
    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,

    // --- GPG compatibility flags (accepted, ignored) ---
    #[clap(long, hide = true)]
    pub keyid_format: Option<String>,

    #[clap(long, hide = true)]
    pub status_fd: Option<String>,

    /// Default signing key (used by pass for --detach-sign).
    #[clap(long, hide = true)]
    pub default_key: Option<String>,

    #[clap(long, short = 'q', hide = true)]
    pub quiet: bool,

    #[clap(long, hide = true)]
    pub yes: bool,

    #[clap(long, hide = true)]
    pub compress_algo: Option<String>,

    #[clap(long, hide = true)]
    pub no_encrypt_to: bool,

    #[clap(long, hide = true)]
    pub batch: bool,

    #[clap(long, hide = true)]
    pub use_agent: bool,

    #[clap(long, hide = true)]
    pub no_secmem_warning: bool,

    #[clap(long, hide = true)]
    pub no_permission_warning: bool,

    #[clap(short = 'v', hide = true)]
    pub verbose: bool,

    /// GPG --list-config (used by pass to query groups).
    #[clap(long, hide = true)]
    pub list_config: bool,
}

#[derive(Parser, Debug)]
pub enum SubCommand {
    /// Run as an SSH agent daemon.
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
    Sign {
        signer_id: String,
        armor: bool,
    },
    Verify {
        signature_file: PathBuf,
    },
    Encrypt {
        recipients: Vec<String>,
        output: PathBuf,
        input: Option<PathBuf>,
        armor: bool,
    },
    Decrypt {
        input: PathBuf,
        output: Option<PathBuf>,
    },
    DecryptListOnly {
        input: PathBuf,
    },
    ListKeysColon {
        key_ids: Vec<String>,
    },
    ListSecretKeysColon,
    ListKeys,
    ListConfig,
    SshAgent {
        host: String,
    },
    SshExport {
        key_id: String,
        ssh_pubkey_file: PathBuf,
    },
    None,
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        // Subcommands
        match value.subcmd {
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

        // --list-config (pass uses this to query GPG groups)
        if value.list_config {
            return Ok(Mode::ListConfig);
        }

        // --list-secret-keys --with-colons
        if value.list_secret_keys {
            return Ok(Mode::ListSecretKeysColon);
        }

        // --list-keys (with or without --with-colons)
        if value.list_keys {
            if value.with_colons {
                return Ok(Mode::ListKeysColon {
                    key_ids: value.input_files,
                });
            }
            return Ok(Mode::ListKeys);
        }

        // --decrypt --list-only FILE (metadata inspection)
        if value.decrypt && value.list_only {
            let input = value
                .input_files
                .first()
                .map(PathBuf::from)
                .ok_or("--decrypt --list-only requires an input file")?;
            return Ok(Mode::DecryptListOnly { input });
        }

        // --encrypt
        if value.encrypt {
            if value.recipients.is_empty() {
                return Err("Encryption requires at least one -r/--recipient".into());
            }
            let output = value.output.ok_or("Encryption requires -o/--output")?;
            let input = value.input_files.first().map(PathBuf::from);
            return Ok(Mode::Encrypt {
                recipients: value.recipients,
                output,
                input,
                armor: value.armor,
            });
        }

        // --decrypt / -d
        if value.decrypt {
            let input = value
                .input_files
                .first()
                .map(PathBuf::from)
                .ok_or("Decryption requires an input file")?;
            return Ok(Mode::Decrypt {
                input,
                output: value.output,
            });
        }

        // --verify
        if let Some(signature) = value.verify {
            let has_stdin_marker = value.input_files.iter().any(|f| f == "-");
            if has_stdin_marker {
                Ok(Mode::Verify {
                    signature_file: signature,
                })
            } else {
                // pass calls: --verify FILE.sig FILE (two positional args, no "-")
                // Also support this form
                Ok(Mode::Verify {
                    signature_file: signature,
                })
            }
        } else if value.detach_sign || value.sign {
            // Signing: -u is required, but --default-key can serve as fallback
            let signer_id = value
                .local_user
                .or(value.default_key)
                .ok_or("Signing requires -u or --default-key")?;
            Ok(Mode::Sign {
                signer_id,
                armor: value.armor,
            })
        } else {
            Ok(Mode::None)
        }
    }
}
