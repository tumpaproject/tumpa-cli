use std::convert::TryFrom;
use std::path::PathBuf;

use clap::Parser;
use clap_complete::Shell;

/// tclig — a GPG drop-in for git, pass, and anything else that
/// expects a `gpg.program` binary. Backed by the tumpa keystore.
///
/// Most users never invoke `tclig` directly; they point
/// `git config gpg.program tclig` or symlink `gpg2` to `tclig`.
/// For human-facing key management see `tcli` instead.
#[derive(Parser, Debug)]
#[clap(name = "tclig", version)]
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

    /// List keys in the tumpa keystore (GPG colon format).
    #[clap(long)]
    pub list_keys: bool,

    /// List secret keys in the tumpa keystore (GPG colon format).
    #[clap(long)]
    pub list_secret_keys: bool,

    /// Output in colon-delimited format (for --list-keys / --list-secret-keys).
    #[clap(long)]
    pub with_colons: bool,

    /// List only metadata (used with --decrypt to inspect encrypted file).
    #[clap(long)]
    pub list_only: bool,

    // --- Positional ---

    /// Positional arguments: input files, or "-" for stdin in verify mode.
    pub input_files: Vec<String>,

    // --- Keystore ---

    /// Path to tumpa keystore database. Defaults to ~/.tumpa/keys.db.
    #[clap(long, env = "TUMPA_KEYSTORE")]
    pub keystore: Option<PathBuf>,

    // --- Shell completions ---

    /// Generate shell completions and print to stdout.
    #[clap(long, value_name = "SHELL", value_enum)]
    pub completions: Option<Shell>,

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

    #[clap(long, hide = true)]
    pub debug: Option<String>,

    #[clap(long, hide = true)]
    pub debug_level: Option<String>,
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
    ListConfig,
    Completions {
        shell: Shell,
    },
    None,
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        // --- Shell completions ---

        if let Some(shell) = value.completions {
            return Ok(Mode::Completions { shell });
        }

        // --- GPG compatibility modes ---

        // --list-config (pass uses this to query GPG groups)
        if value.list_config {
            return Ok(Mode::ListConfig);
        }

        // --list-secret-keys --with-colons
        if value.list_secret_keys {
            return Ok(Mode::ListSecretKeysColon);
        }

        // --list-keys (always colon format in tclig)
        if value.list_keys {
            return Ok(Mode::ListKeysColon {
                key_ids: value.input_files,
            });
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
            return Ok(Mode::Verify {
                signature_file: signature,
            });
        }

        // -b / -s (signing)
        if value.detach_sign || value.sign {
            // Signing: -u is required, but --default-key can serve as fallback
            let signer_id = value
                .local_user
                .or(value.default_key)
                .ok_or("Signing requires -u or --default-key")?;
            return Ok(Mode::Sign {
                signer_id,
                armor: value.armor,
            });
        }

        Ok(Mode::None)
    }
}
