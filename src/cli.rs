use std::convert::TryFrom;
use std::path::PathBuf;

use clap::Parser;

/// A GPG-compatible CLI for git signing/verification backed by tumpa keystore,
/// with optional SSH agent mode.
///
/// Designed to be used as `gpg.program` in git configuration.
/// Tries hardware OpenPGP cards first, then falls back to software keys
/// from ~/.tumpa/keys.db.
#[derive(Parser, Debug)]
#[clap(name = "tcli")]
pub struct Args {
    /// Verify a detached signature.
    /// The signed data must be provided via STDIN.
    #[clap(long, value_names = ["SIGNATURE_FILE"])]
    pub verify: Option<PathBuf>,

    /// Create a detached signature.
    #[clap(long, short = 'b')]
    pub detach_sign: bool,

    /// Sign mode (accepted alongside --detach-sign).
    #[clap(long, short = 's', hide = true)]
    pub sign: bool,

    /// Output ASCII-armored signatures.
    #[clap(long, short = 'a')]
    pub armor: bool,

    /// Signing key fingerprint or key ID.
    #[clap(long, short = 'u', value_names = ["SIGNING_KEY"])]
    pub local_user: Option<String>,

    /// Git passes this, we accept and ignore it.
    #[clap(long, hide = true)]
    pub keyid_format: Option<String>,

    /// Git passes this, we accept and ignore it.
    #[clap(long, hide = true)]
    pub status_fd: Option<String>,

    /// Positional argument (git passes "-" for stdin in verify mode).
    pub file_to_verify: Option<String>,

    /// Path to tumpa keystore database.
    /// Defaults to ~/.tumpa/keys.db.
    #[clap(long, env = "TUMPA_KEYSTORE")]
    pub keystore: Option<PathBuf>,

    /// List keys in the tumpa keystore.
    #[clap(long)]
    pub list_keys: bool,

    /// SSH agent subcommand.
    #[clap(subcommand)]
    pub subcmd: Option<SubCommand>,
}

#[derive(Parser, Debug)]
pub enum SubCommand {
    /// Run as an SSH agent daemon.
    SshAgent {
        /// Binding host (e.g., unix:///tmp/tcli.sock).
        #[clap(short = 'H', long)]
        host: String,
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
    SshAgent {
        host: String,
    },
    ListKeys,
    None,
}

impl TryFrom<Args> for Mode {
    type Error = String;

    fn try_from(value: Args) -> Result<Self, Self::Error> {
        if value.list_keys {
            return Ok(Mode::ListKeys);
        }

        if let Some(SubCommand::SshAgent { host }) = value.subcmd {
            return Ok(Mode::SshAgent { host });
        }

        if let Some(signature) = value.verify {
            if Some("-".into()) == value.file_to_verify {
                Ok(Mode::Verify {
                    signature_file: signature,
                })
            } else {
                Err("Verification requires '-' as positional argument (data from stdin)".into())
            }
        } else if value.detach_sign || value.sign {
            if let Some(user_id) = value.local_user {
                Ok(Mode::Sign {
                    signer_id: user_id,
                    armor: value.armor,
                })
            } else {
                Err("The -u parameter is required for signing".into())
            }
        } else {
            Ok(Mode::None)
        }
    }
}
