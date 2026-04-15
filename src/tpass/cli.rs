use clap::{Parser, Subcommand};

#[derive(Parser)]
#[clap(
    name = "tpass",
    about = "tpass - password store backed by tumpa keystore",
    version,
    disable_help_subcommand = true,
)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Option<Command>,

    /// Remaining args (for default show/extension behavior)
    #[clap(trailing_var_arg = true)]
    pub args: Vec<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize new password storage and use gpg-id for encryption.
    Init {
        /// Subfolder to initialize
        #[clap(short = 'p', long = "path")]
        path: Option<String>,

        /// GPG IDs for encryption
        #[clap(required = true)]
        gpg_ids: Vec<String>,
    },

    /// List passwords.
    #[clap(alias = "list")]
    Ls {
        /// Subfolder to list
        subfolder: Option<String>,
    },

    /// Show existing password.
    Show {
        /// Copy to clipboard (optionally specify line number)
        #[clap(short = 'c', long = "clip")]
        clip: Option<Option<usize>>,

        /// Show as QR code (optionally specify line number)
        #[clap(short = 'q', long = "qrcode")]
        qrcode: Option<Option<usize>>,

        /// Password name
        pass_name: Option<String>,
    },

    /// List passwords that match pass-names.
    #[clap(alias = "search")]
    Find {
        /// Search terms
        #[clap(required = true)]
        pass_names: Vec<String>,
    },

    /// Search for password files containing search-string when decrypted.
    Grep {
        /// Grep options and search string
        #[clap(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Insert new password.
    #[clap(alias = "add")]
    Insert {
        /// Read multiline from stdin
        #[clap(short = 'm', long)]
        multiline: bool,

        /// Echo the password back
        #[clap(short = 'e', long)]
        echo: bool,

        /// Force overwrite
        #[clap(short = 'f', long)]
        force: bool,

        /// Password name
        pass_name: String,
    },

    /// Insert a new password or edit an existing password using editor.
    Edit {
        /// Password name
        pass_name: String,
    },

    /// Generate a new password.
    Generate {
        /// Generate password with no symbols
        #[clap(short = 'n', long = "no-symbols")]
        no_symbols: bool,

        /// Copy to clipboard
        #[clap(short = 'c', long)]
        clip: bool,

        /// Show as QR code
        #[clap(short = 'q', long)]
        qrcode: bool,

        /// Replace first line of existing entry
        #[clap(short = 'i', long = "in-place")]
        in_place: bool,

        /// Force overwrite
        #[clap(short = 'f', long)]
        force: bool,

        /// Password name
        pass_name: String,

        /// Password length
        pass_length: Option<usize>,
    },

    /// Remove existing password or directory.
    #[clap(alias = "delete", alias = "remove")]
    Rm {
        /// Recursively delete
        #[clap(short = 'r', long)]
        recursive: bool,

        /// Force delete without prompt
        #[clap(short = 'f', long)]
        force: bool,

        /// Password name
        pass_name: String,
    },

    /// Renames or moves old-path to new-path.
    #[clap(alias = "rename")]
    Mv {
        /// Force overwrite
        #[clap(short = 'f', long)]
        force: bool,

        /// Old path
        old_path: String,

        /// New path
        new_path: String,
    },

    /// Copies old-path to new-path.
    #[clap(alias = "copy")]
    Cp {
        /// Force overwrite
        #[clap(short = 'f', long)]
        force: bool,

        /// Old path
        old_path: String,

        /// New path
        new_path: String,
    },

    /// Execute a git command on the password store.
    Git {
        /// Git command and arguments
        #[clap(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Show version information.
    Version,
}
