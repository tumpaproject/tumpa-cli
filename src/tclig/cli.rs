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

    /// Sign mode. Without --detach-sign or --clearsign, produces an
    /// inline opaque signed message (`gpg --sign` shape). When combined
    /// with --detach-sign, the detached path wins.
    #[clap(long, short = 's')]
    pub sign: bool,

    /// Produce a cleartext-signed message (`-----BEGIN PGP SIGNED
    /// MESSAGE-----`). Card-first dispatch: a connected OpenPGP card
    /// whose signing slot matches the signer is used before falling
    /// back to a software secret key.
    #[clap(long)]
    pub clearsign: bool,

    /// Hash algorithm for the detached signature: SHA256, SHA384, or
    /// SHA512. Software-keys only — card-backed signing always uses
    /// the digest the card chose. Used by PGP/MIME callers that need
    /// to lock `micalg` (RFC 3156).
    #[clap(long, value_name = "ALGO")]
    pub digest_algo: Option<String>,

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

    /// With --decrypt: also verify any inner OpenPGP signature on the
    /// payload and emit `[GNUPG:] GOODSIG / BADSIG / NO_PUBKEY` status
    /// lines on stderr. Card-first dispatch: a card whose decryption
    /// slot matches is used before falling back to the software key.
    #[clap(long)]
    pub verify_decrypt: bool,

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

/// Which shape of signature `tclig` should produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignShape {
    /// `gpg --detach-sign` / `-b`: standalone signature, payload
    /// elsewhere. Used by git, PGP/MIME `multipart/signed`.
    Detached,
    /// `gpg --clearsign`: `-----BEGIN PGP SIGNED MESSAGE-----` block
    /// with the original text inline. Used by mailing lists, README
    /// signatures, and the rare PGP/INLINE email path.
    Cleartext,
    /// `gpg --sign` (without `-b`): signed-then-literal packet stream,
    /// the recipient gets back the original bytes after `--decrypt`.
    InlineOpaque,
}

pub enum Mode {
    Sign {
        signer_id: String,
        armor: bool,
        digest_algo: Option<String>,
        shape: SignShape,
    },
    Verify {
        signature_file: PathBuf,
    },
    Encrypt {
        recipients: Vec<String>,
        output: PathBuf,
        input: Option<PathBuf>,
        armor: bool,
        /// When `Some`, sign-then-encrypt (single OpenPGP message
        /// containing a one-pass-signature, the literal data, and
        /// the signature packet — i.e. what `gpg --sign --encrypt`
        /// produces). Card-first dispatch: a connected OpenPGP card
        /// whose signing slot matches the signer is used before
        /// falling back to a software secret key.
        signer_id: Option<String>,
    },
    Decrypt {
        input: PathBuf,
        output: Option<PathBuf>,
        verify: bool,
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

        // --encrypt (optionally combined with --sign / -u for the
        // canonical "sign and encrypt in one OpenPGP message" path,
        // which is what most encrypted email clients produce).
        if value.encrypt {
            if value.recipients.is_empty() {
                return Err("Encryption requires at least one -r/--recipient".into());
            }
            // --clearsign produces an armored "BEGIN PGP SIGNED
            // MESSAGE" block — that shape is incompatible with
            // --encrypt (encryption wraps a binary message, not
            // a cleartext-signed envelope). GnuPG itself rejects
            // this combination, and silently coercing it to
            // sign+encrypt would change the output format the
            // user explicitly asked for.
            if value.clearsign {
                return Err("--clearsign cannot be combined with --encrypt; \
                     use --sign for sign-then-encrypt"
                    .into());
            }
            // --digest-algo only locks the digest for the detached
            // signing path; in --encrypt mode there is no detached
            // signature to attach a `micalg` to, so the flag has no
            // meaning. Silently ignoring it would mislead PGP/MIME
            // callers that include it as a default — better to fail
            // loudly so the caller drops the flag.
            if value.digest_algo.is_some() {
                return Err("--digest-algo is not supported with --encrypt; \
                     it only locks the digest for detached signatures (-b)"
                    .into());
            }
            let output = value.output.ok_or("Encryption requires -o/--output")?;
            let input = value.input_files.first().map(PathBuf::from);

            // If --sign or --detach-sign accompanies --encrypt, the
            // user wants sign+encrypt. --detach-sign + --encrypt is
            // not a meaningful GPG combination (detached sigs are
            // standalone), so we treat it as a request for inline
            // sign-then-encrypt — same as `gpg --sign --encrypt`.
            // Either explicit --sign or just `-u <key>` alongside
            // --encrypt is enough to engage the signing path,
            // matching GnuPG's lenient behavior.
            let signer_id = if value.sign || value.detach_sign || value.local_user.is_some() {
                Some(value.local_user.or(value.default_key).ok_or(
                    "Sign+encrypt requires -u/--local-user or --default-key for the signer",
                )?)
            } else {
                None
            };

            return Ok(Mode::Encrypt {
                recipients: value.recipients,
                output,
                input,
                armor: value.armor,
                signer_id,
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
                verify: value.verify_decrypt,
            });
        }

        // --verify-decrypt without --decrypt is a usage error: the
        // flag is a *modifier* on the decrypt path that asks for the
        // inner signature to be verified at the same time. Without
        // --decrypt we'd otherwise fall through to Mode::None (help),
        // which silently swallows the user's request. Implicitly
        // turning on --decrypt would risk confusion with --verify
        // (the detached path), so we reject loudly instead.
        if value.verify_decrypt {
            return Err("--verify-decrypt requires --decrypt; \
                 use --verify for detached-signature verification"
                .into());
        }

        // --verify
        if let Some(signature) = value.verify {
            return Ok(Mode::Verify {
                signature_file: signature,
            });
        }

        // Signing: --detach-sign (-b), --clearsign, or --sign (-s).
        // Precedence: detached > cleartext > inline-opaque. This matches
        // git/pass which always pass -b and want detached even if -s is
        // also present.
        if value.detach_sign || value.clearsign || value.sign {
            let signer_id = value
                .local_user
                .or(value.default_key)
                .ok_or("Signing requires -u or --default-key")?;
            let shape = if value.detach_sign {
                SignShape::Detached
            } else if value.clearsign {
                SignShape::Cleartext
            } else {
                SignShape::InlineOpaque
            };
            // --digest-algo only locks the digest for the detached path;
            // clearsign and inline-opaque embed the digest in the
            // signature packet so the receiver doesn't need PGP/MIME
            // micalg negotiation. Accepting it for those shapes would
            // be a silent no-op, which is exactly the trap a GPG
            // drop-in must avoid.
            if value.digest_algo.is_some() && shape != SignShape::Detached {
                return Err("--digest-algo is only supported for detached signatures (-b)".into());
            }
            return Ok(Mode::Sign {
                signer_id,
                armor: value.armor,
                digest_algo: value.digest_algo,
                shape,
            });
        }

        Ok(Mode::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Convenience: parse a tclig argv into a `Mode`. `args[0]` is
    /// the binary name, like clap expects.
    fn mode_from_args(args: &[&str]) -> Result<Mode, String> {
        let parsed = Args::parse_from(args);
        Mode::try_from(parsed)
    }

    /// `--encrypt` alone (no signer) → `Mode::Encrypt` with
    /// `signer_id: None`. Encrypt-only is the simplest path and must
    /// stay easy.
    #[test]
    fn encrypt_only_has_no_signer() {
        let m = mode_from_args(&[
            "tclig",
            "--encrypt",
            "-r",
            "alice@example.com",
            "-o",
            "/tmp/out.asc",
            "-a",
        ])
        .unwrap();
        match m {
            Mode::Encrypt {
                recipients,
                signer_id,
                armor,
                ..
            } => {
                assert_eq!(recipients, vec!["alice@example.com"]);
                assert_eq!(signer_id, None, "no -u/-s ⇒ encrypt-only");
                assert!(armor);
            }
            _ => panic!("expected Mode::Encrypt"),
        }
    }

    /// `--encrypt --sign -u <fpr>` → `Mode::Encrypt` with the signer
    /// populated. This is the canonical PGP/MIME outgoing combo.
    #[test]
    fn encrypt_with_explicit_sign_carries_signer() {
        let m = mode_from_args(&[
            "tclig",
            "--encrypt",
            "--sign",
            "-u",
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            "-r",
            "alice@example.com",
            "-o",
            "/tmp/out.asc",
        ])
        .unwrap();
        match m {
            Mode::Encrypt { signer_id, .. } => {
                assert_eq!(
                    signer_id.as_deref(),
                    Some("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
                );
            }
            _ => panic!("expected Mode::Encrypt with signer"),
        }
    }

    /// Just `-u <fpr>` alongside `--encrypt` (no explicit `--sign`)
    /// is enough to engage sign+encrypt — matches GnuPG's lenient
    /// behavior, where supplying a local-user implies signing.
    #[test]
    fn encrypt_with_local_user_only_carries_signer() {
        let m = mode_from_args(&[
            "tclig",
            "--encrypt",
            "-u",
            "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE",
            "-r",
            "alice@example.com",
            "-o",
            "/tmp/out.asc",
        ])
        .unwrap();
        match m {
            Mode::Encrypt { signer_id, .. } => {
                assert_eq!(
                    signer_id.as_deref(),
                    Some("FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE")
                );
            }
            _ => panic!("expected Mode::Encrypt with signer"),
        }
    }

    /// `--encrypt --sign` without `-u` or `--default-key` is a usage
    /// error: we don't know which key to sign with. The error
    /// message must mention `-u` so the user knows what to add.
    #[test]
    fn encrypt_with_sign_but_no_signer_is_an_error() {
        let result = mode_from_args(&[
            "tclig",
            "--encrypt",
            "--sign",
            "-r",
            "alice@example.com",
            "-o",
            "/tmp/out.asc",
        ]);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got Ok(Mode::...)"),
        };
        assert!(
            err.to_lowercase().contains("-u") || err.to_lowercase().contains("local-user"),
            "error must point to -u/--local-user, got: {err}"
        );
    }

    /// `--encrypt --clearsign` is incompatible (clearsign produces
    /// armored cleartext, not a binary message that --encrypt can
    /// wrap) and must be rejected with a clear error rather than
    /// silently falling back to encrypt-only.
    #[test]
    fn encrypt_with_clearsign_is_rejected() {
        let result = mode_from_args(&[
            "tclig",
            "--encrypt",
            "--clearsign",
            "-u",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "-r",
            "alice@example.com",
            "-o",
            "/tmp/out.asc",
        ]);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got Ok(Mode::...)"),
        };
        assert!(
            err.to_lowercase().contains("clearsign"),
            "error must mention --clearsign, got: {err}"
        );
    }

    /// `--digest-algo` is also meaningless with `--encrypt`: there
    /// is no detached signature to attach a `micalg` to. PGP/MIME
    /// callers shouldn't pass it, but if they do we fail loudly.
    #[test]
    fn digest_algo_with_encrypt_is_rejected() {
        let result = mode_from_args(&[
            "tclig",
            "--encrypt",
            "--digest-algo",
            "SHA512",
            "-r",
            "alice@example.com",
            "-o",
            "/tmp/out.asc",
        ]);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got Ok(Mode::...)"),
        };
        assert!(
            err.to_lowercase().contains("digest-algo"),
            "error must mention --digest-algo, got: {err}"
        );
    }

    /// `--verify-decrypt` is a modifier on `--decrypt`; standalone
    /// it would silently fall through to help. Reject loudly so the
    /// user sees their typo (likely meant `--verify` or forgot
    /// `--decrypt`).
    #[test]
    fn verify_decrypt_without_decrypt_is_rejected() {
        let result = mode_from_args(&["tclig", "--verify-decrypt"]);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got Ok(Mode::...)"),
        };
        assert!(
            err.to_lowercase().contains("verify-decrypt"),
            "error must mention --verify-decrypt, got: {err}"
        );
    }

    /// `--digest-algo` only locks `micalg` for the detached path
    /// (PGP/MIME multipart/signed). Accepting it for `--clearsign`
    /// or `--sign` (inline-opaque) would silently no-op and mislead
    /// the caller, so we reject it.
    #[test]
    fn digest_algo_with_clearsign_is_rejected() {
        let result = mode_from_args(&[
            "tclig",
            "--clearsign",
            "--digest-algo",
            "SHA512",
            "-u",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ]);
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got Ok(Mode::...)"),
        };
        assert!(
            err.to_lowercase().contains("digest-algo"),
            "error must mention --digest-algo, got: {err}"
        );
    }

    #[test]
    fn digest_algo_with_inline_sign_is_rejected() {
        let result = mode_from_args(&[
            "tclig",
            "--sign",
            "--digest-algo",
            "SHA512",
            "-u",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ]);
        assert!(
            result.is_err(),
            "--digest-algo with inline --sign must be rejected"
        );
    }

    /// `--digest-algo` with `--detach-sign` is the canonical PGP/MIME
    /// shape and must keep working.
    #[test]
    fn digest_algo_with_detach_sign_is_accepted() {
        let m = mode_from_args(&[
            "tclig",
            "--detach-sign",
            "--digest-algo",
            "SHA512",
            "-u",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ])
        .unwrap();
        match m {
            Mode::Sign {
                shape, digest_algo, ..
            } => {
                assert_eq!(shape, SignShape::Detached);
                assert_eq!(digest_algo.as_deref(), Some("SHA512"));
            }
            _ => panic!("expected Mode::Sign(Detached)"),
        }
    }

    /// Bare `--sign` (no `--encrypt`) keeps the existing sign-only
    /// path — `Mode::Sign`, not `Mode::Encrypt`. Regression guard
    /// against accidentally folding signing-only into the encrypt
    /// branch when refactoring.
    #[test]
    fn sign_only_still_goes_to_sign_mode() {
        let m = mode_from_args(&[
            "tclig",
            "--sign",
            "-u",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ])
        .unwrap();
        assert!(matches!(m, Mode::Sign { .. }));
    }
}
