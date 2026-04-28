mod cli;

use std::io::{stderr, stdin, stdout};

use clap::{CommandFactory, Parser};
use clap_complete::generate;
use tumpa_cli::gpg;

use cli::*;

fn main() {
    env_logger::builder().format_timestamp_micros().init();

    let args = Args::parse();
    let keystore_path = args.keystore.clone();

    let res = match Mode::try_from(args) {
        Ok(Mode::Sign {
            signer_id,
            armor,
            digest_algo,
            shape,
        }) => match shape {
            SignShape::Detached => gpg::sign::sign(
                stdin(),
                stdout(),
                stderr(),
                &signer_id,
                armor,
                digest_algo.as_deref(),
                keystore_path.as_ref(),
            ),
            SignShape::Cleartext => gpg::sign::clearsign(
                stdin(),
                stdout(),
                stderr(),
                &signer_id,
                keystore_path.as_ref(),
            ),
            SignShape::InlineOpaque => gpg::sign::sign_inline(
                stdin(),
                stdout(),
                stderr(),
                &signer_id,
                keystore_path.as_ref(),
            ),
        },
        Ok(Mode::Verify { signature_file }) => gpg::verify::verify(
            stdin(),
            stdout(),
            stderr(),
            &signature_file,
            keystore_path.as_ref(),
        ),
        Ok(Mode::Encrypt {
            recipients,
            output,
            input,
            armor,
            signer_id,
        }) => gpg::encrypt::encrypt(
            input.as_ref(),
            &output,
            &recipients,
            armor,
            signer_id.as_deref(),
            keystore_path.as_ref(),
        ),
        Ok(Mode::Decrypt {
            input,
            output,
            verify,
        }) => {
            if verify {
                gpg::decrypt::decrypt_and_verify(
                    &input,
                    output.as_ref(),
                    keystore_path.as_ref(),
                    stderr(),
                )
            } else {
                gpg::decrypt::decrypt(&input, output.as_ref(), keystore_path.as_ref())
            }
        }
        Ok(Mode::DecryptListOnly { input }) => {
            gpg::decrypt::decrypt_list_only(&input, keystore_path.as_ref())
        }
        Ok(Mode::ListKeysColon { key_ids }) => {
            gpg::keys::list_keys_colon(&key_ids, keystore_path.as_ref())
        }
        Ok(Mode::ListSecretKeysColon) => gpg::keys::list_secret_keys_colon(keystore_path.as_ref()),
        Ok(Mode::ListConfig) => gpg::keys::list_config(),
        Ok(Mode::Completions { shell }) => {
            generate(shell, &mut Args::command(), "tclig", &mut stdout());
            Ok(())
        }
        Ok(Mode::None) => {
            print_help();
            Ok(())
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = res {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn print_help() {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "tclig".to_string());

    eprintln!(
        "tclig - GPG drop-in backed by the tumpa keystore

Invoked by git, pass, and anything else that expects a `gpg.program`.
For human-facing key management use `tcli` instead.

To use with git:

  $ git config --global gpg.program {exe}
  $ git config --global user.signingkey <FINGERPRINT>
  $ git config --global commit.gpgsign true

To use with pass (password-store):

  $ ln -s {exe} ~/bin/gpg2
  $ pass init <FINGERPRINT>

Keys are stored in ~/.tumpa/keys.db (managed by the tumpa desktop app
or `tcli --import`). Hardware OpenPGP cards are tried first, then
software keys from the keystore."
    );
}
