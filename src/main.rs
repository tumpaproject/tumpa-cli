mod cache;
mod cli;
mod gpg;
mod pinentry;
mod ssh;
mod store;

use std::io::{stderr, stdin, stdout};

use clap::Parser;

use cli::*;

fn main() {
    env_logger::builder().format_timestamp_micros().init();

    let args = Args::parse();
    let keystore_path = args.keystore.clone();

    let res = match Mode::try_from(args) {
        Ok(Mode::Sign { signer_id, armor }) => gpg::sign::sign(
            stdin(),
            stdout(),
            stderr(),
            &signer_id,
            armor,
            keystore_path.as_ref(),
        ),
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
        }) => gpg::encrypt::encrypt(
            input.as_ref(),
            &output,
            &recipients,
            armor,
            keystore_path.as_ref(),
        ),
        Ok(Mode::Decrypt { input, output }) => {
            gpg::decrypt::decrypt(&input, output.as_ref(), keystore_path.as_ref())
        }
        Ok(Mode::DecryptListOnly { input }) => {
            gpg::decrypt::decrypt_list_only(&input, keystore_path.as_ref())
        }
        Ok(Mode::ListKeysColon { key_ids }) => {
            gpg::keys::list_keys_colon(&key_ids, keystore_path.as_ref())
        }
        Ok(Mode::ListSecretKeysColon) => {
            gpg::keys::list_secret_keys_colon(keystore_path.as_ref())
        }
        Ok(Mode::ListConfig) => gpg::keys::list_config(),
        Ok(Mode::ListKeys) => list_keys(keystore_path.as_ref()),
        Ok(Mode::SshAgent { host }) => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(ssh::run_agent(&host, keystore_path))
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
        .unwrap_or_else(|| "tcli".to_string());

    eprintln!(
        "tcli - GPG replacement and SSH agent backed by tumpa keystore

To use with git:

  $ git config --global gpg.program {exe}
  $ git config --global user.signingkey <FINGERPRINT>
  $ git config --global commit.gpgsign true

To use with pass (password-store):

  $ alias gpg={exe}
  $ pass init <FINGERPRINT>

To list keys in the keystore:

  $ tcli --list-keys

Keys are stored in ~/.tumpa/keys.db (managed by the tumpa desktop app).
Hardware OpenPGP cards are tried first, then software keys from the keystore."
    );
}

fn list_keys(keystore_path: Option<&std::path::PathBuf>) -> anyhow::Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let certs = keystore.list_certs()?;

    if certs.is_empty() {
        println!("No keys in keystore.");
        return Ok(());
    }

    for cert in &certs {
        let secret_marker = if cert.is_secret { "sec" } else { "pub" };
        let uid = cert
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or("<no UID>");

        println!("{} {} {}", secret_marker, cert.fingerprint, uid);
    }

    Ok(())
}
