mod cli;

use std::io::{stderr, stdin, stdout};

use clap::{CommandFactory, Parser};
use clap_complete::generate;
use tumpa_cli::{gpg, keystore, pinentry, ssh, store};

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
        Ok(Mode::Agent {
            ssh,
            ssh_host,
            cache_ttl,
        }) => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(tumpa_cli::agent::run_agent(ssh, ssh_host, cache_ttl, keystore_path))
        }
        Ok(Mode::SshAgent { host }) => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(ssh::run_agent(&host, keystore_path))
        }
        Ok(Mode::SshExport {
            key_id,
            ssh_pubkey_file,
        }) => ssh_export(&key_id, &ssh_pubkey_file, keystore_path.as_ref()),
        Ok(Mode::Import { paths, recursive }) => {
            keystore::cmd_import(&paths, recursive, keystore_path.as_ref())
        }
        Ok(Mode::Export {
            key_id,
            armor,
            binary,
            output,
        }) => keystore::cmd_export(&key_id, armor, binary, output.as_ref(), keystore_path.as_ref()),
        Ok(Mode::Info { key_id }) => keystore::cmd_info(&key_id, keystore_path.as_ref()),
        Ok(Mode::Desc { path }) => keystore::cmd_desc(&path),
        Ok(Mode::Delete { key_id, force }) => {
            keystore::cmd_delete(&key_id, force, keystore_path.as_ref())
        }
        Ok(Mode::Search { query, email }) => {
            keystore::cmd_search(&query, email, keystore_path.as_ref())
        }
        Ok(Mode::Fetch { email, dry_run }) => {
            keystore::cmd_fetch(&email, dry_run, keystore_path.as_ref())
        }
        Ok(Mode::Completions { shell }) => {
            generate(shell, &mut Args::command(), "tcli", &mut stdout());
            Ok(())
        }
        Ok(Mode::CardStatus) => card_status(),
        Ok(Mode::ShowSocket { ssh }) => {
            if ssh {
                match tumpa_cli::agent::default_ssh_socket_path() {
                    Ok(path) => { println!("{}", path); Ok(()) }
                    Err(e) => Err(e),
                }
            } else {
                match tumpa_cli::agent::default_socket_path() {
                    Ok(path) => { println!("{}", path.display()); Ok(()) }
                    Err(e) => Err(e),
                }
            }
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

fn ssh_export(
    key_id: &str,
    ssh_pubkey_file: &std::path::PathBuf,
    keystore_path: Option<&std::path::PathBuf>,
) -> anyhow::Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let (cert_data, cert_info) = store::resolve_signer(&keystore, key_id)?;

    let uid = cert_info
        .user_ids
        .first()
        .map(|u| u.value.as_str())
        .unwrap_or(&cert_info.fingerprint);
    let ssh_pubkey = wecanencrypt::get_ssh_pubkey(&cert_data, Some(uid))
        .map_err(|e| anyhow::anyhow!("Failed to export SSH public key: {}", e))?;
    std::fs::write(ssh_pubkey_file, &ssh_pubkey)
        .map_err(|e| anyhow::anyhow!("Failed to write {:?}: {}", ssh_pubkey_file, e))?;

    eprintln!("Exported SSH public key to {:?}", ssh_pubkey_file);

    Ok(())
}

fn list_keys(keystore_path: Option<&std::path::PathBuf>) -> anyhow::Result<()> {
    let keystore = store::open_keystore(keystore_path)?;
    let keys = keystore.list_keys()?;

    if keys.is_empty() {
        println!("No keys in keystore.");
        return Ok(());
    }

    for key in &keys {
        let secret_marker = if key.is_secret { "sec" } else { "pub" };
        let uid = key
            .user_ids
            .first()
            .map(|u| u.value.as_str())
            .unwrap_or("<no UID>");

        println!("{} {} {}", secret_marker, key.fingerprint, uid);
    }

    Ok(())
}

fn card_status() -> anyhow::Result<()> {
    let cards = wecanencrypt::card::list_all_cards()
        .map_err(|e| anyhow::anyhow!("Failed to enumerate cards: {}", e))?;

    if cards.is_empty() {
        println!("No OpenPGP card detected.");
        return Ok(());
    }

    for (i, card_summary) in cards.iter().enumerate() {
        if i > 0 {
            println!();
        }

        let info = wecanencrypt::card::get_card_details(Some(&card_summary.ident))
            .map_err(|e| anyhow::anyhow!("Failed to read card {}: {}", card_summary.ident, e))?;

        println!("Manufacturer .....: {}", info.manufacturer_name.as_deref().unwrap_or("Unknown"));
        println!("Serial number ....: {}", info.serial_number);

        if let Some(ref name) = info.cardholder_name {
            let formatted = pinentry::format_cardholder_name(name);
            if !formatted.is_empty() {
                println!("Name of cardholder: {}", formatted);
            }
        }

        if let Some(ref url) = info.public_key_url {
            if !url.is_empty() {
                println!("URL of public key : {}", url);
            }
        }

        print_card_key("Signature key ....", &info.signature_fingerprint);
        print_card_key("Encryption key ...", &info.encryption_fingerprint);
        print_card_key("Authentication key", &info.authentication_fingerprint);

        println!("Signature counter : {}", info.signature_counter);
        println!(
            "PIN retry counter : {} {} {}",
            info.pin_retry_counter,
            info.reset_code_retry_counter,
            info.admin_pin_retry_counter
        );
    }

    Ok(())
}

fn print_card_key(label: &str, fingerprint: &Option<String>) {
    match fingerprint {
        Some(fp) if !fp.is_empty() && fp != "0000000000000000000000000000000000000000" => {
            // Format as "XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX"
            // (groups of 4, double space after the 5th group, matching gpg)
            let fp_upper = fp.to_uppercase();
            let groups: Vec<&str> = (0..fp_upper.len())
                .step_by(4)
                .map(|i| &fp_upper[i..(i + 4).min(fp_upper.len())])
                .collect();
            let formatted = if groups.len() >= 10 {
                format!(
                    "{}  {}",
                    groups[..5].join(" "),
                    groups[5..].join(" ")
                )
            } else {
                groups.join(" ")
            };
            println!("{}: {}", label, formatted);
        }
        _ => {
            println!("{}: [none]", label);
        }
    }
}
