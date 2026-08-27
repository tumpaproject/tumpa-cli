use std::io::Write;
use std::process::{Command, Stdio};

use tempfile::TempDir;
use wecanencrypt::create_key_simple;

fn run_tclig(args: &[String], input: &[u8], keystore: &std::path::Path) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tclig"));
    command
        .args(args)
        .arg("--keystore")
        .arg(keystore)
        .env("TUMPA_PASSPHRASE", "pw")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("tclig must start");
    child
        .stdin
        .take()
        .expect("stdin must be piped")
        .write_all(input)
        .expect("stdin write must succeed");
    child.wait_with_output().expect("tclig must exit")
}

/// Exercise the stdin/stdout argv shapes SOPS uses for its configured GPG
/// executable. The extra `--keystore` is test setup; SOPS itself supplies all
/// preceding encryption flags and invokes decryption as just `-d`.
#[test]
fn sops_argv_shapes_encrypt_and_decrypt_over_stdio() {
    let temp = TempDir::new().unwrap();
    let keystore_path = temp.path().join("keys.db");
    let key = create_key_simple("pw", &["SOPS test <sops@example.com>"]).unwrap();
    let keystore = wecanencrypt::KeyStore::open(&keystore_path).unwrap();
    keystore.import_key(&key.secret_key).unwrap();
    drop(keystore);

    let trusted_key = key.fingerprint[key.fingerprint.len() - 8..].to_string();
    let encrypt_args = vec![
        "--no-default-recipient".to_string(),
        "--yes".to_string(),
        "--encrypt".to_string(),
        "-a".to_string(),
        "-r".to_string(),
        key.fingerprint.clone(),
        "--trusted-key".to_string(),
        trusted_key,
        "--no-encrypt-to".to_string(),
    ];
    let plaintext = b"SOPS stdin/stdout compatibility\n";
    let encrypted = run_tclig(&encrypt_args, plaintext, &keystore_path);
    assert!(
        encrypted.status.success(),
        "encryption failed: {}",
        String::from_utf8_lossy(&encrypted.stderr)
    );
    assert!(encrypted.stdout.starts_with(b"-----BEGIN PGP MESSAGE-----"));

    let decrypted = run_tclig(&["-d".to_string()], &encrypted.stdout, &keystore_path);
    assert!(
        decrypted.status.success(),
        "decryption failed: {}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    assert_eq!(decrypted.stdout, plaintext);
}
