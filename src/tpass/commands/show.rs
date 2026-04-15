use anyhow::Result;

use crate::util::{clip, config, crypto, tree};

use super::init::{check_sneaky_paths, checked_passfile_path, checked_store_path};

/// `tpass [show] [--clip[=N],-c[N]] [--qrcode[=N],-q[N]] [pass-name]`
pub fn cmd_show(path: Option<&str>, clip_line: Option<usize>, qrcode_line: Option<usize>) -> Result<()> {
    let prefix = config::store_dir();

    let path = path.unwrap_or("");
    if !path.is_empty() {
        check_sneaky_paths(&[path])?;
    }

    let passfile = checked_passfile_path(&prefix, path)?;
    let dir_path = checked_store_path(&prefix, path)?;

    if passfile.is_file() {
        let plaintext = crypto::decrypt_file(&passfile, None)?;
        let content = String::from_utf8_lossy(&plaintext);

        if let Some(line_num) = clip_line {
            let line = content
                .lines()
                .nth(line_num - 1)
                .unwrap_or("");
            if line.is_empty() {
                anyhow::bail!(
                    "There is no password to put on the clipboard at line {}.",
                    line_num
                );
            }
            clip::clip(line, path)?;
        } else if let Some(line_num) = qrcode_line {
            let line = content
                .lines()
                .nth(line_num - 1)
                .unwrap_or("");
            if line.is_empty() {
                anyhow::bail!(
                    "There is no password to put on the clipboard at line {}.",
                    line_num
                );
            }
            qrcode(line, path)?;
        } else {
            print!("{}", content);
        }
    } else if dir_path.is_dir() {
        let header = if path.is_empty() {
            "Password Store".to_string()
        } else {
            path.trim_end_matches('/').to_string()
        };
        tree::show_tree(&dir_path, &header)?;
    } else if path.is_empty() {
        anyhow::bail!("Error: password store is empty. Try \"tpass init\".");
    } else {
        anyhow::bail!("Error: {} is not in the password store.", path);
    }

    Ok(())
}

/// Display data as QR code using qrencode.
fn qrcode(data: &str, name: &str) -> Result<()> {
    use std::process::{Command, Stdio};

    let has_display =
        std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok();

    if has_display {
        // Try graphical viewers: feh, gm, display
        for (viewer, args) in &[
            ("feh", vec!["-x", "--title", &format!("pass: {}", name), "-g", "+200+200", "-"]),
            ("gm", vec!["display", "-title", &format!("pass: {}", name), "-geometry", "+200+200", "-"]),
            ("display", vec!["-title", &format!("pass: {}", name), "-geometry", "+200+200", "-"]),
        ] {
            if Command::new("which")
                .arg(viewer)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let qr = Command::new("qrencode")
                    .args(["--size", "10", "-o", "-"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn();

                if let Ok(mut qr_child) = qr {
                    if let Some(mut stdin) = qr_child.stdin.take() {
                        use std::io::Write;
                        let _ = stdin.write_all(data.as_bytes());
                    }
                    let qr_output = qr_child.wait_with_output()?;

                    let mut view_child = Command::new(viewer)
                        .args(args)
                        .stdin(Stdio::piped())
                        .spawn()?;

                    if let Some(mut stdin) = view_child.stdin.take() {
                        use std::io::Write;
                        let _ = stdin.write_all(&qr_output.stdout);
                    }
                    let _ = view_child.wait();
                    return Ok(());
                }
            }
        }
    }

    // Fallback: UTF-8 terminal output
    let mut child = Command::new("qrencode")
        .args(["-t", "utf8"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| anyhow::anyhow!("qrencode is not installed"))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(data.as_bytes());
    }
    let _ = child.wait();

    Ok(())
}
