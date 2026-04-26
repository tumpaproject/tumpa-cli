use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::config;

/// Copy data to clipboard and clear after PASSWORD_STORE_CLIP_TIME seconds.
/// Matches pass's clip() function behavior.
pub fn clip(data: &str, display_name: &str) -> Result<()> {
    let clip_time = config::clip_time();
    let x_selection = config::x_selection();

    let (copy_cmd, paste_cmd, display) = detect_clipboard(&x_selection)?;

    let sleep_argv0 = format!("password store sleep on display {}", display);

    // Kill any previous clip timer
    let _ = Command::new("pkill")
        .args(["-f", &format!("^{}", sleep_argv0)])
        .status();

    // Snapshot current clipboard content (base64 encoded to handle binary)
    let before = get_clipboard_base64(&paste_cmd);

    // Copy data to clipboard
    let mut child = Command::new(&copy_cmd[0])
        .args(&copy_cmd[1..])
        .stdin(Stdio::piped())
        .spawn()
        .context("Could not copy data to the clipboard")?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(data.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("Error: Could not copy data to the clipboard");
    }

    // Spawn background process to clear clipboard after timeout
    let paste_cmd_str = paste_cmd.join(" ");
    let copy_cmd_str = copy_cmd.join(" ");
    // We use a bash background process to match pass behavior exactly
    let script = format!(
        r#"
        sleep {clip_time}
        now="$({paste_cmd_str} 2>/dev/null | base64)"
        expected="$(echo -n '{data_escaped}' | base64)"
        if [ "$now" != "$expected" ]; then
            before="$now"
        else
            before="{before}"
        fi
        echo "$before" | base64 -d | {copy_cmd_str}
        qdbus org.kde.klipper /klipper org.kde.klipper.klipper.clearClipboardHistory 2>/dev/null || true
        "#,
        clip_time = clip_time,
        paste_cmd_str = paste_cmd_str,
        copy_cmd_str = copy_cmd_str,
        data_escaped = shell_escape(data),
        before = before.unwrap_or_default(),
    );

    Command::new("bash")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok(); // Best effort — don't fail if background process fails

    println!(
        "Copied {} to clipboard. Will clear in {} seconds.",
        display_name, clip_time
    );

    Ok(())
}

fn detect_clipboard(x_selection: &str) -> Result<(Vec<String>, Vec<String>, String)> {
    if let Ok(display) = std::env::var("WAYLAND_DISPLAY") {
        if which("wl-copy") {
            let mut copy_cmd = vec!["wl-copy".to_string()];
            let mut paste_cmd = vec!["wl-paste".to_string(), "-n".to_string()];
            if x_selection == "primary" {
                copy_cmd.push("--primary".to_string());
                paste_cmd.push("--primary".to_string());
            }
            return Ok((copy_cmd, paste_cmd, display));
        }
    }

    if let Ok(display) = std::env::var("DISPLAY") {
        if which("xclip") {
            let copy_cmd = vec![
                "xclip".to_string(),
                "-selection".to_string(),
                x_selection.to_string(),
            ];
            let paste_cmd = vec![
                "xclip".to_string(),
                "-o".to_string(),
                "-selection".to_string(),
                x_selection.to_string(),
            ];
            return Ok((copy_cmd, paste_cmd, display));
        }
    }

    // macOS
    if which("pbcopy") {
        return Ok((
            vec!["pbcopy".to_string()],
            vec!["pbpaste".to_string()],
            "macOS".to_string(),
        ));
    }

    anyhow::bail!("Error: No X11 or Wayland display and clipper detected")
}

fn which(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn get_clipboard_base64(paste_cmd: &[String]) -> Option<String> {
    let paste_output = Command::new(&paste_cmd[0])
        .args(&paste_cmd[1..])
        .output()
        .ok()?;

    let base64_output = Command::new("base64")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                let _ = stdin.write_all(&paste_output.stdout);
            }
            child.wait_with_output().ok()
        })?;

    Some(
        String::from_utf8_lossy(&base64_output.stdout)
            .trim()
            .to_string(),
    )
}

fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}
