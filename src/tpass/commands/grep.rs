use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::Result;

use crate::util::{config, crypto};

/// `tpass grep [GREPOPTIONS] search-string`
pub fn cmd_grep(args: &[String]) -> Result<()> {
    if args.is_empty() {
        anyhow::bail!("Usage: tpass grep [GREPOPTIONS] search-string");
    }

    let prefix = config::store_dir();

    // Walk all .gpg files
    let mut found_any = false;
    walk_and_grep(&prefix, &prefix, args, &mut found_any)?;

    Ok(())
}

fn walk_and_grep(
    dir: &std::path::Path,
    prefix: &std::path::Path,
    grep_args: &[String],
    found_any: &mut bool,
) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip .git and .extensions
        if name_str == ".git" || name_str == ".extensions" {
            continue;
        }

        if path.is_dir() {
            walk_and_grep(&path, prefix, grep_args, found_any)?;
        } else if path.extension().map(|e| e == "gpg").unwrap_or(false) {
            // Decrypt and grep
            match crypto::decrypt_file(&path, None) {
                Ok(plaintext) => {
                    let mut child = Command::new("grep")
                        .arg("--color=always")
                        .args(grep_args)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .spawn()?;

                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(&plaintext);
                    }

                    let output = child.wait_with_output()?;

                    if output.status.success() && !output.stdout.is_empty() {
                        *found_any = true;

                        // Format path like pass does: blue dir + bold filename
                        let rel = path
                            .strip_prefix(prefix)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .trim_end_matches(".gpg")
                            .to_string();

                        let (dir_part, file_part) = if let Some(pos) = rel.rfind('/') {
                            (&rel[..pos + 1], &rel[pos + 1..])
                        } else {
                            ("", rel.as_str())
                        };

                        println!(
                            "\x1b[94m{}\x1b[1m{}\x1b[0m:",
                            dir_part, file_part
                        );
                        std::io::stdout().write_all(&output.stdout)?;
                    }
                }
                Err(e) => {
                    log::debug!("Failed to decrypt {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(())
}
