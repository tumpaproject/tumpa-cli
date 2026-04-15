use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// Display a tree listing of the password store, stripping .gpg extensions.
/// Matches pass's tree output format.
pub fn show_tree(dir: &Path, header: &str) -> Result<()> {
    let output = Command::new("tree")
        .args(["-N", "-C", "-l", "--noreport"])
        .arg(dir)
        .output()
        .context("Failed to run 'tree'. Is the 'tree' command installed?")?;

    if !output.status.success() {
        anyhow::bail!("tree command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", header);

    // Skip the first line (directory name) and strip .gpg extensions
    // while preserving ANSI color codes. Matches pass's sed:
    // sed -E 's/\.gpg(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'
    for line in stdout.lines().skip(1) {
        println!("{}", strip_gpg_extension(line));
    }

    Ok(())
}

/// Display a tree listing filtered by patterns (for find command).
pub fn show_tree_find(dir: &Path, patterns: &[String]) -> Result<()> {
    // Build pattern: *term1*|*term2*
    let pattern = patterns
        .iter()
        .map(|t| format!("*{}*", t))
        .collect::<Vec<_>>()
        .join("|");

    let output = Command::new("tree")
        .args([
            "-N",
            "-C",
            "-l",
            "--noreport",
            "-P",
            &pattern,
            "--prune",
            "--matchdirs",
            "--ignore-case",
        ])
        .arg(dir)
        .output()
        .context("Failed to run 'tree'. Is the 'tree' command installed?")?;

    if !output.status.success() {
        anyhow::bail!("tree command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Skip first line, strip .gpg extensions
    for line in stdout.lines().skip(1) {
        println!("{}", strip_gpg_extension(line));
    }

    Ok(())
}

/// Strip .gpg extension from tree output while preserving ANSI color codes.
/// Equivalent to: sed -E 's/\.gpg(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'
fn strip_gpg_extension(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Check if we're at ".gpg"
        if i + 4 <= len && &bytes[i..i + 4] == b".gpg" {
            // Check what follows: optional ANSI escape, then " ->" or end
            let mut j = i + 4;

            // Capture optional ANSI escape sequence
            let ansi_start = j;
            if j < len && bytes[j] == 0x1b {
                // Skip \x1B[...m
                j += 1;
                if j < len && bytes[j] == b'[' {
                    j += 1;
                    while j < len && bytes[j] != b'm' {
                        j += 1;
                    }
                    if j < len {
                        j += 1; // skip 'm'
                    }
                }
            }
            let ansi_seq = &line[ansi_start..j];

            // Check if followed by " ->" or end of line
            if j >= len || (j + 3 <= len && &bytes[j..j + 3] == b" ->") {
                // Strip the .gpg but keep the ANSI escape and what follows
                result.push_str(ansi_seq);
                i = j;
                continue;
            }
        }

        result.push(bytes[i] as char);
        i += 1;
    }

    result
}
