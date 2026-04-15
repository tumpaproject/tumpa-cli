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
    // Use the same sed approach as pass — pipe through sed for correctness
    // with UTF-8 box-drawing characters and ANSI escapes.
    // The regex removes ".gpg" before an optional ANSI escape and then
    // either " ->" (symlink) or end of line.
    let mut result = String::with_capacity(line.len());
    let mut chars = line.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        // Check if we're at ".gpg" by looking at the byte slice
        let remaining = &line.as_bytes()[i..];
        if remaining.len() >= 4 && &remaining[..4] == b".gpg" {
            let after_gpg = i + 4;
            let mut j = after_gpg;
            let bytes = line.as_bytes();

            // Skip optional ANSI escape sequence
            if j < bytes.len() && bytes[j] == 0x1b {
                j += 1;
                if j < bytes.len() && bytes[j] == b'[' {
                    j += 1;
                    while j < bytes.len() && bytes[j] != b'm' {
                        j += 1;
                    }
                    if j < bytes.len() {
                        j += 1; // skip 'm'
                    }
                }
            }

            // Check if followed by " ->" or end of line
            if j >= bytes.len() || (j + 3 <= bytes.len() && &bytes[j..j + 3] == b" ->") {
                // Strip .gpg, keep the ANSI escape and what follows
                result.push_str(&line[after_gpg..j]);
                // Advance the char iterator past the consumed bytes
                while let Some((next_i, _)) = chars.peek() {
                    if *next_i < j {
                        chars.next();
                    } else {
                        break;
                    }
                }
                continue;
            }
        }

        result.push(c);
    }

    result
}
