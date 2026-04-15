use anyhow::Result;

use crate::util::{config, git};

/// `tpass git git-command-args...`
pub fn cmd_git(args: &[String]) -> Result<()> {
    let prefix = config::store_dir();
    let git_dir = git::find_git_dir(&prefix.join("."), &prefix);

    if args.first().map(|s| s.as_str()) == Some("init") {
        // Special case: git init
        let status = std::process::Command::new("git")
            .args(["-C", &prefix.to_string_lossy()])
            .args(args)
            .status()?;

        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }

        // Add current contents
        let _ = git::git_add_file(
            &prefix,
            &prefix,
            "Add current contents of password store.",
        );

        // Create .gitattributes
        let gitattributes = prefix.join(".gitattributes");
        std::fs::write(&gitattributes, "*.gpg diff=gpg\n")?;
        let _ = git::git_add_file(
            &prefix,
            &gitattributes,
            "Configure git repository for gpg file diff.",
        );

        // Configure diff.gpg
        let _ = std::process::Command::new("git")
            .args([
                "-C",
                &prefix.to_string_lossy(),
                "config",
                "--local",
                "diff.gpg.binary",
                "true",
            ])
            .status();

        let _ = std::process::Command::new("git")
            .args([
                "-C",
                &prefix.to_string_lossy(),
                "config",
                "--local",
                "diff.gpg.textconv",
                "tcli -d",
            ])
            .status();
    } else if let Some(ref gd) = git_dir {
        git::git_run(gd, args)?;
    } else {
        anyhow::bail!(
            "Error: the password store is not a git repository. Try \"tpass git init\"."
        );
    }

    Ok(())
}
