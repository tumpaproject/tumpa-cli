mod cli;
mod commands;
mod util;

use clap::Parser;

use cli::{Args, Command};

fn main() {
    env_logger::builder().format_timestamp_micros().init();

    // Set umask
    let umask = util::config::umask_value();
    unsafe {
        libc::umask(umask as libc::mode_t);
    }

    // Unset GIT_* environment variables that could interfere
    // (matches pass's behavior at line 22-23)
    for var in &[
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_NAMESPACE",
        "GIT_INDEX_FILE",
        "GIT_INDEX_VERSION",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
    ] {
        std::env::remove_var(var);
    }

    // Set GIT_CEILING_DIRECTORIES
    let prefix = util::config::store_dir();
    if let Some(parent) = prefix.parent() {
        std::env::set_var("GIT_CEILING_DIRECTORIES", parent);
    }

    let args = Args::parse();

    let result = match args.command {
        Some(Command::Init { path, gpg_ids }) => {
            commands::init::cmd_init(path.as_deref(), &gpg_ids)
        }
        Some(Command::Ls { subfolder }) => {
            commands::show::cmd_show(subfolder.as_deref(), None, None)
        }
        Some(Command::Show {
            clip,
            qrcode,
            pass_name,
        }) => {
            let clip_line = clip.map(|c| c.unwrap_or(1));
            let qrcode_line = qrcode.map(|q| q.unwrap_or(1));
            commands::show::cmd_show(pass_name.as_deref(), clip_line, qrcode_line)
        }
        Some(Command::Find { pass_names }) => commands::find::cmd_find(&pass_names),
        Some(Command::Grep { args }) => commands::grep::cmd_grep(&args),
        Some(Command::Insert {
            multiline,
            echo,
            force,
            pass_name,
        }) => commands::insert::cmd_insert(&pass_name, multiline, echo, force),
        Some(Command::Edit { pass_name }) => commands::edit::cmd_edit(&pass_name),
        Some(Command::Generate {
            no_symbols,
            clip,
            qrcode,
            in_place,
            force,
            pass_name,
            pass_length,
        }) => commands::generate::cmd_generate(
            &pass_name,
            no_symbols,
            clip,
            qrcode,
            in_place,
            force,
            pass_length,
        ),
        Some(Command::Rm {
            recursive,
            force,
            pass_name,
        }) => commands::rm::cmd_rm(&pass_name, recursive, force),
        Some(Command::Mv {
            force,
            old_path,
            new_path,
        }) => commands::mv::cmd_mv(&old_path, &new_path, force),
        Some(Command::Cp {
            force,
            old_path,
            new_path,
        }) => commands::cp::cmd_cp(&old_path, &new_path, force),
        Some(Command::Git { args }) => commands::git::cmd_git(&args),
        Some(Command::Version) => {
            print_version();
            Ok(())
        }
        None => {
            // Default: try extension, then show, then help
            if args.args.is_empty() {
                // No args at all — show root listing or help if store doesn't exist
                let prefix = util::config::store_dir();
                if !prefix.exists() {
                    print_usage();
                    return;
                }
                commands::show::cmd_show(None, None, None)
            } else {
                // Try as extension first, then as show
                let first = &args.args[0];
                if try_extension(first, &args.args[1..]) {
                    Ok(())
                } else {
                    // Treat as show
                    commands::show::cmd_show(Some(first), None, None)
                }
            }
        }
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn print_version() {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "============================================\n\
         = tpass: password store via tumpa keystore  =\n\
         =                                          =\n\
         =                  v{}                  =\n\
         =                                          =\n\
         =       backed by tumpa keystore           =\n\
         ============================================",
        version
    );
}

fn print_usage() {
    print_version();
    let clip_time = util::config::clip_time();
    let gen_length = util::config::generated_length();
    println!(
        "\n\
Usage:\n\
    tpass init [--path=subfolder,-p subfolder] gpg-id...\n\
        Initialize new password storage and use gpg-id for encryption.\n\
        Selectively reencrypt existing passwords using new gpg-id.\n\
    tpass [ls] [subfolder]\n\
        List passwords.\n\
    tpass find pass-names...\n\
        List passwords that match pass-names.\n\
    tpass [show] [--clip[=line-number],-c[line-number]] pass-name\n\
        Show existing password and optionally put it on the clipboard.\n\
        If put on the clipboard, it will be cleared in {clip_time} seconds.\n\
    tpass grep [GREPOPTIONS] search-string\n\
        Search for password files containing search-string when decrypted.\n\
    tpass insert [--echo,-e | --multiline,-m] [--force,-f] pass-name\n\
        Insert new password. Optionally, echo the password back to the console\n\
        during entry. Or, optionally, the entry may be multiline. Prompt before\n\
        overwriting existing password unless forced.\n\
    tpass edit pass-name\n\
        Insert a new password or edit an existing password using ${{EDITOR:-vi}}.\n\
    tpass generate [--no-symbols,-n] [--clip,-c] [--in-place,-i | --force,-f] pass-name [pass-length]\n\
        Generate a new password of pass-length (or {gen_length} if unspecified) with optionally no symbols.\n\
        Optionally put it on the clipboard and clear board after {clip_time} seconds.\n\
        Prompt before overwriting existing password unless forced.\n\
        Optionally replace only the first line of an existing file with a new password.\n\
    tpass rm [--recursive,-r] [--force,-f] pass-name\n\
        Remove existing password or directory, optionally forcefully.\n\
    tpass mv [--force,-f] old-path new-path\n\
        Renames or moves old-path to new-path, optionally forcefully, selectively reencrypting.\n\
    tpass cp [--force,-f] old-path new-path\n\
        Copies old-path to new-path, optionally forcefully, selectively reencrypting.\n\
    tpass git git-command-args...\n\
        If the password store is a git repository, execute a git command\n\
        specified by git-command-args.\n\
    tpass help\n\
        Show this text.\n\
    tpass version\n\
        Show version information.\n"
    );
}

/// Try to run a command as an extension.
/// Returns true if extension was found and executed.
fn try_extension(command: &str, args: &[String]) -> bool {
    // Check sneaky paths
    if commands::init::check_sneaky_paths(&[command]).is_err() {
        return false;
    }

    let extensions_dir = util::config::extensions_dir();
    let extensions_enabled = util::config::extensions_enabled();

    // Check user extension
    if extensions_enabled {
        let ext_path = extensions_dir.join(format!("{}.bash", command));
        if ext_path.is_file() && is_executable(&ext_path) {
            return run_extension(&ext_path, args);
        }
    }

    // No system extension dir in tpass for now
    false
}

fn is_executable(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            return metadata.permissions().mode() & 0o111 != 0;
        }
    }
    false
}

fn run_extension(path: &std::path::Path, args: &[String]) -> bool {
    // Export environment variables that extensions expect
    let prefix = util::config::store_dir();
    std::env::set_var("PREFIX", &prefix);
    std::env::set_var("PASSWORD_STORE_DIR", &prefix);
    std::env::set_var("EXTENSIONS", util::config::extensions_dir());
    std::env::set_var("X_SELECTION", util::config::x_selection());
    std::env::set_var("CLIP_TIME", util::config::clip_time().to_string());
    std::env::set_var("GENERATED_LENGTH", util::config::generated_length().to_string());
    std::env::set_var("CHARACTER_SET", util::config::character_set());
    std::env::set_var(
        "CHARACTER_SET_NO_SYMBOLS",
        util::config::character_set_no_symbols(),
    );

    // Source the extension script via bash
    let mut cmd_args = vec![path.to_string_lossy().to_string()];
    cmd_args.extend(args.iter().cloned());

    let status = std::process::Command::new("bash")
        .args(&cmd_args)
        .status();

    match status {
        Ok(s) => {
            if !s.success() {
                std::process::exit(s.code().unwrap_or(1));
            }
            true
        }
        Err(_) => false,
    }
}
