use std::path::PathBuf;

use dirs;

pub fn store_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PASSWORD_STORE_DIR") {
        PathBuf::from(dir)
    } else {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".password-store")
    }
}

pub fn clip_time() -> u64 {
    std::env::var("PASSWORD_STORE_CLIP_TIME")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(45)
}

pub fn generated_length() -> usize {
    std::env::var("PASSWORD_STORE_GENERATED_LENGTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(25)
}

pub fn character_set() -> String {
    std::env::var("PASSWORD_STORE_CHARACTER_SET")
        .unwrap_or_else(|_| "[:punct:][:alnum:]".to_string())
}

pub fn character_set_no_symbols() -> String {
    std::env::var("PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS")
        .unwrap_or_else(|_| "[:alnum:]".to_string())
}

pub fn x_selection() -> String {
    std::env::var("PASSWORD_STORE_X_SELECTION").unwrap_or_else(|_| "clipboard".to_string())
}

pub fn signing_key() -> Option<Vec<String>> {
    std::env::var("PASSWORD_STORE_SIGNING_KEY")
        .ok()
        .map(|v| v.split_whitespace().map(|s| s.to_string()).collect())
}

pub fn store_key() -> Option<Vec<String>> {
    std::env::var("PASSWORD_STORE_KEY")
        .ok()
        .map(|v| v.split_whitespace().map(|s| s.to_string()).collect())
}

pub fn extensions_enabled() -> bool {
    std::env::var("PASSWORD_STORE_ENABLE_EXTENSIONS")
        .map(|v| v == "true")
        .unwrap_or(false)
}

pub fn extensions_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PASSWORD_STORE_EXTENSIONS_DIR") {
        PathBuf::from(dir)
    } else {
        store_dir().join(".extensions")
    }
}

pub fn umask_value() -> u32 {
    std::env::var("PASSWORD_STORE_UMASK")
        .ok()
        .and_then(|v| u32::from_str_radix(&v, 8).ok())
        .unwrap_or(0o077)
}

pub fn editor() -> String {
    std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string())
}
