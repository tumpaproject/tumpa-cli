use anyhow::Result;

use crate::util::{config, tree};

/// `tpass find pass-names...`
pub fn cmd_find(terms: &[String]) -> Result<()> {
    if terms.is_empty() {
        anyhow::bail!("Usage: tpass find pass-names...");
    }

    let prefix = config::store_dir();

    // Print search terms (comma-separated)
    println!("Search Terms: {}", terms.join(","));

    tree::show_tree_find(&prefix, terms)?;

    Ok(())
}
