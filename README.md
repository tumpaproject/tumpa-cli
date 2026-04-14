# tumpa-cli

A command-line tool for OpenPGP operations and SSH agent functionality,
backed by the [tumpa](https://github.com/tumpaproject/tumpa) keystore.

The binary is called `tcli`. It acts as a drop-in replacement for GnuPG
in git workflows and can also run as an SSH agent. It tries hardware
OpenPGP cards first, then falls back to software keys stored in
`~/.tumpa/keys.db`.

## Features

- **Git commit and tag signing** -- use as `gpg.program` in git config
- **Signature verification** -- verify commits and tags with keys from the tumpa keystore
- **OpenPGP card support** -- cards are tried first, software keys as fallback
- **Passphrase handling** -- pinentry program, `TUMPA_PASSPHRASE` env var, or terminal prompt
- **SSH agent** -- serve authentication subkeys from the keystore and connected cards *(planned)*
- **Compatible with [multiverse/bump-tag](https://github.com/SUNET/multiverse)** -- produces the `[GNUPG:]` status lines git expects

## Installation

### From source

```
cargo install tumpa-cli
```

The binary `tcli` will be installed to `~/.cargo/bin/`.

### System dependencies

On Linux, card support requires PC/SC libraries:

- **Debian/Ubuntu**: `sudo apt install pkg-config libpcsclite-dev pcscd`
- **Fedora/RHEL**: `sudo dnf install pkg-config pcsc-lite-devel pcsc-lite`
- **Arch**: `sudo pacman -S pkg-config pcsclite`

The `pcscd` service must be running: `sudo systemctl start pcscd.socket`

On macOS, the PC/SC framework is built in -- no extra packages needed.

## Setup

Configure git to use `tcli` for signing:

```
git config --global gpg.program tcli
git config --global user.signingkey <FINGERPRINT>
git config --global commit.gpgsign true
```

Find your signing key fingerprint:

```
tcli --list-keys
```

Keys are managed through the [tumpa](https://github.com/tumpaproject/tumpa)
desktop application and stored in `~/.tumpa/keys.db`.

## Usage

### Signing

`tcli` is normally invoked by git, not directly. When git runs
`gpg.program --detach-sign ...`, `tcli` handles it transparently.

If a hardware OpenPGP card is connected and holds the signing key,
`tcli` uses the card. Otherwise it uses the software key from the
tumpa keystore.

### Verification

Git invokes `tcli --verify <sigfile> -` automatically for commands
like `git verify-commit`, `git verify-tag`, and `git log --show-signature`.

### Passphrase / PIN entry

`tcli` acquires passphrases in this order:

1. `TUMPA_PASSPHRASE` environment variable (useful for scripting)
2. `pinentry` program (same mechanism GnuPG uses)
3. Terminal prompt (fallback)

For card operations, the PIN is requested the same way.

### Listing keys

```
tcli --list-keys
```

Shows all keys in the tumpa keystore with their fingerprints and user IDs.

### Custom keystore path

```
tcli --keystore /path/to/keys.db --list-keys
```

Or set `TUMPA_KEYSTORE` environment variable.

## How it works with bump-tag

[bump-tag](https://github.com/SUNET/multiverse) verifies that all commits
and tags are signed before creating a new signed tag. It relies on:

- `git pull --verify-signatures`
- `git verify-tag` / `git verify-commit`
- `git log --pretty="format:%G?"` expecting `G` for every commit
- `git tag -s` for creating the new tag

`tcli` produces all the `[GNUPG:]` status lines these commands require
(`SIG_CREATED`, `GOODSIG`, `VALIDSIG`, `TRUST_FULLY`), so bump-tag
works without changes.

## License

GPL-3.0-or-later
