# tumpa-cli

A command-line tool for OpenPGP operations, SSH agent, and
password management, backed by the
[tumpa](https://github.com/tumpaproject/tumpa) keystore.

The binary is called `tcli`. It acts as a drop-in replacement for GnuPG
in git and [password-store](https://www.passwordstore.org/) workflows,
and can also run as an SSH agent. It tries hardware OpenPGP cards first,
then falls back to software keys stored in `~/.tumpa/keys.db`.

## Features

- **Git commit and tag signing** -- use as `gpg.program` in git config
- **Signature verification** -- verify commits and tags with keys from the tumpa keystore
- **Encryption / decryption** -- multi-recipient encryption, auto-detect secret key for decryption
- **password-store (`pass`) support** -- works as a drop-in GPG replacement for `pass`
- **OpenPGP card support** -- cards are tried first, software keys as fallback
- **SSH agent** -- serve authentication subkeys from the keystore and connected cards
- **Passphrase handling** -- pinentry program, `TUMPA_PASSPHRASE` env var, or terminal prompt
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

### Git

Configure git to use `tcli` for signing:

```
git config --global gpg.program tcli
git config --global user.signingkey <FINGERPRINT>
git config --global commit.gpgsign true
```

### password-store (`pass`)

Symlink or alias `tcli` as `gpg`/`gpg2` so `pass` finds it:

```
mkdir -p ~/bin
ln -s $(which tcli) ~/bin/gpg2
export PATH="$HOME/bin:$PATH"
pass init <FINGERPRINT>
```

Or in your shell profile:

```
alias gpg2=tcli
```

Then use `pass` normally:

```
pass insert email/work        # encrypt a password
pass email/work               # decrypt and display
pass generate sites/github 20 # generate a random password
pass edit email/work           # decrypt, edit, reencrypt
```

### Finding your key fingerprint

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

### Encryption

```
echo "secret" | tcli -e -r <FINGERPRINT> -o output.gpg
tcli -e -r <FP1> -r <FP2> -o output.gpg input.txt
```

Multiple recipients are supported. Any recipient can decrypt.

### Decryption

```
tcli -d output.gpg             # decrypt to stdout
tcli -d -o plaintext.txt file.gpg  # decrypt to file
```

The secret key is auto-detected from the encrypted message.
Decrypted output files are created with `0600` permissions.

### Passphrase / PIN entry

`tcli` acquires passphrases in this order:

1. `TUMPA_PASSPHRASE` environment variable (useful for scripting and CI)
2. `pinentry` program (same mechanism GnuPG uses)
3. Terminal prompt (fallback)

For card operations, the PIN is requested the same way.

### Listing keys

```
tcli --list-keys                     # human-readable
tcli --list-keys --with-colons       # GnuPG colon format
tcli --list-secret-keys --with-colons
```

### Custom keystore path

```
tcli --keystore /path/to/keys.db --list-keys
```

Or set `TUMPA_KEYSTORE` environment variable.

## SSH agent

`tcli` can run as an SSH agent, serving authentication subkeys from the
tumpa keystore and any connected OpenPGP cards.

### Starting the agent

```
tcli ssh-agent -H unix:///tmp/tcli.sock
```

This prints the `SSH_AUTH_SOCK` export line. In another terminal:

```
export SSH_AUTH_SOCK=/tmp/tcli.sock
ssh-add -L    # list available keys
ssh user@host # authenticate using a key from the keystore
```

### How it works

- On `ssh-add -L`, the agent returns all authentication-capable subkeys
  from the keystore, converted to SSH public key format.
- On SSH login, the agent unlocks the matching secret key using pinentry
  (the passphrase is cached in memory for the agent's lifetime).
- Ed25519, ECDSA (P-256, P-384, P-521), and RSA software keys are all
  supported for signing.
- Card-based keys are also listed if the card's auth key fingerprint
  is in the keystore.

## Supported key types

### GPG operations (signing, verification, encryption, decryption)

All cipher suites supported by the `wecanencrypt` library work:

| Cipher suite | Signing algorithm | Notes |
|---|---|---|
| Cv25519 (default) | EdDSA (Ed25519) | Legacy v4 format, widely compatible |
| Cv25519Modern | Ed25519 | RFC 9580 native format |
| RSA 2048 | RSA | |
| RSA 4096 | RSA | |
| NIST P-256 | ECDSA | |
| NIST P-384 | ECDSA | |
| NIST P-521 | ECDSA | |

When a hardware OpenPGP card is connected and holds the signing key,
the card performs the operation regardless of algorithm.

### SSH agent

The agent serves authentication subkeys as SSH identities:

| OpenPGP algorithm | SSH key type | Software signing |
|---|---|---|
| Ed25519 | `ssh-ed25519` | Supported |
| ECDSA P-256 | `ecdsa-sha2-nistp256` | Supported |
| ECDSA P-384 | `ecdsa-sha2-nistp384` | Supported |
| ECDSA P-521 | `ecdsa-sha2-nistp521` | Supported |
| RSA 2048/4096 | `ssh-rsa` | Supported |

Card-based SSH authentication works for all algorithms the card
hardware supports.

See [ADR 0001](docs/adr/0001-ssh-agent-support.md) for the full
architectural rationale and algorithm details.

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

## Testing

Run the `pass` integration tests:

```
TUMPA_PASSPHRASE="your-passphrase" ./tests/test_pass.sh [FINGERPRINT]
```

This tests init, insert, show, generate, overwrite, nested paths,
remove, reinit, and GPG-compatible key listing output.

## License

GPL-3.0-or-later
