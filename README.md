# tumpa-cli

A command-line tool for OpenPGP operations, SSH agent, and
password management, backed by the
[tumpa](https://github.com/tumpaproject/tumpa) keystore.

At a glance, tumpa-cli works as a drop-in for:

- **Git** — commit and tag signing + verification via `gpg.program`
- **pass** — [password-store](https://www.passwordstore.org/) replacement,
  either through a native `tpass` binary or by pointing `pass` at `tclig`
- **SSH** — OpenSSH-compatible agent serving keystore keys and OpenPGP
  card auth subkeys
- **Browserpass** — [Browserpass](https://github.com/browserpass/browserpass-extension)
  browser extension via the `gpg2` → `tclig` symlink
- **PassFF** — [PassFF](https://github.com/passff/passff) Firefox extension,
  same `gpg2` → `tclig` path
- **OpenPGP smart cards** — cards are tried first for sign / decrypt / SSH
  auth, with a software-key fallback from `~/.tumpa/keys.db`
- **[multiverse/bump-tag](https://github.com/SUNET/multiverse)** — emits
  the `[GNUPG:]` status lines bump-tag greps for

Three binaries are provided:

- **`tcli`** -- human-facing key management and SSH agent: import, export,
  search, fetch, describe, list, delete, card status, agent daemons
- **`tclig`** -- GnuPG drop-in for programs that invoke `gpg` (git signing,
  `pass`, anything with a `gpg.program` hook)
- **`tpass`** -- drop-in replacement for [password-store](https://www.passwordstore.org/)
  (`pass`), calling the tumpa keystore directly without GPG

All 3 try hardware OpenPGP cards first, then fall back to software keys
stored in `~/.tumpa/keys.db`.

For detailed usage instructions, see the
[Usage Guide](https://github.com/tumpaproject/tumpa-cli/blob/main/docs/usage.md).

## Upgrading from 0.1.x

As of 0.3.0, the GPG drop-in flags (`-bsau`, `--verify`, `-e`, `-d`,
`--list-keys --with-colons`, `--decrypt --list-only`, etc.) have
moved out of `tcli` into a new binary **`tclig`**. `tcli` is now the
human-facing key-management UI only.

If you configured git with `gpg.program = tcli`, or symlinked
`gpg2` to `tcli`, re-point them at `tclig`:

```
git config --global gpg.program tclig
ln -sf $(which tclig) ~/bin/gpg2
```

Everything you typed at the `tcli` prompt as a human (`tcli
--import`, `tcli --list-keys`, `tcli agent --ssh`, etc.) is
unchanged.

## Features

- **Git commit and tag signing** -- use as `gpg.program` in git config
- **Signature verification** -- verify commits and tags with keys from the tumpa keystore
- **Encryption / decryption** -- multi-recipient encryption, card-first decryption with software fallback
- **password-store (`pass`) support** -- works as a drop-in GPG replacement for `pass`
- **Browser extension support** -- [PassFF](https://github.com/passff/passff) and [Browserpass](https://github.com/browserpass/browserpass-extension) work via the `gpg2 -> tclig` symlink (ciphertext on stdin via `-`, `--debug` flag accepted)
- **`tpass`** -- native password-store replacement, no GPG dependency
- **OpenPGP card support** -- cards are tried first for signing, decryption, and SSH auth
- **Unified agent** -- caches passphrases for GPG operations + optional SSH agent
- **Key management** -- import, export, search, delete, and fetch keys via WKD
- **SSH agent** -- serve authentication subkeys from the keystore and connected cards
- **Passphrase handling** -- agent cache, pinentry, `TUMPA_PASSPHRASE` env var, or terminal prompt
- **Compatible with [multiverse/bump-tag](https://github.com/SUNET/multiverse)** -- produces the `[GNUPG:]` status lines git expects

## Quickstart

For the common case — a hardware OpenPGP card holding the signing
key, with just the **public** key imported into the keystore so
`tcli` knows which card-backed key to use.

**1. Install**

```
# macOS (Homebrew)
brew tap tumpaproject/tumpa-cli
brew install tumpa-cli

# Linux / from source
cargo install tumpa-cli
```

Linux also needs PC/SC libraries for card support — see
[System dependencies](#system-dependencies) below.

**2. Import the public key matching your card**

```
tcli --import my-public-key.asc
```

The secret bits live on the card; the keystore only needs the public
key so `tcli` can resolve the fingerprint and route signing /
decryption to the card.

**3. Verify the key and the card**

```
tcli --info <FINGERPRINT>     # details for the imported key
tcli --card-status            # connected cards, serial, PIN retries
```

**4. Configure git**

```
git config --global gpg.program tclig
git config --global user.signingkey <FINGERPRINT>
git config --global commit.gpgsign true
```

`tclig` (not `tcli`) is the GPG drop-in that git talks to.

**5. Start the agent at login**

**macOS (Homebrew)**:

```
brew services start tumpa-cli
```

Then add to `~/.zshrc` so SSH clients find the agent:

```bash
export SSH_AUTH_SOCK="$HOME/.tumpa/tcli-ssh.sock"
```

**Linux (systemd user service)** — see
[`contrib/systemd/README.md`](contrib/systemd/README.md) for the
ready-made unit files. The one-liner for the common case is:

```
systemctl --user enable --now tumpa-agent.service
```

Point your shell at the SSH socket via an `environment.d` drop-in
(systemd reads this into every user session):

```bash
mkdir -p ~/.config/environment.d
echo 'SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/tcli-ssh.sock' \
    > ~/.config/environment.d/tumpa-ssh-agent.conf
```

## Installation

### From source

```
cargo install tumpa-cli
```

Three binaries are installed to `~/.cargo/bin/`: `tcli`, `tclig`, and `tpass`.

### Homebrew

```
brew tap tumpaproject/tumpa-cli
brew install tumpa-cli
```

### System dependencies

On Linux, card support requires PC/SC libraries:

- **Debian/Ubuntu**: `sudo apt install pkg-config libpcsclite-dev pcscd`
- **Fedora/RHEL**: `sudo dnf install pkg-config pcsc-lite-devel pcsc-lite`
- **Arch**: `sudo pacman -S pkg-config pcsclite`

The `pcscd` service must be running: `sudo systemctl start pcscd.socket`

On macOS, the PC/SC framework is built in -- no extra packages needed.

## Setup

### Import your key

The first step is importing your OpenPGP key. The keystore directory
(`~/.tumpa/`) and database are created automatically on first use:

```
tcli --import my-secret-key.asc
```

Already have keys in GnuPG? Import the whole keyring in one shot —
both process substitution and stdin work, and multi-key streams
are split into individual keys:

```
tcli --import <(gpg --export)          # all public keys from gpg
gpg --export | tcli --import -         # same via a pipe
gpg --export-secret-keys | tcli --import -
```

Verify it was imported:

```
tcli --list-keys
```

If you don't have a key yet, generate one with
[wecanencrypt](https://github.com/kushaldas/wecanencrypt),
[GnuPG](https://gnupg.org/), or the
[tumpa](https://github.com/tumpaproject/tumpa) desktop application,
then import it.

### Shell completions

```bash
# Bash
tcli --completions bash > ~/.local/share/bash-completion/completions/tcli
tpass --completions bash > ~/.local/share/bash-completion/completions/tpass

# Zsh
mkdir -p ~/.zfunc
tcli --completions zsh > ~/.zfunc/_tcli
tpass --completions zsh > ~/.zfunc/_tpass

# Add to .zshrc:
# fpath=(~/.zfunc $fpath)
# autoload -Uz compinit
# compinit

# Fish
tcli --completions fish > ~/.config/fish/completions/tcli.fish
tpass --completions fish > ~/.config/fish/completions/tpass.fish
```

### Git

Configure git to use `tclig` for signing (it's the GPG drop-in; `tcli`
is the human-facing key manager and doesn't accept `gpg` flags):

```
git config --global gpg.program tclig
git config --global user.signingkey <FINGERPRINT>
git config --global commit.gpgsign true
```

### tpass (recommended)

Use `tpass` directly -- no GPG symlinking needed:

```
tpass init <FINGERPRINT>
tpass insert email/work
tpass show email/work
tpass -c email/work            # copy to clipboard
tpass generate sites/github 20
tpass edit email/work
tpass grep admin
```

`tpass` is fully compatible with `pass` -- they share the same store
format (`~/.password-store/`). See the
[Usage Guide](https://github.com/tumpaproject/tumpa-cli/blob/main/docs/usage.md#tpass--native-password-store)
for full documentation.

### password-store (`pass`) via tclig

Alternatively, use the original `pass` with `tclig` as the GPG backend:

```
mkdir -p ~/bin
ln -s $(which tclig) ~/bin/gpg2
export PATH="$HOME/bin:$PATH"
pass init <FINGERPRINT>
```

### Finding your key fingerprint

```
tcli --list-keys
```

Keys are managed through the [tumpa](https://github.com/tumpaproject/tumpa)
desktop application and stored in `~/.tumpa/keys.db`.

### Optional: run the agent at login

On Linux, ship-ready systemd **user** units are in
[`contrib/systemd/`](contrib/systemd/). Pick one (combined GPG+SSH,
GPG-only, or SSH-only) — they are mutually exclusive via
`Conflicts=`, so `systemctl --user enable --now tumpa-agent.service`
is the one-liner for the common case. Full walkthrough and the
`SSH_AUTH_SOCK` wiring are covered under
[Agent → Starting the agent automatically](#starting-the-agent-automatically)
below.

## Usage

### Signing

`tclig` is normally invoked by git, not directly. When git runs
`gpg.program --detach-sign ...`, `tclig` handles it transparently.

If a hardware OpenPGP card is connected and holds the signing key,
`tclig` uses the card. Otherwise it uses the software key from the
tumpa keystore.

### Verification

Git invokes `tclig --verify <sigfile> -` automatically for commands
like `git verify-commit`, `git verify-tag`, and `git log --show-signature`.

### Encryption

```
echo "secret" | tclig -e -r <FINGERPRINT> -o output.gpg
tclig -e -r <FP1> -r <FP2> -o output.gpg input.txt
```

Multiple recipients are supported. Any recipient can decrypt.

### Decryption

```
tclig -d output.gpg             # decrypt to stdout
tclig -d -o plaintext.txt file.gpg  # decrypt to file
```

The secret key is auto-detected from the encrypted message.
Decrypted output files are created with `0600` permissions.

### Passphrase / PIN entry

Both `tcli` and `tclig` acquire passphrases in this order:

1. **Agent cache** -- if `tcli agent` is running, cached passphrases
   are returned without prompting
2. **`TUMPA_PASSPHRASE` environment variable** -- useful for scripting and CI
3. **`pinentry` program** -- same mechanism GnuPG uses
4. **Terminal prompt** -- fallback

For card operations, the PIN is requested the same way.

### Key management

```
tcli --import mykey.asc              # import from file
tcli --import /path/to/keys/ -r      # import from directory (recursive)
tcli --import <(gpg --export)        # migrate from gpg in one go
gpg --export | tcli --import -       # or read keyring bytes from stdin
tcli --export <FP> -o key.asc        # export (armored)
tcli --info <FP>                     # detailed info for a keystore key
tcli --desc mykey.asc                # detailed info for a key file (no import)
tcli --search "Kushal"               # search by name
tcli --search --email user@example.com  # search by email
tcli --fetch user@example.com        # fetch via WKD
tcli --fetch user@example.com --dry-run  # preview without importing
tcli --delete <FP>                   # delete a key
```

### Listing keys

```
tcli --list-keys                     # human-readable
tcli --list-keys --with-colons       # GnuPG colon format
tcli --list-secret-keys --with-colons
```

### Smart card status

```
tcli --card-status
```

Shows details of connected OpenPGP cards (manufacturer, serial,
key fingerprints, PIN retry counters), similar to `gpg --card-status`.

### Custom keystore path

```
tcli --keystore /path/to/keys.db --list-keys
```

Or set `TUMPA_KEYSTORE` environment variable.

## Agent

`tcli agent` runs a daemon that caches passphrases for GPG operations
(signing, decryption) and optionally serves as an SSH agent.

### GPG passphrase caching

```
tcli agent
```

This eliminates repeated passphrase prompts. When git calls `tcli` for
signing, or `tpass` decrypts a password, the agent provides the cached
passphrase instead of prompting again. The cache expires after 30
minutes by default.

### GPG + SSH agent

```
tcli agent --ssh
tcli agent --ssh -H unix:///tmp/tcli.sock   # custom SSH socket
tcli agent --cache-ttl 3600                 # custom TTL (1 hour)
```

### Starting the agent automatically

#### Via homebrew

```
brew services start tumpa-cli
```

Add to `~/.zshrc`:

```bash
export SSH_AUTH_SOCK="$HOME/.tumpa/tcli-ssh.sock"
```

**Linux (systemd user service)** -- copy the ready-made units from
`contrib/systemd/` and enable one:

```bash
mkdir -p ~/.config/systemd/user
cp contrib/systemd/tumpa-*.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tumpa-agent.service    # GPG + SSH
# or
systemctl --user enable --now tumpa-gpg-agent.service   # GPG only
# or
systemctl --user enable --now tumpa-ssh-agent.service   # SSH only
```

Point your shell at the SSH socket via an
`environment.d` drop-in (systemd reads this into every user session):

```bash
mkdir -p ~/.config/environment.d
echo 'SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/tcli-ssh.sock' \
    > ~/.config/environment.d/tumpa-ssh-agent.conf
```

See [`contrib/systemd/README.md`](contrib/systemd/README.md) for
customisation (binary path, environment overrides, troubleshooting)
and [`docs/adr/0004-systemd-user-service.md`](docs/adr/0004-systemd-user-service.md)
for the design rationale.

### Without agent

Everything works without the agent -- you just get prompted every time.
The agent is purely additive.

### Querying socket paths

```
tcli --show-socket         # GPG agent socket (~/.tumpa/agent.sock)
tcli --show-socket ssh     # SSH agent socket (/run/user/<UID>/tcli-ssh.sock)
```

Useful for scripting:

```bash
export SSH_AUTH_SOCK=$(tcli --show-socket ssh)
```

### How it works

- Passphrases are cached in memory with a configurable TTL (default 30 min)
- SSH authentication keys from the keystore and connected cards are served
- Ed25519, ECDSA (P-256, P-384, P-521), and RSA keys are supported
- Card-based keys are listed if the card's auth key fingerprint is in the keystore
- The agent socket (`~/.tumpa/agent.sock`) is created with 0600 permissions

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

```
just test-all
```

Or run individual test suites:

```
just test             # tpass integration tests (33+ tests)
just test-compat      # tpass <-> pass cross-compatibility
just test-pass        # tcli + pass integration
just test-keystore    # key management (import/export/info/delete/search/fetch)
```

All tests require `TUMPA_PASSPHRASE` set and a secret key in `~/.tumpa/keys.db`.

## License

GPL-3.0-or-later
