# Usage Guide

This guide covers installation, setup, and day-to-day usage of `tcli`
for git signing, password management with `pass`, SSH authentication,
and direct encryption/decryption.

## Table of contents

- [Installation](#installation)
  - [Shell completions](#shell-completions)
- [Getting started](#getting-started)
- [Key management](#key-management)
- [Git signing](#git-signing)
- [Password store (pass)](#password-store-pass)
- [tpass — native password store](#tpass--native-password-store)
- [Encryption and decryption](#encryption-and-decryption)
- [Agent (passphrase cache + SSH)](#agent-passphrase-cache--ssh)
- [Hardware OpenPGP cards](#hardware-openpgp-cards)
- [Passphrase handling](#passphrase-handling)
- [Environment variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

---

## Installation

### From crates.io

```
cargo install tumpa-cli
```


Three binaries are installed to `~/.cargo/bin/`:

- **`tcli`** -- human-facing key management and SSH agent: import, export,
  search, fetch, describe, list, delete, card status, agent daemons
- **`tclig`** -- GnuPG drop-in for programs that invoke `gpg` (git signing,
  `pass`, anything with a `gpg.program` hook)
- **`tpass`** -- drop-in replacement for [password-store](https://www.passwordstore.org/)
  (`pass`), calling the tumpa keystore directly without GPG

All 3 try hardware OpenPGP cards first, then fall back to software keys
stored in `~/.tumpa/keys.db`.


Make sure `~/.cargo/bin/` is in your `PATH`.


### Homebrew

```
brew tap tumpaproject/tumpa-cli
brew install tumpa-cli
```


### From source

```
git clone https://github.com/tumpaproject/tumpa-cli
cd tumpa-cli
cargo build --release
cp target/release/tcli target/release/tpass ~/.local/bin/
```

### System dependencies

`tcli` uses PC/SC for hardware OpenPGP card communication. If you
don't use cards, you can skip this, but the build still requires the
development headers.

**Debian / Ubuntu:**

```
sudo apt install pkg-config libpcsclite-dev pcscd
sudo systemctl enable --now pcscd.socket
```

**Fedora / RHEL:**

```
sudo dnf install pkg-config pcsc-lite-devel pcsc-lite
sudo systemctl enable --now pcscd.socket
```

**Arch Linux:**

```
sudo pacman -S pkg-config pcsclite
sudo systemctl enable --now pcscd.socket
```

**macOS:**

No extra packages needed. The PC/SC framework (CryptoTokenKit) is
built in.

### Shell completions

Generate completions for your shell and source them:

```bash
# Bash
tcli --completions bash > ~/.local/share/bash-completion/completions/tcli
tpass --completions bash > ~/.local/share/bash-completion/completions/tpass

# Zsh (add ~/.zfunc to your fpath in .zshrc first)
tcli --completions zsh > ~/.zfunc/_tcli
tpass --completions zsh > ~/.zfunc/_tpass

# Fish
tcli --completions fish > ~/.config/fish/completions/tcli.fish
tpass --completions fish > ~/.config/fish/completions/tpass.fish
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

---

## Getting started

The first step after installation is importing your OpenPGP key. The
keystore directory (`~/.tumpa/`) and database file (`keys.db`) are
created automatically on first use — no manual setup needed.

### Import your public/secret key

```
tcli --import my-secret-key.asc
```

This imports both the secret key material and the public certificate.
If `~/.tumpa/keys.db` doesn't exist yet, it is created automatically.

### Migrate from GnuPG

If your keys already live in GnuPG, feed `gpg --export` (or
`gpg --export-secret-keys`) straight into `tcli --import`. The
stream can contain many keys concatenated — every key is imported
or merged:

```
tcli --import <(gpg --export)                # all public keys
tcli --import <(gpg --export-secret-keys)    # public + secret material
gpg --export | tcli --import -               # same via a pipe
gpg --export | tcli --import                 # no path = read stdin
```

The process-substitution form (`<(...)`) works because bash exposes
the pipe as `/dev/fd/N`, which `tcli` reads like any other file.
Each key inside the stream runs through the same merge-on-duplicate
flow as a single-file import — re-running the command later picks
up renewed expiries and new certifications instead of duplicating.

### Verify the import

```
$ tcli --list-keys
sec A85FF376759C994A8A1168D8D8219C8C43F6C5E1 Alice <alice@example.com>
```

Lines starting with `sec` indicate keys you own (have the secret key
for). The 40-character hex string is the fingerprint — you'll use it
for git signing, `pass init`, and encryption.

### Import contacts' public keys

```
tcli --import colleague-pubkey.asc
tcli --fetch colleague@example.com       # or fetch via WKD
```

These are stored as public-only certificates (shown as `pub` in
`tcli --list-keys`) and used as encryption recipients.

### Next steps

With your key imported, set up the workflows you need:

- [Git signing](#git-signing) — sign commits and tags
- [tpass](#tpass--native-password-store) — manage passwords
- [Agent](#agent-passphrase-cache--ssh) — cache passphrases and SSH auth

On Linux, consider installing the ready-made systemd **user** units
from [`contrib/systemd/`](../contrib/systemd/) once you start using
the agent — they start it at login and restart on crash. The
[Starting the agent automatically](#starting-the-agent-automatically)
section has the one-liner.

---

## Key management

`tcli` reads keys from the [tumpa](https://github.com/tumpaproject/tumpa)
keystore at `~/.tumpa/keys.db`. Keys can be managed from the command
line or through the tumpa desktop application.

### Importing keys

```
tcli --import mykey.asc
tcli --import /path/to/keys/ --recursive
tcli --import <(gpg --export)                # process substitution
gpg --export | tcli --import -               # stdin (explicit)
gpg --export | tcli --import                 # stdin (implicit)
```

Accepts armored and binary OpenPGP files. For directories, imports all
`.asc`, `.gpg`, `.pub`, `.key`, `.pgp` files.

A path of `-` (or no paths at all) reads a keyring from stdin. Any
input — file, directory entry, process substitution, or stdin — may
contain **multiple keys concatenated**, the shape `gpg --export`
produces. Every key in the stream is imported or merged; a malformed
key is reported and skipped without aborting the rest.

When importing a key that already exists in the keystore, `tcli` merges
the new data into the existing certificate instead of skipping it. This
picks up renewed expiry dates, new third-party certifications, updated
subkey bindings, and new user IDs. If the imported data is identical to
what's already stored, the key is reported as "Unchanged".

```
$ tcli --import updated_key.asc
Updated A85FF376759C994A... (Alice <alice@example.com>) — merged new signatures
```

See [ADR 0006](adr/0006-import-from-gpg-and-stdin.md) for the design
rationale behind multi-key and stdin support.

### Fetching keys via WKD

```
tcli --fetch user@example.com
tcli --fetch user@example.com --dry-run   # preview without importing
```

Looks up the key via Web Key Directory (WKD) and prompts to import.
With `--dry-run`, shows detailed key info without importing.

If the key already exists in the keystore, `tcli` offers to merge
updates from the WKD response. This is how you refresh a contact's
key after they renew their expiry or add new subkeys.

### Key information

```
tcli --info <FINGERPRINT>
```

Shows algorithm, capabilities, UIDs (primary first), subkeys with
full fingerprints, creation and expiry timestamps.

### Inspecting a key file before importing

```
tcli --desc mykey.asc
tcli --desc /path/to/key.pub
```

Renders the same detail view as `--info`, but reads directly from a
key file (armored or binary, public or secret) instead of the
keystore. Nothing is imported or written — useful for reviewing a
cert someone sent you before deciding to trust it.

The first line's leading marker is `sec` for a file that carries
secret key material, `pub` otherwise. Missing or unparseable files
return a non-zero exit code with a clear error.

### Searching keys

```
tcli --search "Kushal"                  # search by name (substring)
tcli --search --email user@example.com  # search by email (exact)
```

### Exporting keys

```
tcli --export <FINGERPRINT>                # armored to stdout
tcli --export <FINGERPRINT> -o key.asc     # armored to file
tcli --export <FINGERPRINT> --binary -o key.gpg  # binary format
```

### Deleting keys

```
tcli --delete <FINGERPRINT>       # prompts for confirmation
tcli --delete <FINGERPRINT> -f    # force, no prompt
```

### Listing keys

```
$ tcli --list-keys
pub A85FF376759C994A8A1168D8D8219C8C43F6C5E1 Kushal Das <kushal@fedoraproject.org>
sec 5794A58891584E513386AA6EF2F491FA8C62645C Fire Cat <cat@cat.se>
```

Lines starting with `sec` are keys you own (have the secret key for).
Lines starting with `pub` are other people's public keys.

### GnuPG-compatible listing

For scripts that parse GnuPG's colon-delimited output, use `tclig`
(the GPG drop-in binary — `tcli` is the human-facing UI and only
emits the condensed `sec/pub fingerprint uid` format):

```
tclig --list-keys --with-colons
tclig --list-keys --with-colons <FINGERPRINT>
tclig --list-secret-keys --with-colons
```

### Using a different keystore

```
tcli --keystore /path/to/other/keys.db --list-keys
```

Or set the environment variable:

```
export TUMPA_KEYSTORE=/path/to/other/keys.db
```

---

## Git signing

### One-time setup

Tell git to use `tclig` instead of `gpg`. `tclig` is the GPG drop-in
binary; the human-facing `tcli` does not accept `gpg` flags.

```
git config --global gpg.program tclig
```

Set your signing key (use the fingerprint from `tcli --list-keys`):

```
git config --global user.signingkey <FINGERPRINT>
```

Enable automatic commit signing:

```
git config --global commit.gpgsign true
```

### Signing commits

With `commit.gpgsign = true`, every commit is signed automatically:

```
git commit -m "my change"
```

To sign a single commit without the global setting:

```
git commit -S -m "signed commit"
```

### Signing tags

```
git tag -s -m "release v1.0" v1.0
```

### Verifying

```
git verify-commit HEAD
git verify-tag v1.0
git log --show-signature
```

The `%G?` format shows `G` for commits with a valid, trusted signature:

```
git log --pretty="format:%H %G?"
```

### How it works

When git calls `tclig` for signing, it:

1. Checks if a connected OpenPGP card holds the signing key
2. If yes, signs using the card (prompts for card PIN via pinentry)
3. If no card, signs using the software key from the keystore
   (prompts for passphrase via pinentry)

For verification, `tclig` looks up the signer's key in the keystore
by fingerprint or key ID extracted from the signature.

### bump-tag compatibility

[multiverse/bump-tag](https://github.com/SUNET/multiverse) works
without any changes. `tclig` produces the `[GNUPG:]` status lines
that git and bump-tag expect: `SIG_CREATED`, `GOODSIG`, `VALIDSIG`,
and `TRUST_FULLY`.

---

## Password store (pass)

[pass](https://www.passwordstore.org/) is the standard Unix password
manager. It calls `gpg` for all encryption and decryption. `tclig`
(the GPG drop-in binary) can replace `gpg` for `pass`.

### Setup

`pass` looks for `gpg2` (or `gpg`) in your `PATH`. The simplest
approach is to create a symlink:

```
mkdir -p ~/bin
ln -s $(which tclig) ~/bin/gpg2
```

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export PATH="$HOME/bin:$PATH"
```

Alternatively, use an alias (works for interactive use but not all
scripts):

```bash
alias gpg2=tclig
```

### Initializing the store

```
pass init <FINGERPRINT>
```

This creates `~/.password-store/` with a `.gpg-id` file containing
your key fingerprint. All passwords will be encrypted to this key.

For multiple recipients (e.g., a team):

```
pass init <FP1> <FP2> <FP3>
```

### Storing passwords

```
pass insert email/work
```

This prompts for the password (typed twice for confirmation). For
non-interactive or multiline input:

```
echo "mypassword" | pass insert -m email/work
```

### Retrieving passwords

```
pass email/work
```

Prints the decrypted password to stdout. `tclig` automatically finds
the right secret key and prompts for the passphrase via pinentry.

### Generating passwords

```
pass generate sites/github 20
```

Generates a 20-character random password, encrypts it, and displays it.

Without symbols:

```
pass generate -n sites/github 20
```

### Editing

```
pass edit email/work
```

Decrypts to a temp file, opens your `$EDITOR`, then reencrypts on save.

### Other operations

```
pass ls                   # tree view of all entries
pass find github          # search entry names
pass grep admin           # search entry contents
pass rm email/old         # delete an entry
pass mv email/old email/new  # rename
pass cp email/work email/backup  # copy
```

### Reencryption

When you change the keys in `.gpg-id` (via `pass init` with different
fingerprints), `pass` reencrypts all passwords to the new set of keys.
`tclig` supports the `--decrypt --list-only` and `--list-keys --with-colons`
commands that `pass` uses to detect which files need reencryption.

### Browser extensions

Browser extensions that speak to `pass` (via a native messaging host)
work against the `gpg2 -> tclig` symlink, too:

- **[PassFF](https://github.com/passff/passff)** — invokes gpg with
  `--debug`. `tclig` accepts and ignores this flag.
- **[Browserpass](https://github.com/browserpass/browserpass-extension)**
  — its native host (`browserpass-native`) reads the `.gpg` file
  itself and pipes the ciphertext to `gpg -d -`. `tclig` treats `-`
  as stdin, matching gpg's convention.

No configuration beyond the standard `gpg2 -> tclig` symlink is
needed for either extension.

---

## tpass — native password store

`tpass` is a drop-in replacement for `pass` (password-store) that calls
the tumpa keystore directly instead of shelling out to GPG. It supports
every `pass` command with identical flags, file formats, and environment
variables. Stores created by `tpass` are fully interchangeable with
`pass` (and vice versa).

### Installation

`tpass` is built alongside `tcli`:

```
cargo install tumpa-cli
```

This installs both `tcli` and `tpass` to `~/.cargo/bin/`.

### Initializing the store

```
tpass init <FINGERPRINT>
```

For multiple recipients:

```
tpass init <FP1> <FP2> <FP3>
```

Initialize a subfolder with different keys:

```
tpass init -p work <WORK_FP>
```

### Storing and retrieving passwords

```
# Insert (prompted, typed twice for confirmation)
tpass insert email/work

# Insert from stdin (multiline)
echo "mypassword" | tpass insert -m email/work

# Insert with echo (single line, visible)
tpass insert -e email/work

# Show a password
tpass show email/work

# Copy to clipboard (auto-clears after 45 seconds)
tpass show -c email/work

# Copy a specific line to clipboard
tpass show -c2 email/work

# Show as QR code
tpass show -q email/work
```

### Generating passwords

```
# Generate a 20-character password with symbols
tpass generate sites/github 20

# Without symbols (alphanumeric only)
tpass generate -n sites/github 20

# Copy generated password to clipboard
tpass generate -c sites/github 20

# Replace only the first line of an existing entry
tpass generate -i sites/github 20
```

### Listing and searching

```
# List all entries (tree view)
tpass ls

# List a subfolder
tpass ls email

# Search entry names
tpass find github

# Search decrypted contents
tpass grep admin
```

### Editing

```
tpass edit email/work
```

Decrypts to a secure temp file (`/dev/shm` if available), opens
`$EDITOR`, and reencrypts on save. The temp file is overwritten with
zeros before deletion.

### Moving, copying, removing

```
tpass mv email/old email/new
tpass cp email/work email/backup
tpass rm email/old
tpass rm -r email            # recursive
```

### Git integration

```
# Initialize git tracking
tpass git init

# All changes are auto-committed (insert, generate, edit, rm, mv, cp)

# Run any git command on the store
tpass git log
tpass git push
```

### Reencryption

When you change the keys with `tpass init`, all passwords under that
path are reencrypted to the new set of keys:

```
# Change keys for the entire store
tpass init <NEW_FP>

# Change keys for a subfolder only
tpass init -p team <FP1> <FP2>
```

### Clipboard

Clipboard support works on:

- **Wayland** — uses `wl-copy` / `wl-paste`
- **X11** — uses `xclip`
- **macOS** — uses `pbcopy` / `pbpaste`

The clipboard is automatically cleared after `PASSWORD_STORE_CLIP_TIME`
seconds (default: 45). The previous clipboard content is restored.

### Extensions

`tpass` supports `pass` extensions. Place executable `.bash` scripts in
`~/.password-store/.extensions/` and enable them:

```
export PASSWORD_STORE_ENABLE_EXTENSIONS=true
```

Then run:

```
tpass myextension arg1 arg2
```

### Environment variables

`tpass` respects all `pass` environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `PASSWORD_STORE_DIR` | Store directory | `~/.password-store` |
| `PASSWORD_STORE_KEY` | Override encryption key(s) | from `.gpg-id` |
| `PASSWORD_STORE_CLIP_TIME` | Clipboard clear timeout (seconds) | `45` |
| `PASSWORD_STORE_UMASK` | File creation mask | `077` |
| `PASSWORD_STORE_GENERATED_LENGTH` | Default password length | `25` |
| `PASSWORD_STORE_CHARACTER_SET` | Characters for generation | `[:punct:][:alnum:]` |
| `PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS` | Alphanumeric charset | `[:alnum:]` |
| `PASSWORD_STORE_X_SELECTION` | X11 clipboard selection | `clipboard` |
| `PASSWORD_STORE_ENABLE_EXTENSIONS` | Enable user extensions | (disabled) |
| `PASSWORD_STORE_EXTENSIONS_DIR` | Extensions directory | `$PREFIX/.extensions` |
| `PASSWORD_STORE_SIGNING_KEY` | GPG fingerprint(s) for `.gpg-id` signing | (disabled) |
| `EDITOR` | Editor for `tpass edit` | `vi` |

Plus the tumpa-specific variables (`TUMPA_KEYSTORE`, `TUMPA_PASSPHRASE`,
`PINENTRY_PROGRAM`) documented in the [Environment variables](#environment-variables)
section above.

### Differences from pass

`tpass` is fully compatible with `pass`, with these differences:

- **No GPG dependency** — `tpass` calls the tumpa keystore directly.
  No need to symlink `tclig` as `gpg2` or configure `gpg.program`.
- **Faster** — no process spawning overhead for GPG on each operation.
- **Single binary** — `tpass` handles everything; no shell script.
- **GPG groups not supported** — `pass` can expand GPG groups from
  `gpg.conf`. `tpass` treats all `.gpg-id` entries as literal key
  identifiers. Use full fingerprints instead.

### Migrating from pass

If you already have a password store set up with `pass` and `tclig` as
the GPG backend, switching to `tpass` requires no migration. Just use
`tpass` instead of `pass` — the store format is identical:

```
# Before
pass show email/work

# After
tpass show email/work
```

Both commands read the same `~/.password-store/` directory and the same
`~/.tumpa/keys.db` keystore.

---

## Encryption and decryption

`tclig` is the GPG drop-in, so encryption and decryption from the
shell use the same flags `gpg` accepts.

### Encrypting

Encrypt from stdin to a file:

```
echo "secret data" | tclig -e -r <FINGERPRINT> -o secret.gpg
```

Encrypt a file:

```
tclig -e -r <FINGERPRINT> -o document.gpg document.txt
```

Encrypt to multiple recipients (any of them can decrypt):

```
tclig -e -r <FP1> -r <FP2> -r <FP3> -o shared.gpg data.txt
```

Produce ASCII-armored output:

```
tclig -e -a -r <FINGERPRINT> -o secret.asc document.txt
```

### Decrypting

Decrypt to stdout:

```
tclig -d secret.gpg
```

Decrypt to a file:

```
tclig -d -o document.txt secret.gpg
```

Decrypt ciphertext piped on stdin (pass `-` as the input file, same
convention as `gpg`):

```
cat secret.gpg | tclig -d -
```

`tclig` automatically determines which secret key can decrypt the
message by inspecting the encrypted file's recipient key IDs. If your
keystore contains the matching secret key, decryption proceeds after
passphrase entry.

Output files from decryption are created with `0600` permissions
(owner read/write only).

### Inspecting encrypted files

To see which key IDs a file is encrypted for, without decrypting:

```
tclig --decrypt --list-only encrypted.gpg
```

Output:

```
gpg: public key is CCD470033AD77830
```

---

## Agent (passphrase cache + SSH)

`tcli agent` runs a daemon that caches passphrases for GPG operations
and optionally serves as an SSH agent. This eliminates repeated
passphrase prompts when signing commits, decrypting passwords, etc.

### GPG passphrase caching only

```
tcli agent
```

When the agent is running, `tcli`, `tclig`, and `tpass` all check it
for cached passphrases before prompting via pinentry. Passphrases
obtained from pinentry are automatically stored in the agent for
reuse.

### GPG + SSH agent

```
tcli agent --ssh
tcli agent --ssh -H unix:///tmp/tcli.sock   # custom SSH socket
```

When `--ssh` is passed, the agent also serves SSH authentication
requests. The SSH and GPG caches are shared — a passphrase cached
from a git signing operation is also available for SSH authentication
with the same key.

```
ssh-add -L    # list available SSH keys
ssh user@host # authenticate
```

### Cache TTL

```
tcli agent --cache-ttl 3600   # 1 hour (default: 1800 = 30 min)
```

Cached passphrases expire after the TTL. A background task sweeps
expired entries every 60 seconds.

### Starting the agent automatically

#### macOS (Launch Agent)

Create `~/Library/LaunchAgents/rocks.tumpa.agent.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>rocks.tumpa.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/USERNAME/.cargo/bin/tcli</string>
        <string>agent</string>
        <string>--ssh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/Users/USERNAME/.tumpa/agent.log</string>
</dict>
</plist>
```

Replace `USERNAME` with your macOS username, then load it:

```
launchctl load ~/Library/LaunchAgents/rocks.tumpa.agent.plist
```

Add to your shell profile (`~/.zshrc`):

```bash
export SSH_AUTH_SOCK="$HOME/.tumpa/tcli-ssh.sock"
```

The agent starts automatically on login, restarts if it crashes, and
logs to `~/.tumpa/agent.log`.

To stop: `launchctl unload ~/Library/LaunchAgents/rocks.tumpa.agent.plist`

#### Linux (systemd user service, recommended)

Ready-made user units ship under
[`contrib/systemd/`](../contrib/systemd/). Three variants are
provided and they are mutually exclusive via `Conflicts=`, so
switching between them is a single `systemctl --user enable --now …`:

| Unit                          | Runs                     | GPG cache | SSH agent |
|-------------------------------|--------------------------|:---:|:---:|
| `tumpa-agent.service`         | `tcli agent --ssh`       | ✓   | ✓   |
| `tumpa-gpg-agent.service`     | `tcli agent`             | ✓   | —   |
| `tumpa-ssh-agent.service`     | `tcli ssh-agent -H …`    | —   | ✓   |

Install and enable (combined agent shown — swap the unit name for
the other variants):

```bash
mkdir -p ~/.config/systemd/user
cp contrib/systemd/tumpa-*.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now tumpa-agent.service
```

The units call `%h/.cargo/bin/tcli` by default (from
`cargo install tumpa-cli`). If your binary is elsewhere, edit the
unit via `systemctl --user edit --full tumpa-agent.service` and
adjust `ExecStart=`. The systemd-scoped approach handles crash
restart, clean shutdown, and logging via the journal:

```bash
journalctl --user -u tumpa-agent.service -f
```

Wire up `SSH_AUTH_SOCK` for every shell the user session spawns via
an `environment.d` drop-in (same pattern `gnome-keyring-daemon`
uses — no `.bashrc`/`.zshrc` hack needed):

```bash
mkdir -p ~/.config/environment.d
echo 'SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/tcli-ssh.sock' \
    > ~/.config/environment.d/tumpa-ssh-agent.conf
```

Re-login (or `systemctl --user daemon-reexec`) for the environment
drop-in to take effect.

Environment overrides (`PINENTRY_PROGRAM`, `TUMPA_KEYSTORE`,
`RUST_LOG`) can go in `~/.config/tumpa/env` — the units pick it up
automatically. Do **not** put `TUMPA_PASSPHRASE=…` in that file;
prefer pinentry.

For full details and troubleshooting, see
[`contrib/systemd/README.md`](../contrib/systemd/README.md). For the
design rationale (why three units, why user-scoped, why no socket
activation yet), see
[`docs/adr/0004-systemd-user-service.md`](adr/0004-systemd-user-service.md).

#### Linux (without systemd)

If your system uses `runit`, `s6`, `openrc`, or no service manager
at all, add to `~/.bashrc` or `~/.zshrc`:

```bash
if ! pgrep -f "tcli agent" >/dev/null; then
    tcli agent --ssh &
    disown
fi
export SSH_AUTH_SOCK=$(tcli --show-socket ssh)
```

This is a fallback — it does not restart the agent on crash and
only runs in interactive shells.

### Querying socket paths

```
tcli --show-socket         # GPG agent socket
tcli --show-socket ssh     # SSH agent socket
```

Output:

```
$ tcli --show-socket
/home/user/.tumpa/agent.sock

$ tcli --show-socket ssh
/run/user/1000/tcli-ssh.sock
```

Useful for shell profile setup:

```bash
export SSH_AUTH_SOCK=$(tcli --show-socket ssh)
```

The SSH socket defaults to `/run/user/<UID>/tcli-ssh.sock` on Linux
and `~/.tumpa/tcli-ssh.sock` on macOS.

### Without agent

Everything works without the agent — you just get prompted every
time. The agent is purely additive.

### Supported SSH algorithms

| Key type | SSH algorithm | Status |
|---|---|---|
| Ed25519 | `ssh-ed25519` | Supported |
| ECDSA P-256 | `ecdsa-sha2-nistp256` | Supported |
| ECDSA P-384 | `ecdsa-sha2-nistp384` | Supported |
| ECDSA P-521 | `ecdsa-sha2-nistp521` | Supported |
| RSA 2048/4096 | `ssh-rsa` | Supported |

### Security notes

- The agent socket (`~/.tumpa/agent.sock`) is created with `0600`
  permissions (owner only). Security relies on filesystem permissions,
  same trust model as gpg-agent and ssh-agent.
- Passphrases are stored in memory using `Zeroizing<String>` and are
  zeroed when expired or when the agent exits.
- A PID file (`~/.tumpa/agent.pid`) prevents multiple agents from
  running simultaneously.

---

## Hardware OpenPGP cards

`tcli` supports OpenPGP-compatible smart cards for signing, decryption,
and SSH authentication. Regularly tested against:

| Card | Supported algorithms | Notes |
|---|---|---|
| **YubiKey 4 / 5** | RSA 2048/4096, NIST P-256/P-384, Curve25519 | Curve25519 requires firmware ≥ 5.2.3 |
| **Nitrokey 3** | RSA, `Cv25519Modern` (Ed25519 + X25519 per RFC 9580) | Legacy `Cv25519` (EdDSALegacy + ECDH/Curve25519), `Ed448`, and `X448` are rejected at upload time with a clear error |

Other OpenPGP-card implementations may work but aren't on the test matrix.

When uploading a key to a Nitrokey, generate it with `cv25519modern`:

```
tcli generate --cipher cv25519modern
```

Uploading a legacy `Cv25519` key to a Nitrokey exits with:

```
Error: failed to upload primary key of ABC... to card: Nitrokey GmbH does not support EdDSALegacy
```

No APDU is sent to the card in this case — the guard fires before the
factory-reset step, so your card is never left in a half-reset state.

### Card status

```
tcli --card-status
```

Shows details of all connected OpenPGP cards, similar to
`gpg --card-status`:

```
Manufacturer .....: Yubico
Serial number ....: 04901321
Name of cardholder: Kushal Das
URL of public key : https://kushaldas.in/key.asc
Signature key ....: 0BC1 3512 5EB2 FF9A 0F88  EE1C C65F F007 C757 66ED
Encryption key ...: D2BA F621 2E4C DE54 8C33  0C3D FB82 AA5D 326D A75D
Authentication key: 621B 1339 CDB8 3147 9A4D  EB4F 7C90 F274 9E08 5E1D
Signature counter : 1234
PIN retry counter : 3 0 3
```

If no card is connected, prints "No OpenPGP card detected."

### How card priority works

For every operation, `tcli` and `tpass` check for a connected card
first:

1. **Signing:** checks if any connected card holds the signing key.
   If found, the card performs the signature. Otherwise, the software
   key is used.
2. **Decryption:** checks if any connected card holds the encryption
   key. If found, prompts for card PIN and decrypts on-card. Otherwise,
   falls back to software key.
3. **SSH agent:** card-based authentication keys are listed alongside
   software keys. Card keys are preferred when both are available.

### PIN entry

Card PINs are prompted via pinentry, the same way as software key
passphrases. Set `TUMPA_PASSPHRASE` for non-interactive card PIN
entry (e.g., in CI).

### Listing connected cards

`tcli` enumerates every OpenPGP card visible to PCSC with:

```
tcli --list-cards
```

`--list-cards` is always available (no Cargo feature needed) and
cannot be combined with any other flag.

Sample output:

```
IDENT          MANUFACTURER   SERIAL    HOLDER
0000:00000001  Testcard       00000001  (unset)
000F:CB9A5355  Nitrokey GmbH  CB9A5355  (unset)
```

The IDENT column is the value you pass to `--card-ident` on
`--upload-to-card` / `--reset-card` when more than one card is
attached.

### Uploading a key to a card (experimental)

Builds compiled with `cargo build --features experimental` expose:

```
tcli --upload-to-card FINGERPRINT [--which primary|sub] [--card-ident IDENT]
```

**Warning — destructive:** `--upload-to-card` **factory-resets the
card first** (cardholder name, URL, user PIN, and admin PIN are
cleared to defaults) before writing the selected signing-slot. Only
the key passphrase is prompted; the admin PIN is managed internally
and set to the factory default `12345678` after reset.

With multiple cards attached, pass `--card-ident` (see
`--list-cards` for the value). With a single card, `--card-ident`
can be omitted.

For Nitrokey, the key must be `Cv25519Modern` (Ed25519 + X25519) or
RSA — see the compatibility table above. Legacy `Cv25519`, `Ed448`,
and `X448` keys are rejected before any I/O hits the card.

Factory-reset without upload (e.g. to re-provision):

```
tcli --reset-card [--card-ident IDENT]
```

---

## Passphrase handling

`tcli` needs a passphrase (for software keys) or PIN (for cards)
whenever a secret key operation is performed.

### Acquisition order

1. **Agent cache** -- if `tcli agent` is running, cached passphrases
   are returned without prompting. Both `tcli` (GPG mode) and `tpass`
   benefit automatically.

2. **`TUMPA_PASSPHRASE` environment variable** -- if set, used
   immediately. Suitable for scripting, CI/CD, and testing. Do not
   use in production on shared systems (the variable is visible in
   `/proc/<pid>/environ`).

3. **`pinentry` program** -- `tcli` spawns the system's `pinentry`
   (the same program GnuPG uses). This opens a GUI dialog on desktop
   systems or a curses prompt in terminals. Override the program with
   `PINENTRY_PROGRAM`:

   ```
   export PINENTRY_PROGRAM=/usr/bin/pinentry-gnome3
   ```

4. **Terminal prompt** -- if pinentry is not available, `tcli` falls
   back to reading from the terminal via `rpassword`.

When the agent is running and a passphrase is obtained from steps 2-4,
it is automatically stored in the agent cache for future use.

### Agent caching

With `tcli agent` running, passphrases are cached with a configurable
TTL (default 30 minutes). This is especially valuable for:

- `tpass grep` — decrypts every entry without re-prompting
- `tpass init` — reencrypts all entries with a single prompt
- Repeated `git commit -S` — no prompt after the first one

---

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `TUMPA_KEYSTORE` | Path to the tumpa keystore database | `~/.tumpa/keys.db` |
| `TUMPA_PASSPHRASE` | Passphrase / PIN for non-interactive use | (prompt) |
| `PINENTRY_PROGRAM` | Path to the pinentry binary | `pinentry` |
| `RUST_LOG` | Log level (`error`, `warn`, `info`, `debug`, `trace`) | `error` |

---

## Troubleshooting

### "No key found for identifier: ..."

The fingerprint or key ID you provided doesn't match any key in the
tumpa keystore. Run `tcli --list-keys` to see available keys. Make
sure the key was imported in the tumpa desktop app.

### "No secret key found for key IDs: ..."

The encrypted message is addressed to a key you don't have the secret
for. Check `tcli --list-keys` -- keys marked `sec` can decrypt with
software keys, and keys marked `pub` can decrypt if the corresponding
OpenPGP card is connected. Make sure `pcscd` is running if using a card.

### "Failed to enumerate cards" or card errors

Make sure `pcscd` is running:

```
sudo systemctl start pcscd.socket
```

And that your card reader is recognized:

```
pcsc_scan
```

### pinentry doesn't appear

Check that `pinentry` is installed:

```
which pinentry
```

Install it if missing:

```
# Debian/Ubuntu
sudo apt install pinentry-gnome3   # or pinentry-curses

# Fedora
sudo dnf install pinentry-gnome3

# macOS
brew install pinentry-mac
```

Set `PINENTRY_PROGRAM` if the binary has a non-standard name:

```
export PINENTRY_PROGRAM=/usr/local/bin/pinentry-mac
```

### pass says "encryption failed" or "decryption failed"

Enable debug logging to see what `tcli` is doing:

```
RUST_LOG=debug pass show myentry 2>/tmp/tcli-debug.log
cat /tmp/tcli-debug.log
```

Common causes:

- The key fingerprint in `.gpg-id` doesn't match any key in the
  tumpa keystore
- The secret key's passphrase is wrong (pinentry will prompt again)
- The key is revoked or expired

### git says "failed to sign the data"

1. Check that `gpg.program` is set correctly (and points at `tclig`,
   not `tcli` — `tcli` does not accept GPG flags):

   ```
   git config --global gpg.program
   ```

2. Verify `tclig` can sign on its own:

   ```
   echo test | tclig -bsau <FINGERPRINT>
   ```

3. Make sure `user.signingkey` matches a key in the keystore:

   ```
   git config --global user.signingkey
   tcli --list-keys
   ```

### `gpg: unknown option --verify` after upgrading

You have `git config gpg.program tcli`, or a `gpg2` symlink
pointing at `tcli`. As of tumpa-cli 0.2 the GPG drop-in lives in a
separate binary, `tclig`. Re-point the setting:

```
git config --global gpg.program tclig
ln -sf $(which tclig) ~/bin/gpg2
```

### Verifying the setup

Quick end-to-end check:

```
# Sign and verify
echo "hello" | tclig -bsau <FP> > /tmp/test.sig
echo "hello" | tclig --verify /tmp/test.sig -

# Encrypt and decrypt
echo "secret" | tclig -e -r <FP> -o /tmp/test.gpg
tclig -d /tmp/test.gpg

# Clean up
rm /tmp/test.sig /tmp/test.gpg
```
