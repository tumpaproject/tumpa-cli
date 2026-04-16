# Usage Guide

This guide covers installation, setup, and day-to-day usage of `tcli`
for git signing, password management with `pass`, SSH authentication,
and direct encryption/decryption.

## Table of contents

- [Installation](#installation)
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

Two binaries are installed to `~/.cargo/bin/`:

- `tcli` — GPG replacement for git signing and SSH agent
- `tpass` — drop-in replacement for `pass` (password-store)

Make sure `~/.cargo/bin/` is in your `PATH`.

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

---

## Key management

`tcli` reads keys from the [tumpa](https://github.com/tumpaproject/tumpa)
keystore at `~/.tumpa/keys.db`. Keys can be managed from the command
line or through the tumpa desktop application.

### Importing keys

```
tcli --import mykey.asc
tcli --import /path/to/keys/ --recursive
```

Accepts armored and binary OpenPGP files. For directories, imports all
`.asc`, `.gpg`, `.pub`, `.key`, `.pgp` files.

When importing a key that already exists in the keystore, `tcli` merges
the new data into the existing certificate instead of skipping it. This
picks up renewed expiry dates, new third-party certifications, updated
subkey bindings, and new user IDs. If the imported data is identical to
what's already stored, the key is reported as "Unchanged".

```
$ tcli --import updated_key.asc
Updated A85FF376759C994A... (Alice <alice@example.com>) — merged new signatures
```

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

For scripts that parse GnuPG's colon-delimited output:

```
tcli --list-keys --with-colons
tcli --list-keys --with-colons <FINGERPRINT>
tcli --list-secret-keys --with-colons
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

Tell git to use `tcli` instead of `gpg`:

```
git config --global gpg.program tcli
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

When git calls `tcli` for signing, it:

1. Checks if a connected OpenPGP card holds the signing key
2. If yes, signs using the card (prompts for card PIN via pinentry)
3. If no card, signs using the software key from the keystore
   (prompts for passphrase via pinentry)

For verification, `tcli` looks up the signer's certificate in the
keystore by fingerprint or key ID extracted from the signature.

### bump-tag compatibility

[multiverse/bump-tag](https://github.com/SUNET/multiverse) works
without any changes. `tcli` produces the `[GNUPG:]` status lines that
git and bump-tag expect: `SIG_CREATED`, `GOODSIG`, `VALIDSIG`, and
`TRUST_FULLY`.

---

## Password store (pass)

[pass](https://www.passwordstore.org/) is the standard Unix password
manager. It calls `gpg` for all encryption and decryption. `tcli` can
replace `gpg` for `pass`.

### Setup

`pass` looks for `gpg2` (or `gpg`) in your `PATH`. The simplest
approach is to create a symlink:

```
mkdir -p ~/bin
ln -s $(which tcli) ~/bin/gpg2
```

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export PATH="$HOME/bin:$PATH"
```

Alternatively, use an alias (works for interactive use but not all
scripts):

```bash
alias gpg2=tcli
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

Prints the decrypted password to stdout. `tcli` automatically finds
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
`tcli` supports the `--decrypt --list-only` and `--list-keys --with-colons`
commands that `pass` uses to detect which files need reencryption.

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
  No need to symlink `tcli` as `gpg2` or configure `gpg.program`.
- **Faster** — no process spawning overhead for GPG on each operation.
- **Single binary** — `tpass` handles everything; no shell script.
- **GPG groups not supported** — `pass` can expand GPG groups from
  `gpg.conf`. `tpass` treats all `.gpg-id` entries as literal key
  identifiers. Use full fingerprints instead.

### Migrating from pass

If you already have a password store set up with `pass` and `tcli` as
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

`tcli` can be used directly for encryption and decryption, outside of
git or `pass`.

### Encrypting

Encrypt from stdin to a file:

```
echo "secret data" | tcli -e -r <FINGERPRINT> -o secret.gpg
```

Encrypt a file:

```
tcli -e -r <FINGERPRINT> -o document.gpg document.txt
```

Encrypt to multiple recipients (any of them can decrypt):

```
tcli -e -r <FP1> -r <FP2> -r <FP3> -o shared.gpg data.txt
```

Produce ASCII-armored output:

```
tcli -e -a -r <FINGERPRINT> -o secret.asc document.txt
```

### Decrypting

Decrypt to stdout:

```
tcli -d secret.gpg
```

Decrypt to a file:

```
tcli -d -o document.txt secret.gpg
```

`tcli` automatically determines which secret key can decrypt the
message by inspecting the encrypted file's recipient key IDs. If your
keystore contains the matching secret key, decryption proceeds after
passphrase entry.

Output files from decryption are created with `0600` permissions
(owner read/write only).

### Inspecting encrypted files

To see which key IDs a file is encrypted for, without decrypting:

```
tcli --decrypt --list-only encrypted.gpg
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

When the agent is running, `tcli` and `tpass` check it for cached
passphrases before prompting via pinentry. Passphrases obtained from
pinentry are automatically stored in the agent for reuse.

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

### Shell profile setup

```bash
# Start the agent if not already running
if ! pgrep -f "tcli agent" >/dev/null; then
    tcli agent --ssh &
    disown
fi
```

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

`tcli` supports YubiKey and other OpenPGP-compatible smart cards for
signing, decryption, and SSH authentication.

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

1. Check that `gpg.program` is set correctly:

   ```
   git config --global gpg.program
   ```

2. Verify `tcli` can sign on its own:

   ```
   echo test | tcli -bsau <FINGERPRINT>
   ```

3. Make sure `user.signingkey` matches a key in the keystore:

   ```
   git config --global user.signingkey
   tcli --list-keys
   ```

### Verifying the setup

Quick end-to-end check:

```
# Sign and verify
echo "hello" | tcli -bsau <FP> > /tmp/test.sig
echo "hello" | tcli --verify /tmp/test.sig -

# Encrypt and decrypt
echo "secret" | tcli -e -r <FP> -o /tmp/test.gpg
tcli -d /tmp/test.gpg

# Clean up
rm /tmp/test.sig /tmp/test.gpg
```
