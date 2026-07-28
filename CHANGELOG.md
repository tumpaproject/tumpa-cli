# Changelog

All notable changes to tumpa-cli are documented in this file.
Older releases (before 0.6.1) are documented by their git tags and
commit history.

## [0.6.4] - 2026-07-28

### Added

- `tcli sign-inline` now supports OpenPGP smart cards: card-first
  dispatch tries a connected card holding the signing key (prompting
  for the card PIN) before falling back to the software secret key in
  the keystore. Card-only keys can therefore produce cleartext
  signatures while their card is connected. Detached `tcli sign`
  already worked this way.
- When card signing fails and the command falls back to the software
  key, a warning naming the card is printed to stderr, so the
  downgrade from hardware to software is never silent.

### Security

- A wrong card PIN no longer falls through to the software-key
  fallback. Previously a mistyped PIN spent one of the card's retry
  attempts (typically 3 before the card blocks) while the command
  silently succeeded with the software key, so repeated runs could
  block the card without the user ever noticing. `tcli sign` and
  `tcli sign-inline` now abort with the PIN error instead.
- Fallback is blocked only on a *typed* PIN rejection
  (`PinIncorrect`/`PinBlocked` from the card). Transport and card
  state errors (reader unplugged, applet errors) still fall back to
  the software key, and no longer clear the agent's cached PIN since
  it was never evaluated.

### Changed

- Dependencies updated: libtumpa 0.4.3 -> 0.4.5, wecanencrypt
  0.16.2 -> 0.16.3, pgp 0.19 -> 0.20. pgp stays exactly in lockstep
  with wecanencrypt's own pgp dependency, as required for consistent
  signature parsing in `verify`.

### Fixed

- Homebrew formula: fixed the `tclig` symlink so git can invoke the
  GPG drop-in.

## [0.6.3] - 2026-07-03

### Added

- The SSH agent (`tcli ssh-agent` / `tcli agent --ssh`) now serves
  plain OpenSSH private keys from `~/.ssh` alongside card and
  keystore identities, so it can replace `ssh-agent` outright (#39,
  #44, ADR 0011).
  - The directory is rescanned on every identity request, so newly
    generated keys appear without restarting the agent. Override the
    directory with `TUMPA_SSH_DIR`; set it empty to disable.
  - Encrypted keys are listed without prompting; the passphrase is
    requested via pinentry only at sign time (up to 3 attempts) and
    cached in the shared agent cache. Comments for encrypted keys
    fall back to the sibling `.pub` file.
  - Supported types: Ed25519, ECDSA P-256/384/521, RSA
    (`rsa-sha2-256`/`rsa-sha2-512`; legacy SHA-1 `ssh-rsa` is
    refused). FIDO (`sk-*`) and DSA keys are skipped. Keys already
    served from a card or the keystore are not listed twice.

### Security

- Disk key files follow OpenSSH's strict permission rules: a key
  readable or writable by group/other (e.g. mode 0644) is refused at
  both scan and sign time (Unix only; other platforms have no Unix
  mode bits).
- Symlinks in the key directory are never followed. On Unix the key
  file is opened once with `O_NOFOLLOW`/`O_NONBLOCK` and every guard
  (regular file, 64 KiB size cap, permissions) plus the read applies
  to that open handle, so nothing can be swapped in between a check
  and the read.
- The requested public key is re-verified after the sign-time
  re-read, so a key file replaced between scan and sign fails fast
  instead of prompting for a passphrase or returning a signature the
  client rejects.
- Private key file contents are held in zeroizing buffers that are
  wiped when parsing ends.

### Changed

- Disk key scanning, key file reads, pinentry prompting, and the
  bcrypt passphrase decrypt all run on the async runtime's blocking
  pool, so filesystem or user-interaction latency cannot stall other
  agent sessions.
- Dependencies updated; RUSTSEC-2026-0194 is ignored (no fixed
  release available). libtumpa 0.4.2 -> 0.4.3.

### Fixed

- RSA signature flag precedence is now identical across the card,
  keystore, and disk key signing paths: `rsa-sha2-256` wins when a
  client sets both SHA-2 flags, matching OpenSSH's own agent.
- I/O errors while scanning `~/.ssh` (permission denied, transient
  failures) are logged instead of silently swallowed, so an
  unreadable key cannot disappear without a trace.
- Key files with stray leading whitespace are parsed correctly
  instead of passing discovery and then failing at sign time.

## [0.6.2] - 2026-06-22

### Added

- `tcli encrypt` and `tcli decrypt` subcommands: human-facing file
  and stdin encryption/decryption backed by the tumpa keystore
  (ADR 0010).

### Changed

- wecanencrypt 0.16.2.

## [0.6.1] - 2026-05-23

### Added

- Linux touch-confirmation banners via desktop notifications
  (notify-rust): a banner appears when an OpenPGP card is waiting
  for a touch, matching the existing macOS behavior.

## [0.6.0] - 2026-05-04

See the `v0.6.0` git tag and commit history.
