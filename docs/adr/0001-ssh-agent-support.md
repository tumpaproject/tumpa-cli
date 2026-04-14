# ADR 0001: SSH Agent Support

## Status

Accepted

## Context

The tumpa ecosystem provides key management through a desktop application
(tumpa) and hardware OpenPGP card support. Users who store authentication
subkeys in the tumpa keystore (`~/.tumpa/keys.db`) or on OpenPGP cards
had no way to use those keys for SSH authentication without a separate
SSH agent (like the existing `openpgp-card-ssh-agent`, which only supports
hardware cards).

We needed an SSH agent that:

- Serves authentication subkeys from software keys in the tumpa keystore
- Also supports hardware OpenPGP cards when connected
- Shares the same binary and keystore as the GPG replacement (`tcli`)
- Handles passphrase acquisition via pinentry with in-memory caching

## Decision

We implemented the SSH agent as a subcommand of `tcli` rather than a
separate binary. The agent is started with:

```
tcli ssh-agent -H unix:///path/to/socket
```

### Key resolution

The agent resolves keys from two sources, in order:

1. **Connected OpenPGP cards** -- if a card has an authentication key
   whose fingerprint appears in the tumpa keystore, the agent lists it.
   Card-based signing uses the card's own cryptographic hardware.

2. **Software keys in the tumpa keystore** -- any secret key with a
   non-revoked authentication subkey is listed. Software-key signing
   unlocks the subkey in memory and performs the raw cryptographic
   operation.

### Signing approach

SSH requires raw cryptographic signatures (not OpenPGP formatted). For
software keys, we added `ssh_sign_raw()` to the `wecanencrypt` library.
This function:

1. Parses the secret certificate
2. Finds the authentication subkey
3. Unlocks it with the passphrase
4. Performs the appropriate raw signature (Ed25519, ECDSA, or RSA)
5. Returns the algorithm-specific signature bytes

The agent converts these bytes to the SSH wire format expected by
`ssh-agent-lib`.

### Passphrase handling

Passphrases for software keys are acquired via pinentry (or the
`TUMPA_PASSPHRASE` environment variable) and cached in memory using
`Zeroizing<String>` for the lifetime of the agent process. If a
signing operation fails (possibly wrong passphrase), the cached entry
is cleared so the user is prompted again.

### Protocol

The agent implements the `ssh-agent-lib` `Session` trait:

- `request_identities()` -- returns all available authentication keys
- `sign()` -- matches the requested public key to a keystore entry and
  signs the data

The agent listens on a Unix domain socket. Clients (ssh, ssh-add)
connect via `SSH_AUTH_SOCK`.

## Supported key algorithms

### GPG operations (signing and verification)

These use OpenPGP formatted signatures via the `wecanencrypt` library.
All cipher suites that `wecanencrypt` supports for key generation are
supported:

| Cipher suite | Primary key | Subkeys | Notes |
|---|---|---|---|
| Cv25519 (default) | EdDSA (Ed25519) | ECDH (Curve25519) | Legacy v4 format, widely compatible |
| Cv25519Modern | Ed25519 | X25519 | RFC 9580 native format |
| RSA 2048 | RSA | RSA | |
| RSA 4096 | RSA | RSA | |
| NIST P-256 | ECDSA | ECDH | |
| NIST P-384 | ECDSA | ECDH | |
| NIST P-521 | ECDSA | ECDH | |

For signing, `tcli` uses the primary key by default (via
`wecanencrypt::sign_bytes_detached`). When a hardware card is connected
and holds the signing key, the card performs the signing operation.

For verification, the signature issuer is extracted from the signature
packet (fingerprint or key ID) and looked up in the tumpa keystore.
Verification is attempted against the primary key and all non-revoked
subkeys.

### SSH agent (authentication)

The SSH agent serves authentication subkeys. Only keys with the
OpenPGP authentication key flag are exposed as SSH identities.

**Identity listing** (all algorithms listed as SSH public keys):

| Algorithm | SSH key type | Status |
|---|---|---|
| Ed25519 (v4 legacy EdDSA) | `ssh-ed25519` | Supported |
| Ed25519 (v6 RFC 9580) | `ssh-ed25519` | Supported |
| ECDSA P-256 | `ecdsa-sha2-nistp256` | Supported |
| ECDSA P-384 | `ecdsa-sha2-nistp384` | Supported |
| ECDSA P-521 | `ecdsa-sha2-nistp521` | Supported |
| RSA 2048/4096 | `ssh-rsa` | Supported |

**Software key signing** (raw cryptographic signatures):

| Algorithm | Status | Notes |
|---|---|---|
| Ed25519 | Supported | Uses `ed25519-dalek` via the pgp crate |
| ECDSA P-256 | Supported | SHA-256 digest, `p256` crate |
| ECDSA P-384 | Supported | SHA-384 digest, `p384` crate |
| ECDSA P-521 | Supported | SHA-512 digest, `p521` crate |
| RSA 2048/4096 | Supported | PKCS#1v15 with SHA-256 or SHA-512, private key reconstructed from pgp key components via `rsa` crate |

### Card operations

When a hardware OpenPGP card is connected, the card handles:

- **GPG signing** -- via `wecanencrypt::card::sign_bytes_detached_on_card()`
- **SSH authentication** -- card identity is listed if the auth key
  fingerprint is found in the tumpa keystore (signing is done by the
  card hardware)

Card-supported algorithms depend on the card hardware (YubiKey, Nitrokey,
etc.) but typically include RSA 2048/4096, Ed25519, and NIST P-256/P-384.

## Consequences

- Users can use the same keys for both GPG (git signing) and SSH
  authentication without needing separate tools.
- A single long-running `tcli ssh-agent` process replaces both
  `ssh-agent` and `openpgp-card-ssh-agent` for users of the tumpa
  keystore.
- Software key passphrases are held in memory (zeroized on drop) for
  the agent's lifetime. Users who want tighter control should use
  hardware cards.
- All common SSH key algorithms (Ed25519, ECDSA, RSA) are supported
  for both identity listing and software key signing.
