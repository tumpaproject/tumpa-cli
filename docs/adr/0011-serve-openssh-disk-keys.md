# ADR 0011: Serve On-Disk OpenSSH Keys from ~/.ssh

## Status

Accepted

## Context

The SSH agent (ADR 0001) served identities from two sources: hardware
OpenPGP cards and authentication subkeys in the tumpa keystore
(`~/.tumpa/keys.db`). Users who also hold plain OpenSSH keys
(`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, ...) still had to run the stock
`ssh-agent` next to the tumpa agent, and `ssh-add` a key per session —
or type the key passphrase on every connection.

For the tumpa agent to be a full `ssh-agent` replacement it must serve
those keys too, with the same pinentry prompting and in-memory
passphrase caching the card and keystore paths already have.

## Decision

`TumpaBackend` gains a third identity source: OpenSSH private keys
discovered on disk (`src/ssh/disk_keys.rs`).

### Discovery

- The scanned directory defaults to `~/.ssh` and can be overridden
  with `TUMPA_SSH_DIR`; an empty value disables scanning.
- No registration step (`ssh-add` is not needed and not implemented):
  every file in the directory whose contents start with the
  `-----BEGIN OPENSSH PRIVATE KEY-----` header is parsed. Everything
  else (`*.pub`, `known_hosts`, `config`, sockets, oversized files)
  is skipped, and one unparsable file never hides the rest.
- The directory is rescanned on each `request_identities` call and on
  a sign-request cache miss. The scan is a handful of small file
  reads, and it makes newly created keys visible without restarting
  the agent — mirroring how card hotplug is handled.
- Only key types the agent can sign with are listed: Ed25519,
  ECDSA P-256/P-384/P-521, and RSA. FIDO (`sk-*`) keys need the
  authenticator, and DSA is dead; both are skipped.
- A disk key whose public key already appears as a card or keystore
  identity is not listed twice; the card/keystore entry wins.

### Listing without prompting

The public half of an OpenSSH private key file is stored in
cleartext, so encrypted keys are listed without any passphrase
prompt. Only the key comment lives inside the encrypted blob; for
encrypted keys the comment is taken from the sibling `.pub` file,
falling back to the key path.

### Signing and passphrase caching

Sign requests re-read the key file at sign time (the private material
is never held in agent memory between requests). Encrypted keys are
unlocked via the standard acquisition order (`TUMPA_PASSPHRASE`, then
pinentry) with up to 3 attempts, mirroring the card PIN retry flow.
The passphrase is stored in the shared `CredentialCache` only after a
successful decrypt, keyed as `ssh-disk:<SHA256 fingerprint>` so it can
never collide with a card ident or an OpenPGP fingerprint. Cached
passphrases expire under the same TTL sweep as everything else.

### RSA signing goes through the rsa crate directly

ssh-key 0.6's built-in `Signer` impl for RSA keys is hard-wired to
SHA-512, but SSH clients negotiate the hash and send it as agent
flags (`rsa-sha2-256` = 2, `rsa-sha2-512` = 4). `disk_keys::sign`
therefore dispatches on the flags and signs via
`rsa::pkcs1v15::SigningKey<Sha256|Sha512>`. Requests without either
flag would mean legacy SHA-1 `ssh-rsa`; they are refused, matching
the card path.

The `rsa::RsaPrivateKey` is built from the keypair components by
hand instead of using ssh-key's own conversion: through ssh-key
0.6.7, `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` passes `[p, p]`
as the prime factors instead of `[p, q]`, so the rsa crate rejects
every converted key with a consistency error. The workaround lives in
`disk_keys::rsa_private_key` and can be dropped when the upstream fix
ships.

## Alternatives considered

- **`ssh-add` support (`AddIdentity` protocol message):** would put
  the tumpa agent in charge of keys explicitly handed to it, like
  stock `ssh-agent`. Rejected for now: directory scanning covers the
  common case with zero user setup, and constrained-identity
  semantics (lifetimes, confirm flags) are a larger surface. Can be
  added later without conflicting with scanning.
- **Registering disk keys in the keystore:** importing OpenSSH keys
  into `~/.tumpa/keys.db` would funnel everything through one store,
  but OpenSSH keys are not OpenPGP certificates; wrapping them would
  invent a key format for no user benefit.
- **Caching the decrypted private key instead of the passphrase:**
  marginally faster (skips bcrypt KDF per sign), but keeps raw key
  material in memory long-term instead of a `Zeroizing<String>`
  passphrase, and diverges from how the GPG cache works.

## Consequences

- `tcli ssh-agent` / `tcli agent --ssh` can replace `ssh-agent`
  outright, even for users with no tumpa keystore at all.
- The agent reads key files under the user's home directory at
  runtime. The scan is read-only and skips anything that is not an
  OpenSSH private key, but users who point `SSH_AUTH_SOCK` at the
  tumpa agent should be aware their `~/.ssh` keys are now served by
  it (this is the point of the feature, and identical to what stock
  `ssh-agent` + `ssh-add` would expose).
- New cargo features on ssh-key (`ed25519`, `rsa`, `encryption`) and
  new direct deps `rsa` (must stay on the same 0.9.x line as
  ssh-key's own rsa dependency) and `signature`.
- `TUMPA_SSH_DIR` joins the environment variable surface
  (documented in usage.md).
