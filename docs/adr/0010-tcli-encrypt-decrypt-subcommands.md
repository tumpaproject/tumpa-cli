# ADR 0010: `tcli encrypt` / `tcli decrypt` Subcommands

## Status

Accepted

## Date

2026-06-22

## Context

Through 0.6.x, the only way to encrypt or decrypt from the shell was
the GPG drop-in binary `tclig`:

```
tclig -e -r <FP> -o secret.gpg document.txt
tclig -d secret.gpg
```

`tclig` exists to be invoked *by other programs* — git, `pass`, and any
other consumer that shells out to `gpg` with `gpg`-shape flags (see
ADR 0005). Its grammar, its `[GNUPG:]` status lines on stderr, and its
silent acceptance of compat no-ops (`--batch`, `--no-encrypt-to`, …)
are all there to satisfy machine callers, not humans.

The human-facing binary `tcli` already covered the *signing* side of
the same split: `tcli sign`, `tcli sign-inline`, and `tcli verify` are
the human verbs, while `tclig -bsau` / `tclig --verify` are the
machine forms (ADR 0009). Encryption and decryption were the only
cryptographic operations with no human-facing verb — a user who wanted
to encrypt a file to a colleague had to drop down to the GPG-shape
binary and remember `-e -r … -a -o …`.

This was an inconsistency, not just a missing convenience:

1. **The split was advertised but incomplete.** `docs/usage.md` and
   `--help` present `tcli` as the human UI and `tclig` as the GPG
   drop-in, yet directed users to `tclig` for the single most common
   non-signing operation.

2. **`tclig`'s ergonomics are wrong for humans.** It emits no
   "wrote ciphertext to X" confirmation, defaults to binary output
   (humans usually want armored), requires `-o` for the common case,
   and prints `INV_RECP` machine status lines instead of a readable
   "no key for X" message.

3. **The crypto core already existed.** `gpg::encrypt` and
   `gpg::decrypt` already implement multi-recipient encryption,
   card-first sign-then-encrypt dispatch, card-first decryption with
   software fallback, pinentry prompting, and `0600` output
   permissions. Only a human-facing wrapper was missing.

The release that introduces these subcommands also moves the crate
onto **wecanencrypt 0.16.2** (from 0.15.0) and **libtumpa 0.4.2**
(from 0.3.2). 0.16.2 is the wecanencrypt release whose encrypt /
decrypt surface (`encrypt_bytes_to_multiple`,
`sign_and_encrypt_to_multiple`, the card `sign_and_encrypt_*` /
`decrypt_and_verify_*` entry points) is what these wrappers build on.

## Decision

Add two human-facing subcommands to `tcli`, mirroring the
`tcli sign` / `tcli verify` precedent.

### Command shape

```
tcli encrypt <FILE> -r <FP|KEYID|EMAIL>... [--sign-with <ID>] [--binary] [-o OUT]
tcli decrypt <FILE> [-o OUT]
```

- `encrypt` requires at least one `-r`/`--recipient` (clap `required =
  true`). The flag is repeatable for multiple recipients, matching
  `gpg -r` and `tclig -r`.
- `encrypt` defaults to **ASCII-armored** output written to a sibling
  `<FILE>.asc`. `--binary` switches to binary OpenPGP written to
  `<FILE>.gpg`. `-o PATH` overrides the destination; `-o -` writes to
  stdout. `<FILE> = -` reads plaintext from stdin and then requires
  `-o` (there is no input filename to derive a default from).
- `--sign-with <ID>` produces a single sign-then-encrypt message
  (one-pass-signature + literal + signature, the same packet shape as
  `gpg --sign --encrypt`). The signing leg is card-first (a connected
  card holding the signer's key signs on-card), software secret key
  with passphrase as fallback.
- `decrypt` writes plaintext to **stdout** by default; `-o PATH` writes
  a file with `0600` permissions. `<FILE> = -` reads ciphertext from
  stdin. Decryption is card-first (a connected card holding the
  decryption subkey), software secret key as fallback.

### Specific design decisions

**1. Reuse the `gpg::*` crypto core; do not reimplement.** This is the
same blast-radius bound ADR 0009 decision 9 applied to the subcommand
redesign: the parsing/UI layer is new, the secret-handling code is
not. To make `gpg::encrypt` reusable from a caller that picks its own
destination (sibling file *or* stdout), the core was split into two
public helpers: `prepare_recipients` resolves recipients (emitting any
`INV_RECP` status lines) and `encrypt_bytes_prepared` runs the
card-first sign-then-encrypt dispatch and **returns** the ciphertext
instead of writing a fixed path. The GPG-shape `encrypt_with_status`
now calls `prepare_recipients` then `encrypt_bytes_prepared`, so
`tclig` behaviour is byte-for-byte unchanged. The split also lets the
human-facing `tcli encrypt` resolve recipients (and fail on an unknown
one) *before* it reads plaintext, so a bad recipient never blocks on
stdin; that path passes a sink for the status writer because
`INV_RECP` is a machine protocol, not human output. `tcli decrypt`
calls `gpg::decrypt::decrypt` directly — that function already takes an
`Option<output>` and writes stdout or a `0600` file, exactly the human
shape.

**2. Armored by default, `--binary` to opt out.** This inverts
`tclig`'s default (binary, `-a` to armor). A human encrypting a file
to email or paste it wants armored text far more often than a binary
blob; `tcli sign` already defaults to armored `.asc` for the same
reason. The `--binary` flag name matches `tcli sign --binary` /
`tcli export --binary`, so the modifier reads the same across every
`tcli` verb.

**3. Sibling-file defaults: `.asc` armored, `.gpg` binary.** Mirrors
GnuPG's own sibling conventions and `tcli sign`'s `<FILE>.asc` /
`<FILE>.sig` defaults. The destination logic (`encrypt_destination`)
is a near-copy of `sign_cmd::sign_destination`, deliberately, so the
two human verbs derive output paths identically.

**4. `--sign-with`, not `--signer`.** `tcli sign` uses `--signer` for
"the key that signs". For `encrypt` the signing key is a *secondary*,
optional role layered onto encryption, so the flag is named for what
it does to the message (`--sign-with`) rather than reusing `--signer`,
which would read as "the primary subject of the command". The value
grammar (fingerprint / key ID / email) is identical.

**5. `decrypt` does not emit human signature status.** When the
payload is a sign-then-encrypt message, `tcli decrypt` recovers the
plaintext but does not currently print "Good signature from X". The
GPG-shape `gpg::decrypt::decrypt_and_verify` does surface the inner
signature, but only as `[GNUPG:]` machine lines. A human-readable
decrypt-and-report-signature path (the decrypt analogue of
`tcli verify`) is deferred to a follow-up rather than shipped half-
formed here. `tcli decrypt` is scoped to "recover the plaintext";
verifying a signature is `tcli verify`'s job.

**6. No new flag at the parent level.** Like every other `tcli`
subcommand, `encrypt`/`decrypt` inherit only the global
`--keystore`/`TUMPA_KEYSTORE`. No operation-specific flag is hoisted
to the top level.

## Consequences

### Positive

- **The human/machine split is now complete.** Every cryptographic
  operation has a human verb on `tcli` and a GPG-shape form on
  `tclig`: sign/verify (ADR 0009) and now encrypt/decrypt. The
  documentation no longer has to send `tcli` users to `tclig` for a
  daily operation.

- **Better defaults for interactive use.** Armored output, a derived
  sibling path, a "wrote ciphertext to X" confirmation, and a
  readable error when a recipient has no key — none of which `tclig`
  offers, because `tclig` is tuned for machine callers.

- **Card-first parity for free.** Because the wrappers reuse the
  `gpg::*` core, `tcli encrypt --sign-with <card-key>` and
  `tcli decrypt` of a message addressed to a card subkey get the same
  YubiKey/Nitrokey dispatch as the `tclig` path, with no duplicated
  card code.

- **Bounded blast radius.** The only change to existing crypto code is
  the split of `prepare_recipients` + `encrypt_bytes_prepared` out of
  `encrypt_with_status`; all
  existing `gpg::encrypt` tests still exercise `encrypt_with_status`
  and pass unchanged.

### Negative

- **Two grammars for encrypt/decrypt, like sign/verify before it.**
  Developers and power users now have `tcli encrypt` *and* `tclig -e`,
  with different defaults (armored vs. binary). This is the same cost
  ADR 0009 accepted for the verb split; it is the price of keeping
  `tclig` a faithful `gpg` drop-in while giving humans good
  ergonomics.

- **`tcli decrypt` is silent about inner signatures.** A user who
  decrypts a signed-and-encrypted message gets the plaintext but no
  signature confirmation, which a GnuPG user might expect from a
  single `gpg -d`. Mitigated by decision 5's scoping and the deferred
  follow-up; the message can still be verified explicitly.

- **`--sign-with` vs. `--signer` asymmetry.** The signing key is named
  `--signer` on `tcli sign` but `--sign-with` on `tcli encrypt`. The
  distinction is deliberate (decision 4) but is one more thing to
  remember.

## Alternatives Considered

### Point `tcli encrypt` users at `tclig`

Add no new subcommand; document `tclig -e` / `tclig -d` as the way to
encrypt from `tcli`. Cheapest. Rejected: it cements the
inconsistency — humans would use `tcli` for everything except the one
operation that drops to the machine binary — and forces
human-hostile defaults (binary output, mandatory `-o`, `INV_RECP`
lines) on interactive users.

### One `tcli crypt` subcommand with a direction flag

A single verb (`tcli crypt --encrypt` / `--decrypt`) was considered.
Rejected: it does not match the existing `tcli sign` / `tcli verify`
shape (two verbs, not one verb with a mode flag), and the flag sets
for the two directions barely overlap (`-r`/`--sign-with`/`--binary`
are encrypt-only), so a single command would carry flags that are
errors half the time — exactly the silently-ignored-modifier footgun
ADR 0009 set out to remove.

### Reuse `--signer` for the signing key on `encrypt`

Considered for symmetry with `tcli sign --signer`. Rejected per
decision 4: on `encrypt`, signing is an optional secondary role, and
`--sign-with` reads more clearly as "additionally sign with" than
`--signer` would.

### Make `tcli decrypt` verify and report the inner signature

Considered shipping the decrypt-and-report-signature path now, so
`tcli decrypt` of a signed+encrypted message prints "Good signature
from X" like `tcli verify` does for detached/inline signatures.
Deferred (decision 5): doing it well means a human-shape translation
of the inner-signature outcome (Good / Bad / Unsigned / UnknownKey)
that `gpg::decrypt` currently only emits as `[GNUPG:]` lines, and
shipping a half-formed version is worse than scoping `decrypt` to
plaintext recovery for now.

## Follow-ups

- Add a human-readable inner-signature report to `tcli decrypt` (the
  decrypt analogue of `tcli verify`), translating
  `DecryptVerifyOutcome` into the same "Good signature from … / BAD
  signature / Unknown signer" lines `verify_cmd` prints. Tracked from
  decision 5.
- When shell completions are regenerated, confirm the new `encrypt` /
  `decrypt` subcommands and their flags appear (clap-generated for
  `tcli`, so this is automatic, but worth a spot-check).

## References

- ADR 0005: Split GPG-compat Flags into a Separate `tclig` Binary
  (parent decision: human `tcli` vs. machine `tclig`).
- ADR 0009: `tcli` Subcommand Grammar (establishes the verb shape and
  the "UI layer changes, secret-side code does not" blast-radius
  bound that this ADR follows for encrypt/decrypt).
- `src/gpg/encrypt.rs` (`prepare_recipients` + `encrypt_bytes_prepared`
  shared core),
  `src/gpg/decrypt.rs` (`decrypt`), `src/encrypt_cmd.rs`,
  `src/decrypt_cmd.rs` (the human-facing wrappers).
