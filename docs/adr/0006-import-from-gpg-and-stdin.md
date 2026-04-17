# ADR 0006: Import Directly From GnuPG and Stdin

## Status

Accepted

## Date

2026-04-17

## Context

Users migrating to `tcli` typically already have keys in GnuPG's
keyring. The obvious migration path is `gpg --export` piped or
process-substituted into `tcli --import`:

```
tcli --import <(gpg --export)
gpg --export | tcli --import -
```

Two problems made this unreliable:

1. **Multi-key blobs.** `gpg --export` (with no arguments) emits a
   concatenated binary stream of every public key in the GnuPG
   keyring. The previous `import_file` read the whole file,
   called `wecanencrypt::parse_key_bytes` (single key), and passed
   the raw bytes to `keystore.import_key` (also single key). Only
   the first key landed in the tumpa keystore; the rest were
   silently discarded.

2. **Stdin wasn't wired.** `tcli --import` only accepted paths.
   Piping keys in required a temporary file. Process substitution
   (`<(gpg --export)`) happened to work because bash exposes the
   pipe as `/dev/fd/N`, which `std::fs::read` can open — but that
   still hit the single-key bug above.

## Decision

Rework `tcli --import` so a single invocation handles a stream of
one or many OpenPGP keys, coming from files, directories, process
substitution, or stdin.

1. **Iterate with `pgp::composed::PublicOrSecret::from_reader_many`.**
   The `rpgp` crate already provides a streaming parser that handles
   mixed public/secret, armored/binary input and returns one key at
   a time. `import_file` now reads the bytes, hands them to a new
   `import_blob` helper, and that helper iterates every key in the
   stream. Each key is serialized back to bytes (`to_writer`) and
   passed through the existing single-key merge-or-import path.

2. **Accept `-` as stdin.** `cmd_import` treats a path of `-` as
   "read a keyring from stdin". An empty positional list also
   defaults to stdin, so `gpg --export | tcli --import` works
   without the trailing `-`.

3. **Process substitution falls out for free.** `<(gpg --export)`
   resolves to `/dev/fd/N`; `std::fs::read` opens that fd and reads
   until EOF, and the new multi-key loop picks up every key in the
   pipe.

4. **Preserve existing behaviour for files and directories.** A
   single-key `.asc`/`.pub`/`.gpg` file still follows the same
   per-key merge-or-import logic, including the "Unchanged" /
   "Updated — merged new signatures" messages from ADR 0002.
   Directory recursion (`--import dir/ --recursive`) is unchanged.

## Consequences

### Positive

- Migrating from GnuPG is a one-liner:
  `tcli --import <(gpg --export)` or
  `gpg --export | tcli --import`.
- Keyring files with multiple keys (as produced by `gpg --export`,
  `sq export`, `pg-pack`, or concatenation) are fully imported
  instead of truncating after the first key.
- Each key inside a multi-key stream participates in the existing
  merge-on-duplicate flow (ADR 0002). Refreshing an entire
  keyring's expiries is a single command.
- Stdin support composes with Unix pipelines without a temporary
  file (`curl ... | tcli --import -`).

### Negative

- A single malformed key inside an otherwise valid multi-key stream
  is reported as failed and skipped; the remaining keys still
  import. The final summary counts it under `failed`. We consider
  this strictly better than aborting the whole import on one bad
  key, and noisier than the previous silent truncation.
- `from_reader_many` buffers the full input before iterating. For
  very large keyrings this uses more memory than a true streaming
  parser would, but in practice even a several-thousand-key GnuPG
  ring is on the order of tens of MB.

## Alternatives Considered

### Extend `wecanencrypt::parse_keyring_bytes`

`wecanencrypt` already exposes `parse_keyring_bytes`, but it only
handles `SignedPublicKey::from_reader_many` and would reject a
`gpg --export-secret-keys` stream. Using `PublicOrSecret::from_reader_many`
directly in tumpa-cli handles both cases with no change to
wecanencrypt.

### Require an explicit `--stdin` flag

Rejected. `-` as stdin is a universal Unix convention, and we
already accept `input_files` positionally. Defaulting to stdin
when no paths are given matches `gpg --import` behaviour, which
users migrating from GnuPG already expect.

### Split-and-loop at the tumpa-cli level

We could have written our own "find the next key packet boundary"
scanner to slice a multi-key blob into individual key byte slices.
Rejected in favour of `from_reader_many`, which is already
battle-tested inside `rpgp` and handles both armored and binary
inputs uniformly.
