# ADR 0005: Split GPG-compat Flags into a Separate `tclig` Binary

## Status

Accepted

## Date

2026-04-17

## Context

The `tcli` binary served two distinct audiences from a single entry
point:

1. **Humans** who run `tcli --import key.asc`, `tcli --list-keys`,
   `tcli --desc file.asc`, `tcli --card-status`, `tcli agent`, etc.
2. **Other programs** — `git` (via `git config gpg.program tcli`),
   `pass` (via `ln -s tcli gpg2`), and anything else expecting a
   GPG drop-in — that invoked `tcli` with flags like `-bsau`,
   `--verify`, `-e`, `-d`, `--list-keys --with-colons`,
   `--decrypt --list-only`, plus a large pile of accepted-and-
   ignored compat flags (`--quiet`, `--yes`, `--batch`,
   `--compress-algo`, `--no-encrypt-to`, `--keyid-format`,
   `--status-fd`, `--default-key`, `--use-agent`, `--no-secmem-
   warning`, `--no-permission-warning`, `-v`, `--list-config`).

The two audiences disagreed on what flags mean and what `--help`
should look like:

- `--list-keys` alone is useful human output; `--list-keys
  --with-colons` is the machine-parsed GnuPG colon format that
  `pass` greps.
- GPG-compat flags must be present so `pass` and `git` don't break,
  but they clutter `tcli --help` for humans.
- `src/cli.rs` had ~50 clap fields, roughly half of which existed
  only because some external caller sent them.

Hiding flags behind `#[clap(hide = true)]` reduces noise in
`--help`, but every clap field still participates in the parser's
disambiguation and error messages, and each one is another thing a
human reading the codebase has to skip past when trying to
understand the native CLI surface.

## Decision

Split `tumpa-cli` into two binaries within the same crate:

- **`tcli`** — native, human-facing. Commands: `--import`,
  `--export`, `--info`, `--desc`, `--delete`, `--search`,
  `--fetch`, `--list-keys` (human-readable), `--card-status`,
  `--show-socket`, `--completions`, `agent` / `ssh-agent` /
  `ssh-export` subcommands, `--keystore`.

- **`tclig`** — GPG drop-in, program-facing. Flags: `-b`, `-s`,
  `-u`, `--verify`, `-e`, `-r`, `-d`, `-a`, `-o`, `--list-keys
  --with-colons`, `--list-secret-keys --with-colons`,
  `--decrypt --list-only`, `--list-config`, `--default-key`, plus
  all 11 accepted-and-ignored compat flags, positional
  `input_files`, `--keystore`, `--completions`.

Layout:

```
src/
  main.rs        tcli entry point
  cli.rs         tcli clap Args + Mode
  tclig/
    main.rs      tclig entry point
    cli.rs       tclig clap Args + Mode
  tpass/         (unchanged)
  gpg/           (unchanged — now only called from tclig)
  store.rs, pinentry.rs, keystore.rs, agent/, ssh/, cache.rs
                 (shared via lib.rs; both binaries use them)
```

`Cargo.toml` gains one `[[bin]]` entry:

```toml
[[bin]]
name = "tclig"
path = "src/tclig/main.rs"
```

### Shared flags are redeclared, not shared at the type level

Both `Args` structs carry their own `--keystore`, `--output`,
`--armor`, `--list-keys`, and positional `input_files`. The two
parsers don't share a common base struct. This intentional
duplication keeps each binary's CLI independent — `tcli`'s
`--list-keys` means "human format"; `tclig`'s `--list-keys` means
"GPG colon format". A shared base would force the same semantics on
both.

Code-wise, the dispatch targets (`store::*`, `pinentry::*`,
`keystore::*`, `agent::*`, `ssh::*`, `gpg::*`) are all in `lib.rs`
and reached via `tumpa_cli::*` from both binaries.

### `src/gpg/` stays put, `tclig` calls into it

The `gpg::sign`, `gpg::verify`, `gpg::encrypt`, `gpg::decrypt`,
`gpg::keys` modules don't move. They continue to live under
`src/gpg/` and are re-exposed via `pub mod gpg;` in `lib.rs`. Only
the callers move: the eight dispatch arms that used to be in
`src/main.rs` now live in `src/tclig/main.rs`. `tcli` no longer
reaches into `tumpa_cli::gpg::*` at all.

### `--verify` moves to `tclig` only (for now)

Standalone `tcli --verify file.sig` was plausible for humans who
wanted to verify a signature without `git`. We drop it from `tcli`
in this change. A native `tcli --verify` can be reintroduced later
if demand surfaces; it would share the same
`gpg::verify::verify` function.

## Consequences

### Positive

- `tcli --help` goes from ~50 flags to ~18. Humans reading it see
  only the commands that are for them.
- `tclig` is a stable, narrow GPG-compat surface. Future GPG-compat
  additions (new ignored flags, new modes) don't touch the human
  CLI.
- Each binary has its own `name` in clap, which shows up correctly
  in `--help` examples and generated shell completions.
- `tests/test_pass.sh` symlinks `$TCLIG` as `gpg2`; the real-world
  workload now exercises exactly the binary users will install.

### Negative

- Users upgrading who had `git config gpg.program tcli` or a `gpg2`
  symlink pointing at `tcli` get "unknown option --verify" on next
  use. A migration note at the top of `README.md` and a
  Troubleshooting entry in `docs/usage.md` carry the fix: re-point
  at `tclig`.
- `Cargo.toml` grows one `[[bin]]`. `cargo build` compiles both.
- Shared flags (`--keystore`, `--output`, `--armor`,
  `--list-keys`, positional `input_files`) are declared in both
  `Args` structs, not shared. Future additions to shared flags
  need to touch both.
- Shell completions must be generated for both binaries.
  `tcli --completions <shell>` and `tclig --completions <shell>`
  both exist; users have to run both if they want both.

## Alternatives Considered

### Single binary with a `gpg` subcommand (`tcli gpg -bsau …`)

Would break `gpg.program` drop-in compatibility. `git`'s
`gpg.program` is invoked with flags like `--detach-sign --armor -u
… -bsau`, not with a leading `gpg` subcommand. Making it work
would require a wrapper shell script or an `exec` shim, adding a
new install artifact and failure mode.

### Feature flag (`--features gpg-compat`)

A compile-time toggle doesn't help at runtime — a published binary
must always accept the GPG flags, because the user doesn't control
the compilation. The problem is flag ergonomics, not binary size.

### Keep everything in `tcli`, hide GPG flags with `#[clap(hide =
true)]` (status quo)

Already done for many of the ignored compat flags. `--help` is
cleaner, but `cli.rs` still carries 50 fields; the parser still
has to disambiguate them; reading the codebase is still noisy;
error messages still reference the hidden flags when a typo
matches one. Split solves all four.

### Separate crate for `tclig`

Keeping `tclig` in a sibling crate (`tclig/Cargo.toml`) would let
it evolve independently. Rejected because it means a second
`Cargo.toml` to maintain, a second path dep on `wecanencrypt`, and
a second `cargo publish` step — for code that's tightly coupled to
the keystore and pinentry plumbing in the existing `tumpa-cli`
crate. A second `[[bin]]` in the same crate is much cheaper.

## References

- ADR 0001 (SSH Agent Support) — set the precedent for adding new
  CLI surfaces as subcommands / bins within the same crate.
- `tests/test_pass.sh` — the integration contract for GPG-compat
  behaviour. After this change it symlinks `$TCLIG`, not `$TCLI`,
  as `gpg2`.
- `src/gpg/` — dispatch targets, unchanged by this split.
- commit history of the `tclig`-split change for per-file diffs.
