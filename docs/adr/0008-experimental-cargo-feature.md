# ADR 0008: Experimental Commands Gated by Cargo Feature, Not Runtime Flag

## Status

Accepted

## Date

2026-04-19

## Context

tumpa-cli grew a handful of card-management commands that were not
ready for general users:

- `tcli --upload-to-card <FP>` with `--which primary|sub` — writes a
  secret key from the keystore into the signing slot of a connected
  OpenPGP card.
- `tcli --reset-card` — blocks the admin PIN and issues TERMINATE DF +
  ACTIVATE FILE to factory-reset the card.

Both are destructive: they move or wipe key material, consume admin
PIN retries, and interact directly with smart-card APDUs in a code
path that is still stabilizing. A user who stumbles onto them without
understanding the consequences can brick a production YubiKey or
overwrite the only copy of a signing subkey.

The first iteration gated them behind a runtime `--experimental` flag:

```
tcli --experimental --upload-to-card <FP> --which primary
```

Without `--experimental` the commands rejected with an explanatory
error. The flags were also marked `hide = true` so they did not appear
in `--help`.

This was weak:

- The flags were still present on every built binary, just hidden.
  A grep through the binary, strings-style introspection, shell
  completions, or a copied command line from a developer's terminal
  immediately exposed them.
- The rejection was a single `if !value.experimental { return Err(...) }`
  check. One local patch or one mis-merged branch would ungate them.
- Release engineers who package tcli for end users (Debian, AUR,
  Homebrew) had no way to *remove* the experimental surface from
  their builds. They had to trust that the runtime gate stayed in
  place.
- Code for the experimental commands — PCSC transactions, key-material
  extraction — compiled into every build and added attack surface even
  for users who had no intention of running those commands.

## Decision

Promote the gate from runtime to compile time via a Cargo feature.

```toml
[features]
default = []
experimental = []
```

All experimental code is annotated `#[cfg(feature = "experimental")]`:

- The `upload_card` module in `src/lib.rs`.
- The `--upload-to-card`, `--which`, and `--reset-card` fields of
  `cli::Args`.
- The `Mode::UploadToCard` and `Mode::ResetCard` variants of the
  dispatch enum.
- The `WhichKey` re-export in `src/cli.rs`.
- The `upload_card` import and the two match arms in `src/main.rs`.
- The experimental dispatch block inside `TryFrom<Args> for Mode`.

The runtime `--experimental` opt-in flag is removed. On a feature
build the experimental commands are available unconditionally; on a
default build they do not exist at all — clap rejects them as
`unexpected argument`, and no experimental code is linked into the
binary.

Distributors package default builds. Developers and the CI that
exercises Stage B of `test_upload_card.sh` opt in with
`cargo build --features experimental`.

## Consequences

### Positive

- **Strong separation.** End-user binaries compile without a single
  line of experimental code. Runtime introspection, shell
  completions, and `--help` all agree: the commands do not exist.
- **No accidental activation.** There is no "forgot to pass a flag"
  footgun; a default-built tcli physically cannot run
  `--upload-to-card`.
- **Distributor-friendly.** Packagers get a clear contract: ship the
  default build. If they want the experimental surface they
  explicitly opt in and own the support implications.
- **Smaller attack surface.** PCSC transactions, key-material
  extraction, and factory-reset APDU sequences are absent from
  default builds.
- **Dual-mode CI.** CI builds and lints both configurations, so drift
  between them is caught on every PR:
    1. `cargo build` / `cargo clippy -- -D warnings` (default build
       stays green for users).
    2. `cargo build --features experimental` /
       `cargo clippy --features experimental -- -D warnings` (the
       experimental build is the one `test_upload_card.sh` drives).

### Negative

- **Two compilation shapes to maintain.** Every change that touches
  the experimental surface must keep both cfgs compiling. `cfg`-gated
  variants can hide bugs until the feature is enabled. Mitigation:
  both clippy invocations run in CI, and `cfg`-gated code is small
  and localized to four files.
- **Tests must know which build they are running against.**
  `test_upload_card.sh` has a preflight probe that runs
  `tcli --upload-to-card 0000…` and inspects the output: the default
  build errors with `unexpected argument` (exit the test with a
  rebuild hint), the feature build errors with `key not found` (fall
  through to Stage A). This is slightly less elegant than a runtime
  flag check, but it is honest about what the binary actually
  supports.
- **Not expressible in `--help`.** The commands are hidden even on
  feature builds (`hide = true`). Users who read `tcli --help` on a
  feature build won't discover them without the README or the
  developer docs.

## Alternatives Considered

### Keep the runtime `--experimental` flag

Kept the code simple but provided no real guarantee: flags were still
compiled in, rejection was one `if` line, and packagers had no way to
remove the surface. Rejected as insufficient.

### Separate binary (`tcli-experimental`)

Cleanest in theory — release engineers never even see the
experimental code path — but requires duplicating the agent bring-up,
keystore plumbing, and argument parsing for a very small number of
commands. The experimental surface is expected to shrink as commands
graduate, so carrying a whole second binary is too much overhead.

### Cfg by `debug_assertions` (debug-only)

Would restrict experimental commands to `cargo build` but leak them
into any release build that happened to keep debug assertions on
(e.g. `opt-level = 3` + `debug-assertions = true`). Also makes the
commands unavailable for real smart-card testing, which needs
optimized crypto. Rejected.

### `cfg(env = ...)` / build-time env var

Would gate on an environment variable at build time. Equivalent in
effect to a Cargo feature, but non-idiomatic and invisible in
`Cargo.toml`. Rejected in favour of the standard feature pattern.

## Follow-ups

- When an experimental command graduates, drop its `#[cfg(feature =
  "experimental")]` guards and remove the corresponding section from
  this ADR's scope. No Cargo.toml change required until the last
  experimental command graduates, at which point the feature entry
  itself can go.
- Consider a similar gate for other future stress-test surfaces (for
  example, admin-PIN change UIs or multi-card operations) to keep
  the `experimental` feature as the single opt-in.
