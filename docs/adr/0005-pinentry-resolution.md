# ADR 0005: Pinentry Resolution Order and Startup Probe

## Status

Accepted

## Date

2026-04-17

## Context

`tcli` delegates passphrase and card-PIN prompts to an external
pinentry program via the Assuan protocol (see `src/pinentry.rs`).
`get_passphrase` walks four sources in order: agent cache, the
`TUMPA_PASSPHRASE` env var, a pinentry program, and finally a
terminal prompt via `rpassword`.

The pinentry step is the one an interactive user actually sees.
On Linux a single `pinentry` binary — chosen by distribution
alternatives — dispatches to gtk/qt/curses as appropriate, so the
previous policy of trying `pinentry` first and `pinentry-mac` as a
macOS fallback matched the expected environment.

On macOS the picture is different:

- Homebrew installs two distinct binaries. `pinentry` is a curses
  program that needs a controlling TTY. `pinentry-mac` draws a
  native AppKit dialog and works with no TTY.
- The SSH agent is typically spawned by launchd, by a shell-init
  rc file, or by a desktop launcher. In every one of those paths
  the process has no TTY.
- Launchd in particular inherits only the minimal system PATH
  (`/usr/bin:/bin:/usr/sbin:/sbin`). Homebrew's `/opt/homebrew/bin`
  (Apple Silicon) or `/usr/local/bin` (Intel) are not on it.

The previous implementation tried `pinentry` first. On any dev
machine that had both installed, that meant curses pinentry was
invoked in a no-TTY context, errored out, and the `?` operator on
`try_pinentry_with` propagated the error out of the candidate
loop before `pinentry-mac` was ever reached. `get_passphrase`
silently fell through to the terminal prompt, which the agent
serves from *its own* stdin — effectively dead, or worse,
indistinguishable from the agent working fine until the user
tried to actually sign something.

The failure was invisible in two ways:

1. No log line indicated which pinentry had been chosen, so
   diagnosing "it prompted on STDIN even though pinentry-mac is
   installed" required reading the source.
2. The `?` cascade meant one broken candidate masked all later
   candidates, even when a later one would have worked.

## Decision

Three coordinated changes in `src/pinentry.rs` and
`src/ssh/agent.rs`.

### 1. Candidate order: `pinentry-mac` first on macOS

`pinentry_candidates()` now returns, on macOS:

```
pinentry-mac
/opt/homebrew/bin/pinentry-mac
/usr/local/bin/pinentry-mac
pinentry
```

- Bare `pinentry-mac` is first so a normal interactive install is
  picked up with no magic.
- The two Homebrew absolute paths follow so that an agent with a
  launchd-reduced PATH still resolves the binary without the user
  having to configure `PINENTRY_PROGRAM` or edit launchd plists.
- Bare `pinentry` is last. It is kept so that users who rely on a
  non-macOS pinentry (e.g. `pinentry-tty` symlinked as `pinentry`)
  on a macOS host still have it reachable.

`PINENTRY_PROGRAM`, when set, still takes precedence and is the
only candidate. An explicit override is always authoritative.

On Linux the only default remains `pinentry`, since distributions
supply a single multiplexed binary.

### 2. Tolerant candidate loop

`try_pinentry` now distinguishes three outcomes per candidate:

- `Ok(Some(pass))` — success, return.
- `Ok(None)` — spawn failed (binary not found). Fall through to
  the next candidate.
- `Err(e)` — the candidate ran but the conversation failed. If
  the error is user cancellation, bubble it out (the user has
  already made a decision; do not prompt again on a different
  pinentry). Otherwise log at `debug` and fall through.

This is the core behaviour change. A broken or TTY-less curses
pinentry no longer masks a working `pinentry-mac`. User intent
(cancellation) is still preserved, so we do not silently retry
through three dialogs when the user clicks "Cancel" once.

### 3. Startup probe

`TumpaBackend::new` and `::with_cache` call
`log_pinentry_at_startup()`, which runs `resolve_pinentry()` —
a pure-Rust PATH walk (`which_on_path`) that mirrors `which(1)`
without shelling out — and logs one of:

- `info`: `pinentry: using <name> (resolved to <abs path>)`.
- `warn`: nothing resolved on PATH, with the inherited `PATH`
  value and a one-line fix hint.

Resolution happens once per agent startup, so the cost is
negligible and the log line is the first thing an operator sees
when debugging a "why did it prompt on STDIN" report. The
probe's resolved path is not cached for runtime use: the actual
pinentry invocation still iterates the candidate list at prompt
time, because an operator may install pinentry while the agent
is running and we want to pick it up without a restart.

## Consequences

### Positive

- On a stock `brew install pinentry-mac` + launchd-managed
  `tcli` setup, the GUI dialog appears on the first passphrase
  prompt with no configuration.
- The agent log now answers "which pinentry is in use" in one
  line at startup, converting a class of silent misrouting
  failures into obvious log-visible failures.
- The tolerant loop means future pinentry additions (e.g.
  `pinentry-touchid`, `pinentry-1password`) can be inserted
  without worrying about one broken candidate bricking the
  whole chain.
- `PINENTRY_PROGRAM` override semantics are unchanged, so
  existing users who already pin a specific binary see no
  behaviour change.

### Negative

- The hard-coded Homebrew prefixes are macOS-filesystem trivia
  leaking into source. If Homebrew relocates its prefix they
  become dead entries. The mitigation is cheap: drop or amend
  the strings. The alternative — calling `brew --prefix` at
  startup — is strictly worse (subprocess, slow, unreliable
  under launchd's reduced PATH, doesn't help users without
  brew).
- The startup probe reads `PATH`. If `PATH` genuinely is empty
  at probe time but is later populated (e.g. the operator
  extends `launchctl setenv PATH` mid-session), the probe
  warning will be stale. This is acceptable because the
  runtime candidate loop still picks up the newly available
  binary — the startup log is a diagnostic, not a gate.
- A curses-only macOS install (deliberately uncommon but
  possible) now prompts through `pinentry` rather than
  `pinentry-mac`. Users in that configuration set
  `PINENTRY_PROGRAM=pinentry` explicitly.

### Neutral

- No new dependencies. `which_on_path` is ~10 lines of
  std-only code; adding a `which` crate for a single
  resolution was considered and rejected as out of scope.
- The change is source-only. No config migration, no plist
  change, no user action required on upgrade.

## Alternatives considered

1. **Shell out to `which pinentry-mac` at startup.** Rejected.
   A subprocess is slower than a PATH walk, and under launchd
   the subprocess inherits the same reduced PATH, so the
   lookup yields the same answer we would have gotten in-process.

2. **Patch launchd plists to extend PATH.** Rejected. Requires
   every operator to edit a plist; does not help users who
   start the agent from a shell; bypasses Homebrew-specific
   install-prefix knowledge instead of encoding it.

3. **Ship a bundled pinentry.** Rejected. Vastly out of scope;
   a PGP tool has no business redistributing a UI dialog
   program; existing pinentry-mac is actively maintained.

4. **Remove `pinentry` from the macOS default list entirely.**
   Rejected. Some users deliberately symlink `pinentry-tty` or
   `pinentry-curses` to `pinentry` for SSH-over-terminal
   workflows; keeping it reachable as a last-resort candidate
   preserves that path.
