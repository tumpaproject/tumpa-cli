# ADR 0009: `tcli` Subcommand Grammar (Replacing Flag-as-Verb)

## Status

Accepted

## Date

2026-04-26

## Context

Through 0.3.x, `tcli` exposed roughly fourteen top-level actions as
GPG-style `--long-flags`:

```
tcli --list-keys
tcli --import key.asc
tcli --export FP -o key.asc
tcli --info FP
tcli --desc file.asc
tcli --delete FP
tcli --search QUERY [--email]
tcli --fetch EMAIL [--dry-run]
tcli --sign FILE --with-key X
tcli --sign-inline FILE --with-key X
tcli --verify FILE [--signature SIG] [--with-key PUBKEY]
tcli --card-status
tcli --list-cards
tcli --show-socket [TYPE]
tcli --upload-to-card FP --which X --include-signing/encryption/auth
tcli --reset-card
tcli --completions SHELL
```

Three real subcommands (`agent`, `ssh-agent`, `ssh-export`) were grafted
on alongside this. The result was a 1395-line `src/cli.rs` whose
`TryFrom<Args> for Mode` validator (lines 334–691 in the old shape) was
essentially one long apology for the mix: every action flag had to be
mutually-exclusion-checked against every other action flag, and the
modifier flags (`--armor`, `--binary`, `--output`, `--recursive`,
`--force`, `--dry-run`, `--email`) were silently ignored by actions
they did not apply to instead of being rejected.

The shape produced concrete bugs and footguns:

1. **`--with-key` was overloaded.** For `--sign` / `--sign-inline` the
   value was a signer ID (fingerprint, key ID, or email) looked up in
   the keystore. For `--verify` the same flag was a path to a public-key
   file. The `value_name = "SIGNER|PUBKEY_FILE"` tacitly admitted the
   conflation. A user typing
   `tcli --verify msg.txt --signature msg.sig --with-key alice@example.com`
   got "no such file" rather than a keystore lookup.

2. **`--armor` was dead code.** `keystore::cmd_export` declared the
   parameter as `_armor: bool` and never read it. Armoring was already
   unconditional unless `--binary` was set, so the documented
   `--armor` flag did literally nothing.

3. **A documented invocation did not parse.** README line 369
   advertised `tcli --search --email user@example.com` for email
   search. Because `--search` takes a `String` value, clap consumed
   `--email` as the query token, refused (correctly) to use a flag-
   shaped string as the value, and aborted. The example had been
   broken since the flag was added.

4. **Modifiers silently ignored.** `tcli --list-keys --recursive`,
   `tcli --info FP --binary`, `tcli --export FP --force` and similar
   combinations parsed cleanly and dropped the modifier. The
   sign/verify family rigorously rejected stray modifiers; the
   key-management family did not.

5. **`--show-socket` had a magic optional value.** `--show-socket`
   alone meant "GPG socket"; `--show-socket ssh` meant "SSH socket".
   Implemented via `num_args = 0..=1` and `default_missing_value =
   "gpg"`. Hard to discover, brittle when followed by another flag.

6. **`--info` vs. `--desc` were the same verb on two sources.**
   Users had to remember which one read the keystore (`--info`) and
   which read a file (`--desc`).

7. **Hidden flags the docs referenced.** `--force` was `hide = true`
   despite being documented. The (separately motivated) experimental
   surface added another bundle of `hide = true` flags whose syntax
   only lived in code.

The design also had a structural problem: every guard in
`TryFrom<Args> for Mode` existed precisely because the natural
flag-and-subcommand dispatch order would otherwise silently swallow
an action flag. The mix of flag-actions and subcommands was
fundamentally ambiguous, and the validator was an apology for that
mix rather than a clarifying check.

A self-review of the change set (see
`DIFFERENTIAL_REVIEW_TCLI_SUBCOMMAND_REDESIGN_2026-04-26.md`) also
surfaced a real safety regression in an early draft: the new
`tcli card upload FP` subcommand defaulted `--signing-from` to
`primary`, which silently bypassed `select_sign_target`'s
ambiguity-fails-closed check and caused the destructive (factory-
resetting) card-write to choose the primary key on certificates
that had both a sign-capable primary and a sign-capable signing
subkey. The fix-forward is part of this redesign and is recorded
here so it does not regress.

## Decision

Replace the flag-as-verb grammar with subcommands. Drop the pre-0.4
`--flag` forms entirely; clap rejects them as unknown arguments.

### Top-level command tree

```
tcli list                                   # was --list-keys
tcli import [FILE...] [-r|--recursive]      # was --import + positional
tcli export <FP> [-o FILE] [--binary]       # was --export
tcli describe <FP|KEYID|FILE>               # merged --info + --desc
tcli delete <FP> [-f|--force]               # was --delete
tcli search <QUERY> [--email]               # was --search; --email is a modifier
tcli fetch <EMAIL> [--dry-run]              # was --fetch
tcli sign <FILE> --signer <ID> [-o] [--binary]
tcli sign-inline <FILE> --signer <ID> [-o]
tcli verify <FILE> [--signature SIG] [--key-file PUBKEY]
tcli card status                            # was --card-status
tcli card list                              # was --list-cards
tcli card upload <FP> [--card-ident I] [--signing-from primary|sub]
                       [--with encryption,authentication]   # experimental
tcli card reset [--card-ident I] [-y|--yes]                 # experimental
tcli socket [gpg|ssh]                       # was --show-socket [TYPE]
tcli agent [--ssh] [-H SOCK] [--cache-ttl SECS]
tcli ssh-agent -H SOCK
tcli ssh-export <FP> <PUBKEY_FILE>
tcli completions <SHELL>                    # was --completions SHELL
```

The only flag that lives at the parent level is `--keystore <PATH>`
(also exposed as the `TUMPA_KEYSTORE` env variable). It is `global =
true` so it works before any subcommand.

### Specific design decisions

**1. Hierarchy is hybrid.** Common verbs (`list`, `import`, `export`,
`sign`, `verify`, `describe`, `delete`, `search`, `fetch`) stay flat.
Card and agent operations group under nouns (`card status`, `card
upload`). This mirrors `gh` and `cargo`: shallow tree for the daily
verbs, grouped tree for the operationally distinct surfaces.

**2. No deprecation cycle for the old flag forms.** Pre-0.4 invocations
fail with clap's standard `error: unexpected argument '--list-keys'
found`. The deprecation alias path (`mode_from_deprecated`,
`deprecation_warning`) was implemented in an earlier draft and
removed in the same release. The reasoning: tumpa-cli is at 0.4 with a
small user base; carrying a deprecation surface adds two to four
hundred lines of translation logic to `cli.rs` for a release window
during which we have no released-version users to protect. Future
rename cycles, when the tool has an installed base, will use proper
deprecation aliases.

**3. `tcli ssh-agent` and `tcli agent --ssh` are different commands.**
This was not obvious from the pre-0.4 shape. Tracing the code:

- `tcli ssh-agent -H sock` calls `ssh::run_agent(host, keystore)`
  (`src/ssh/mod.rs:14`). It binds the SSH socket and nothing else: no
  GPG cache listener, no GPG PID file, no `~/.tumpa/agent.sock`.
- `tcli agent --ssh -H sock` calls `agent::run_agent(ssh = true, ...)`
  (`src/agent/mod.rs:84`). It binds `~/.tumpa/agent.sock` for the GPG
  passphrase cache, writes the GPG PID file, and spawns the SSH agent
  on the side.

The split is load-bearing: the shipped systemd units in
`contrib/systemd/` rely on it. `tumpa-agent.service` runs the
combined process; `tumpa-gpg-agent.service` runs only the GPG cache;
`tumpa-ssh-agent.service` runs only the SSH agent. The three units
are declared `Conflicts=` because the combined and SSH-only services
both bind `$XDG_RUNTIME_DIR/tcli-ssh.sock`. Removing `ssh-agent`
would have broken the SSH-only path with no equivalent in the new
grammar.

`ssh-agent` is therefore exposed as a real, visible top-level
subcommand, not a hidden alias.

**4. `--with-key` is split.** Sign-side becomes `--signer`
(fingerprint / key ID / email). Verify-side becomes `--key-file`
(path to a public key). Each flag has one meaning in one place. The
overloaded value-name is gone.

**5. `card upload --signing-from` has no default.** The flag is
`Option<SigningFrom>`. When the user does not pass it and the
certificate carries both a sign-capable primary and a signing
subkey, `mode_from_card` translates the absent flag to `which =
None`. `select_sign_target` (`src/upload_card.rs:233`) then errors
and asks the user to pick. This preserves the fail-closed safety
property of the experimental upload — a destructive, irreversible
operation does not get to silently choose between two equally-
plausible occupants of the card's signing slot. An earlier draft of
this redesign gave the flag a `default_value = "primary"`, bypassing
the ambiguity check; that regression was caught in self-review and
fixed before merge.

**6. `--armor` is removed entirely.** It was a no-op. `cmd_export`
no longer takes the parameter; the documented behaviour (armored
unless `--binary`) is preserved.

**7. `describe` auto-detects FP vs. file by lexical check.** A 40-
or 16-hex-character argument is treated as a keystore lookup;
anything else is treated as a path. A file literally named
`ABCDEF...` (40 hex) can be forced into file mode by writing
`./ABCDEF...`, since clap keeps the leading `./`. The check is
purely lexical (no filesystem stat) so it is deterministic and does
not depend on what is on disk at call time.

**8. `card upload --with` accepts a comma list.** Slot names are
parsed by clap's `value_delimiter = ','`. The flag has fixed
`num_args = 1`, so the positional `FP` argument floats freely:
`tcli card upload --signing-from sub --with encryption,authentication
FP` and `tcli card upload FP --signing-from sub --with
encryption,authentication` parse identically. A variadic
`num_args = 1..` would have eaten the positional; we deliberately
do not use it.

**9. The `Mode` dispatch enum is unchanged for non-experimental
variants.** All cryptographic and key-handling handlers
(`keystore::cmd_*`, `sign_cmd::*`, `verify_cmd::*`, `agent::*`,
`upload_card::*`) take the same inputs they took before. Only the
parsing layer changed. This bounds the blast radius of the redesign:
the trust boundary moved, but the code on the secret side did not.
The two changes downstream are surgical: `cmd_export` lost its
unused `_armor: bool` parameter, and `Mode::SshAgent` is restored
verbatim from pre-0.4 (the early draft had dropped it; see decision
3 above).

## Consequences

### Positive

- **`--help` is small and self-explanatory.** Top-level help lists
  fifteen named commands. Each command has its own `--help` page with
  only the flags relevant to that command. The pre-0.4 help dumped
  ~25 flags into a single screen with no grouping.

- **Validator collapses to clap.** `TryFrom<Args> for Mode` shrinks
  from ~360 lines of mutual-exclusion guards plus a 380-line
  deprecation translator (combined ~740 lines) to ~150 lines of
  per-subcommand match arms. `cli.rs` overall went from ~1395 lines
  to ~822 lines.

- **No silently-ignored modifiers.** `--binary` only exists on the
  subcommands that use it (`export`, `sign`). `--recursive` only
  exists on `import`. `--email` only on `search`. clap rejects
  misuse at parse time with a clear "unexpected argument" message.

- **No more `--with-key` overload.** Verify-side and sign-side flags
  have one meaning each. The footgun
  `tcli verify msg.txt --signature msg.sig --with-key alice@example.com`
  no longer exists; the new shape rejects `--with-key` and the user
  reaches for `--key-file`.

- **`tcli search QUERY --email` parses.** The previously-broken
  README example works as written; modifier flags compose with
  positional arguments without ordering traps.

- **`card upload` fails closed on ambiguity.** Destructive,
  irreversible operations require an explicit choice when two
  occupants are plausible.

- **Positional arguments float.** `tcli card upload --signing-from sub
  --with encryption,authentication FP` works as well as
  `tcli card upload FP --signing-from sub --with
  encryption,authentication`. clap places the positional wherever it
  fits between the flags.

### Negative

- **No deprecation aliases.** Anyone who carried a `tcli --list-keys`
  habit, a `tcli --sign FILE --with-key X` script, or a shell wrapper
  invoking the old form has to migrate at the 0.4 upgrade. Mitigation:
  README and `docs/usage.md` are updated to the new shape, and the
  pre-0.4 README example for `--search --email` was already broken,
  so the migration cost is bounded by what users had actually been
  running successfully.

- **Two binaries with two grammars.** `tclig` (the GPG drop-in for
  git and pass) keeps its `gpg`-style flags forever — git, pass, and
  every other GPG-shape consumer cannot move. Reading the codebase,
  developers now have to remember which binary uses which shape:
  `tcli` = subcommands, `tclig` = GPG flags. ADR 0005 already
  separated the two binaries; this ADR cements the grammar
  difference.

- **`describe` auto-detect is heuristic.** A 40-character hex string
  that happens to be a valid file path is read as a keystore lookup,
  not a file. The `./` escape is documented, but the case is
  surprising on first encounter. Acceptable because the misroute is
  read-only ("info about a key in your keystore" or "key not found"),
  not destructive.

- **Loss of the `--include-signing`-specific error message.** In the
  pre-0.4 shape, a user passing `--include-signing` against a cert
  with no signing subkey got an error that named the flag explicitly.
  The new shape's `tcli card upload FP --signing-from sub` falls
  through to `select_sign_target`'s generic message at
  `src/upload_card.rs:222`, which currently still references the old
  flag names (`--which primary`). The error remains correct in
  intent but suggests deprecated remediation. Tracked as LOW-2 in
  the differential review and queued for a follow-up sweep of the
  `select_sign_target` error texts.

## Alternatives Considered

### Keep the flag-as-verb shape

Cheapest in lines of code; preserves muscle memory for any user
running 0.3.x. Rejected: every concrete bug listed in the Context
section is structural to the flag shape. The validator-as-apology
keeps growing as new actions are added, and silently-ignored
modifiers are a documented footgun pattern. The cost is paid every
time someone reads or extends `src/cli.rs`.

### Hidden deprecated aliases for one cycle

Drafted and implemented (deprecation warnings to stderr, hidden
fields in `Args`, translation in `mode_from_deprecated`). Removed in
the same release for the reasons in decision 2. If `tcli` had an
installed base on a stable major version, the deprecation surface
would have been retained.

### Subcommand for SSH-only via `agent ssh-only` rather than top-level

Considered grouping the SSH-only daemon under `agent` (e.g.
`tcli agent ssh-only -H sock`). Rejected: the systemd unit names and
ADR 0001 already use `tcli ssh-agent`, and the SSH-only mode is
operationally a peer of `agent`, not a sub-mode of it (it does not
share the agent's GPG cache socket or PID file). A nested form would
have changed the systemd unit `ExecStart` line for no architectural
gain.

### Auto-detect `describe` source by file existence (stat-based)

Considered: if the argument exists as a file, treat it as a file;
otherwise treat as a fingerprint. Rejected: making the decision
depend on the filesystem makes the same `tcli describe ABCDEF...`
invocation behave differently across machines (or across `cd`
boundaries). The lexical heuristic is deterministic and
reproducible. The `./ABCDEF...` escape is the explicit override.

### Variadic `--with` on `card upload`

`#[clap(num_args = 1..)]` would have allowed `--with encryption
authentication` (space-separated), matching shell idiom. Rejected:
clap's variadic value collector greedily consumes subsequent tokens
until it sees the next `--flag`, which would have eaten the
positional `FP`. Comma-separated single-value (`value_delimiter =
','`) keeps positional float working. `cargo --features a,b` and
`clippy --allow a,b` both follow the same convention.

## Follow-ups

- Sweep `select_sign_target` error texts in `src/upload_card.rs` to
  reference `--signing-from` instead of the deprecated `--which` /
  `--include-signing`. Tracked as LOW-2 in the differential review.
- When `tpass` next gets a CLI revision, reconsider whether its
  pre-existing subcommand grammar should also adopt the
  `--keystore` global pattern that `tcli` now uses.
- If the experimental card surface graduates and a real installed
  base appears, the next major rename cycle should ship with proper
  deprecation aliases (a feature dropped from this release).

## References

- ADR 0001: SSH Agent Support (defines the `ssh-agent` semantics
  preserved here).
- ADR 0004: systemd User Service (consumes the three-binary split:
  combined / GPG-only / SSH-only).
- ADR 0005: Split GPG-compat Flags into a Separate `tclig` Binary
  (parent decision: this ADR is the follow-up grammar redesign of
  the human-facing `tcli`).
- ADR 0008: Experimental Commands Gated by Cargo Feature (relevant
  for `card upload` / `card reset`, which are still
  `#[cfg(feature = "experimental")]`).
- `DIFFERENTIAL_REVIEW_TCLI_SUBCOMMAND_REDESIGN_2026-04-26.md`
  (self-review of this redesign with the MEDIUM-1 finding that
  motivated decision 5).
