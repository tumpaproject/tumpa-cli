# ADR 0004: systemd User Units for the Tumpa Agent

## Status

Accepted

## Date

2026-04-17

## Context

`tcli agent` and `tcli ssh-agent` are long-running processes that
should be up for every interactive session on a Linux workstation.
Users coming from GnuPG expect a login-time launch story equivalent
to `gpg-agent --daemon` (spawned lazily by its wrapper) or
`ssh-agent -s` (wired into `~/.bashrc` or `.xinitrc`). Neither model
translates cleanly to the tumpa agent:

- `gpg-agent`'s Assuan auto-start ("no running gpg-agent → spawn one")
  is baked into `gpgme`/`gpgsm`; nothing else on the system consults
  `~/.tumpa/agent.sock`, so there is no place to hook a lazy spawn.
- Shell-rc launchers (`eval $(ssh-agent)`) only bring the agent up in
  interactive TTYs. Users with systemd-managed graphical sessions,
  `sudo` invocations, cron, `at`, editor plugins that spawn
  subprocesses from a DE launcher, or non-login shells don't inherit
  the exported env vars, and the agent stays unstarted.

The agent handles secrets (passphrase cache, private-key operations
on software keys, card PIN caching). It must therefore:

1. Run as the user — never root, never with elevated privileges.
2. Restart automatically on crash.
3. Be startable/stoppable without a full session re-login.
4. Expose its sockets at predictable, documented paths so the shell
   env (`SSH_AUTH_SOCK`) can be wired up once and reused.

Three operating modes exist today (see `src/cli.rs` `SubCommand::Agent`
and `SubCommand::SshAgent`):

| Mode         | Invocation                           | GPG passphrase cache | SSH agent |
|--------------|--------------------------------------|:---:|:---:|
| Combined     | `tcli agent --ssh`                   | ✓   | ✓   |
| GPG only     | `tcli agent`                         | ✓   | —   |
| SSH only     | `tcli ssh-agent -H unix://…`         | —   | ✓   |

Not all users want both. A workstation that uses `tcli` for git
signing but keeps ssh keys on a YubiKey run through `openpgp-card-ssh-agent`
wants the GPG-only variant. A CI-ish server that only ever does
non-interactive ssh signing wants the SSH-only variant. Shipping a
single unit with all three cases baked in would force everyone onto
the combined mode.

## Decision

Ship three systemd **user** units under `contrib/systemd/`, one per
mode, and **let the user pick exactly one** via `Conflicts=`.

### 1. Unit scope: user, not system

All three units install into `~/.config/systemd/user/` and enable
against `default.target`. System units were considered and rejected:

- They run as root (or a dedicated service account), but every socket
  path the tumpa agent uses is `$HOME`- or `$XDG_RUNTIME_DIR`-relative.
  A system unit either bakes in a single user (not portable) or
  needs a template plus a complex bind-mount to simulate the user
  session.
- Secret material — passphrase cache, card PIN cache — belongs to the
  user, not to a system daemon. System units weaken this.

### 2. Three files, one active at a time

- `tumpa-agent.service` — `tcli agent --ssh -H unix://%t/tcli-ssh.sock`
- `tumpa-gpg-agent.service` — `tcli agent`
- `tumpa-ssh-agent.service` — `tcli ssh-agent -H unix://%t/tcli-ssh.sock`

The combined unit carries `Conflicts=tumpa-gpg-agent.service
tumpa-ssh-agent.service`; each single-purpose unit carries
`Conflicts=tumpa-agent.service`. Switching variants is a single
`systemctl --user enable --now tumpa-<x>.service` — systemd stops the
outgoing unit first. This prevents two agents from fighting over the
same socket path (both the GPG-only and combined variants would
otherwise try to bind `~/.tumpa/agent.sock`).

### 3. No socket activation — yet

systemd socket activation (`tumpa-agent.socket` owning the listener,
handing the fd to the service on first connection) is the idiomatic
choice for agent-style workloads. We do not ship it in this ADR
because:

- The code at `src/agent/mod.rs::run_agent` calls
  `UnixListener::bind(&socket_path)` directly. Socket activation
  requires the agent to parse `LISTEN_FDS` / `LISTEN_PID` per
  `sd_listen_fds(3)` and adopt the inherited fd via
  `UnixListener::from_raw_fd`. That is a code change, not a packaging
  change.
- The same is true of `src/ssh/mod.rs::run_agent` — it uses
  `ssh-agent-lib`'s `bind()`, which internally creates the listener.
  Socket activation would need upstream support or a wrapper.
- Lazy spawn is a performance optimisation, not a correctness
  requirement. `tcli agent` idle-CPU cost is negligible (a tokio
  runtime and a 60s cache-sweep tick).

Socket activation is tracked as a follow-up; the fd-inheritance code
change is the blocker. When it lands, a `.socket` companion file can
be added to each `.service` without touching the user's workflow
(systemd supports socket activation transparently once both files
are present).

### 4. Hardening knobs

Every unit sets:

```
MemoryDenyWriteExecute=true
NoNewPrivileges=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
RestrictSUIDSGID=true
```

These are cheap and standard. We deliberately do **not** set:

- `PrivateTmp=true` — pinentry GUIs sometimes look at `$TMPDIR` and a
  private-tmp namespace breaks `pinentry-gtk-2` / `pinentry-qt`
  prompts.
- `ProtectHome=read-only` — the agent must write to `~/.tumpa/`.
- `SystemCallFilter=@system-service` — card operations use `ioctl`
  paths through PC/SC that overlap with non-default syscall groups;
  a filter strict enough to be useful would need careful auditing
  and per-backend exemptions.

These are candidates for a future hardening pass, not rejected
outright.

### 5. Binary path is a hard-coded `%h/.cargo/bin/tcli`

User-scoped units have no reliable `PATH` lookup — the inherited
`PATH` in a systemd user manager is minimal and varies by distro.
Every documented install route (`cargo install tumpa-cli`, Homebrew
on Linux, distro packages) ends up with one of:

- `%h/.cargo/bin/tcli` — `cargo install`
- `/usr/local/bin/tcli` — manual / brew on some distros
- `/usr/bin/tcli` — distro package

We pick the `cargo install` path as the default and document
`systemctl --user edit --full <unit>` for the other two in
`contrib/systemd/README.md`. An alternative was to ship three copies
of each unit (one per path) or an install script that detects the
binary; both felt like over-engineering for a one-line edit.

### 6. `SSH_AUTH_SOCK` wiring lives in `environment.d`

The SSH socket path is predictable (`$XDG_RUNTIME_DIR/tcli-ssh.sock`),
but the shell still has to know it. Rather than spelling it out in
each unit via `systemctl --user set-environment` (which doesn't
persist) or relying on `.bashrc`/`.zshrc` hacks, the README points
users at a single `~/.config/environment.d/tumpa-ssh-agent.conf`
drop-in:

```
SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/tcli-ssh.sock
```

systemd reads `environment.d` into the user manager at session start,
so every shell spawned by the user manager inherits it. This is the
same pattern `gnome-keyring-daemon` uses.

## Consequences

### Positive

- Login-start, crash-recover behaviour without any shell-rc surgery.
- User-scoped — no root, no privilege ladder, no cross-user leakage.
- Clean mode switching: `systemctl --user enable --now …` on the
  chosen variant, let `Conflicts=` handle the rest.
- Distro-agnostic — works identically on Debian/Ubuntu/Fedora/Arch/
  openSUSE user sessions.
- Hardening knobs are on by default; opt-out is a unit override, not
  a code change.

### Negative

- Hard-coded binary path in `ExecStart=` needs a one-line edit for
  users whose binary isn't at `~/.cargo/bin/tcli`.
- Not every Linux distro runs the systemd user manager — users on
  `runit`/`s6`/`openrc` need their own equivalent. Units are
  systemd-specific by design; a `runit` `run` script is outside
  scope.
- No socket activation yet — the agent is always on, even when idle.
  Cost is negligible but not zero.
- macOS users get nothing from this (no systemd). A `launchd` plist
  is a separate contribution; Homebrew packaging already covers the
  common case.

## Alternatives Considered

### Single unit with a parameter / `Environment=MODE=gpg|ssh|both`

Simpler on the filesystem (one file), but conditional `ExecStart`
branches don't exist in a single-file systemd unit. Would require
either a wrapper shell script (added surface for injection / PATH
issues) or using multiple `ExecStart=` lines with `Conditional*=`
checks, which aren't granular enough. Three files is clearer.

### System unit with `User=%i` via template instantiation

`tumpa-agent@alice.service` works mechanically but shifts admin
burden onto root and complicates per-user pinentry / DISPLAY. System
units for inherently per-user daemons is the classic anti-pattern
that `systemctl --user` was introduced to avoid. Rejected.

### Socket activation now, with wrapper binary

Write a small `tcli-systemd-shim` that accepts `LISTEN_FDS` and
forwards the fd to the main agent via an argv flag. Rejected:
introduces a new binary just for packaging, duplicates the privilege
profile, and drifts from the documented `tcli agent` invocation.
Proper fix is to teach `run_agent` itself to adopt fd 3 when
`LISTEN_FDS=1` is set; tracked as a code follow-up.

### Use `EnvironmentFile=` to pass mode (`--ssh` vs not)

Reduces three units to one plus a config file. Footgun: the config
file's presence/absence determines which sockets get bound, which is
non-obvious from `systemctl status`. Three distinct units makes the
choice explicit in the unit name.

## References

- `systemd.unit(5)`, `systemd.service(5)`, `systemd.exec(5)` — unit
  and sandbox directive semantics.
- `systemd.special(7)` — `default.target`,
  `graphical-session-pre.target`.
- `environment.d(5)` — per-user environment drop-ins.
- `sd_listen_fds(3)` — socket activation protocol (for future
  follow-up).
- ADR 0001: SSH Agent Support — defines `tcli ssh-agent`.
- ADR 0003: On-Demand Card Identity Cache — sensitive cache state
  lives in the agent, reinforcing user-scoped running.
