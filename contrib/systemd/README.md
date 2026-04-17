# systemd user units for tumpa-cli

Three ready-to-use **user-scoped** units for running the `tcli` agent at
login on Linux. Pick one variant — they are mutually exclusive via
`Conflicts=`, so systemd will stop whichever is running before it
starts a different one.

| Unit                          | Runs                       | GPG socket            | SSH socket                              |
|-------------------------------|----------------------------|-----------------------|-----------------------------------------|
| `tumpa-agent.service`         | `tcli agent --ssh`         | `~/.tumpa/agent.sock` | `$XDG_RUNTIME_DIR/tcli-ssh.sock`        |
| `tumpa-gpg-agent.service`     | `tcli agent`               | `~/.tumpa/agent.sock` | —                                       |
| `tumpa-ssh-agent.service`     | `tcli ssh-agent -H …`      | —                     | `$XDG_RUNTIME_DIR/tcli-ssh.sock`        |

`$XDG_RUNTIME_DIR` is usually `/run/user/$UID` on Linux.

## Install

```bash
mkdir -p ~/.config/systemd/user
cp contrib/systemd/*.service ~/.config/systemd/user/
systemctl --user daemon-reload
```

## Adjust the binary path

Every unit calls `%h/.cargo/bin/tcli`, which is where `cargo install
tumpa-cli` puts the binary. If yours is elsewhere (`/usr/local/bin/tcli`,
`/usr/bin/tcli`, a pkgsrc path, …), edit the `ExecStart=` line:

```bash
systemctl --user edit --full tumpa-agent.service
```

## Enable the combined agent (recommended)

```bash
systemctl --user enable --now tumpa-agent.service
systemctl --user status tumpa-agent.service
```

You should see `Agent listening on "/home/<user>/.tumpa/agent.sock"`
and `SSH_AUTH_SOCK=/run/user/<uid>/tcli-ssh.sock;` in the journal.

To tail the journal:

```bash
journalctl --user -u tumpa-agent.service -f
```

## Enable a single-purpose variant

```bash
systemctl --user enable --now tumpa-gpg-agent.service   # GPG only
# or
systemctl --user enable --now tumpa-ssh-agent.service   # SSH only
```

Swapping between variants is safe — `Conflicts=` makes systemd stop
the currently-running one first.

## Point your shell at the SSH socket

Create `~/.config/environment.d/tumpa-ssh-agent.conf` with:

```
SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/tcli-ssh.sock
```

systemd reads `environment.d` into the user session at login, so new
shells (bash, zsh, fish — anything started by the systemd user
manager) see `SSH_AUTH_SOCK`. Re-login, or `systemctl --user
daemon-reexec` and reopen your terminal, for it to take effect.

Existing TTY shells that predate the change can be fixed one-off:

```bash
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/tcli-ssh.sock"
```

Verify with:

```bash
ssh-add -L
```

## Optional: environment overrides

Each unit loads `~/.config/tumpa/env` if it exists. Good fit for:

```
PINENTRY_PROGRAM=/usr/bin/pinentry-gnome3
TUMPA_KEYSTORE=/home/alice/keys-alt.db
RUST_LOG=info
```

**Do not** put `TUMPA_PASSPHRASE=…` here — it defeats the pinentry
prompt and puts your passphrase in a file readable by anyone who
compromises your account.

## Troubleshooting

**Service fails immediately with `Failed to bind …agent.sock`.**
An earlier `tcli agent` is still running, or another agent left a
stale socket. Check with `ps -fC tcli` and `ls ~/.tumpa/`. If stale,
remove the socket and PID file:
```bash
rm ~/.tumpa/agent.sock ~/.tumpa/agent.pid
```

**SSH still uses `gpg-agent` or the default `ssh-agent`.**
`SSH_AUTH_SOCK` in your current shell points somewhere else. Print it
(`echo $SSH_AUTH_SOCK`). Either log out and back in (so
`environment.d` takes effect) or export it manually per the section
above.

**`systemctl --user status` shows `code=exited, status=203/EXEC`.**
systemd can't find `tcli` — the ExecStart path is wrong. Edit the unit
and point it at your binary (`which tcli`).

**Agent runs fine but card PINs aren't prompted.**
`PINENTRY_PROGRAM` isn't set, or its binary doesn't exist. Set it in
`~/.config/tumpa/env` and restart the service.

## Uninstall

```bash
systemctl --user disable --now tumpa-agent.service
rm ~/.config/systemd/user/tumpa-*.service
systemctl --user daemon-reload
```
