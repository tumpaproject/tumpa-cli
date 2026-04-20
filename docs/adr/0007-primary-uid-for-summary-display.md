# ADR 0007: Primary UID for Single-Line Key Summaries

## Status

Accepted

## Date

2026-04-17

## Context

`tcli --search <query>` and `tcli --fetch <email>` (and a couple of other
one-line display paths) show one UID per key, to keep the output compact
and shell-friendly. The previous implementation picked the UID with
`key.user_ids.first()` — i.e. whichever UID the keystore (or `rpgp`'s
parser) happened to hand back first.

For keys with multiple UIDs the "first" UID is the first one serialized
into the key packet, not the one the owner has marked primary. OpenPGP
keys explicitly carry a **Primary User ID** subpacket on one UID's
self-signature (RFC 9580 §5.2.3.27), and GnuPG, Sequoia, and every other
OpenPGP tool surface that UID as the headline when they need to pick
exactly one. `tcli --info` and `tcli --desc` already do the right thing
— they filter out revoked UIDs, sort `is_primary` first, and tag the
chosen one with `[primary]`.

This caused a confusing asymmetry reported by Kushal (see
session transcript 2026-04-17):

```
❯ tcli --search kushaldas
pub A85FF376759C994A8A1168D8D8219C8C43F6C5E1 Kushal Das <kushal@fedoraproject.org>

❯ tcli --info A85FF376759C994A8A1168D8D8219C8C43F6C5E1
     UIDs:
       [primary] Kushal Das <mail@kushaldas.in>
                 Kushal Das <kushal@fedoraproject.org>
                 ... (4 more)
```

Same key, same command-line tool, two different "headline" UIDs.

## Decision

Introduce a private `summary_uid(&[UserIDInfo]) -> &str` helper in
`src/keystore.rs` and use it for every single-line key summary. The
selection rules are:

1. Non-revoked UID with `is_primary == true`.
2. Else the first non-revoked UID in serialization order.
3. Else the first UID in serialization order (all UIDs revoked — show
   *something* so users can still identify the key).
4. Else the literal string `<no UID>`.

`find()` rather than `max_by_key()` is used because the stdlib
`max_by_key` returns the **last** tied element on a tie, which for a
key with no primary-flagged UID would surface the *last* serialized
UID rather than the first. The test suite pins this behaviour.

Current call sites using the helper:

- `cmd_search` — `--search` output line.
- `cmd_fetch` — the "Imported / Updated / Unchanged" line printed
  after a WKD fetch.

`print_key_info` (used by `--info` / `--desc`) already had its own
"primary first" sort for the multi-line UID listing and is left alone.

## Consequences

### Positive

- `--search` headline UIDs now match the `[primary]` line shown by
  `--info` for the same key.
- The helper keeps the selection logic in one place; if another
  single-line display path is added, it picks up the correct behaviour
  by calling `summary_uid`.
- Revoked UIDs no longer mask live ones even if they still carry a
  stale `is_primary` flag from an older self-signature.

### Negative

- When a user searches on a substring that only matches a *non-primary*
  UID (e.g. `tcli --search fedoraproject`), the displayed headline UID
  will *not* contain the substring the user typed — it will be the
  primary UID instead. This matches `gpg --list-keys` behaviour
  (GnuPG's `--list-keys` also shows only the primary UID per entry)
  and is considered correct, but is worth calling out because it can
  read as "tcli printed the wrong match" at a glance.
- Keys with zero non-revoked UIDs fall back to the first revoked UID.
  This is a deliberate degenerate-case affordance so the fingerprint
  isn't printed in total isolation; `--info` still shows the revoked
  state if the user wants the full picture.

## Alternatives Considered

### Surface the matching UID when the primary doesn't match the query

We could try to echo back whichever UID actually matched the search
substring (so `--search fedora` would show `kushal@fedoraproject.org`
even though the primary is `mail@kushaldas.in`). Rejected: the
keystore search returns `Vec<KeyInfo>` with no record of *which* UID
matched, and GnuPG sets the precedent of always showing the primary.
Showing the primary also keeps the display of a key stable regardless
of how the user happened to find it.

### Use `max_by_key(is_primary)` without sorting

First attempt. The test suite caught that `max_by_key` returns the
last tied element — so a key with no `is_primary == true` UID would
display the *last* serialized UID rather than the first. Replaced
with `find` + chained `or_else` fallbacks for an unambiguous
preference order. The test
`summary_uid_falls_back_to_first_non_revoked_when_no_primary` pins
this.

### Leave `cmd_import` / `cmd_delete` call sites on `.first()`

`cmd_import` (the "Imported/Updated/Unchanged" line after a
`tcli --import`) and `cmd_delete` (the confirmation prompt) have
the same `user_ids.first()` pattern. They were left alone for this
change to keep the fix scoped to what the reported bug covers. A
future cleanup can route them through `summary_uid` too; the helper
is designed for that.
