# ADR 0003: On-Demand Card Identity Cache for SSH Agent

## Status

Accepted (supersedes background poller approach)

## Date

2026-04-16

## Context

Each SSH authentication hop requires the agent to determine which
connected OpenPGP card (if any) holds the requested authentication
key. The original implementation did full card enumeration inline on
every `request_identities()` and `sign()` call:

1. `list_all_cards()` — enumerates connected cards (1 card SELECT)
2. `get_card_details()` per card — reads fingerprints, cardholder
   name, signature counter (3 more SELECTs per card)
3. Keystore lookup + SSH pubkey extraction

Card operations are slow (~60ms per SELECT over PC/SC). There is no
caching at any layer — not in PC/SC, not in `card-backend-pcsc`, not
in `openpgp-card`. Every call is a full hardware round-trip.

With 1 card connected, each SSH hop did 7+ SELECTs for detection and
signing combined. A jumphost connection (2 hops) did 14+.

A background poller approach was considered but rejected because it
adds a continuously running thread that polls the card every 2 seconds
even when idle, and `ssh-add -L` would show stale data for up to 2
seconds after a card insert.

## Decision

Use an on-demand card identity cache with change detection:

### Startup

Full card enumeration once. Cache the mapping of SSH pubkey to
card ident, cardholder name, and comment. Store the set of known
card idents for change detection.

### `request_identities()`

Call `list_all_cards()` (1 SELECT — the cheapest card operation).
Compare the returned ident set against the cached set:

- **Same set**: return cached card identities immediately (0
  additional SELECTs)
- **Different set**: full re-enumeration via `refresh_card_identities()`
  (4 SELECTs per card), update cache, clear stale PINs

Then append software key identities from the keystore.

### `sign(request)`

Look up `request.pubkey` in the cached identity list:

- **Cache hit**: sign directly with the matched card (3 SELECTs
  for `ssh_authenticate_on_card` — unavoidable)
- **Cache miss**: call `refresh_card_identities()` (maybe a new
  card was just plugged in), retry lookup. If still no match,
  fall back to software keys.

### PIN cache invalidation

`refresh_card_identities()` compares the new card ident set against
the previous one and clears cached PINs for removed cards.

## Performance

### Card SELECT operations per SSH hop (1 card connected)

| Operation | Original | On-demand cache |
|-----------|----------|-----------------|
| `request_identities()` | 4+ SELECTs | 1 (change check only) |
| `sign()` detection | 4+ SELECTs | 0 (cache hit) |
| `ssh_authenticate_on_card()` | 3 SELECTs | 3 SELECTs |
| **Total per hop** | **7+** | **4** |
| **Jumphost (2 hops)** | **14+** | **8** |

### Steady state (same cards connected)

- `request_identities()`: 1 SELECT (`list_all_cards` for change check)
- `sign()`: 0 SELECTs (cache hit)
- No background thread, no polling when idle

### Card event (add/remove/swap)

- Detected on next `request_identities()` call (1 SELECT for check +
  4 SELECTs for full re-enum)
- Or detected on `sign()` cache miss (full re-enum + retry)

## Consequences

### Positive

- SSH authentication latency reduced by ~200ms per hop (3 fewer
  SELECTs at ~60ms each)
- No background thread — zero card I/O when the agent is idle
- `ssh-add -L` always shows current card state (triggers change
  check on every call)
- Multi-card setups work correctly: cached mapping resolves which
  card holds which SSH key without per-request full enumeration
- Sign cache miss handles late card insertion gracefully

### Negative

- `request_identities()` still does 1 SELECT per call (the
  `list_all_cards` change check). This is the minimum possible
  without a background thread.
- A card inserted between `request_identities()` and `sign()` is
  handled by the sign cache-miss path (full re-enum), adding ~250ms
  to that specific sign operation. This is rare in practice.

## Alternatives Considered

### Background poller thread

A `tokio::spawn` task polling every 2 seconds, caching results for
request handlers to read with zero card I/O. Achieves 3 SELECTs per
hop (vs 4 for on-demand) but:
- Continuously polls the card even when idle
- `ssh-add -L` shows stale data for up to 2 seconds after card insert
- More complex code (async poller, `spawn_blocking`, timer management)

The 1 extra SELECT per hop (on-demand vs poller) is ~60ms — not worth
the complexity and idle overhead of a background thread.

### Event-driven card detection (PC/SC notifications)

PC/SC supports `SCardGetStatusChange` for card insertion/removal
events. Would eliminate all polling. Rejected because the
`card-backend-pcsc` crate doesn't expose this API.

## References

- [OpenPGP Card Specification](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
- PC/SC SELECT timing: ~60ms per round-trip on YubiKey 5
