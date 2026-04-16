# ADR 0002: Merge Certificates on Re-Import

## Status

Accepted

## Date

2026-04-16

## Context

When a user imports a key that already exists in the tumpa keystore,
the previous behavior was to skip it entirely with the message
"Skipping ... already imported". The same applied to WKD fetches:
if the key was already present, `tcli --fetch` refused with "Key
already in keystore."

This was wrong for two common workflows:

1. **Expiry renewal.** A contact renews their key's expiry and
   publishes the updated certificate to their WKD or sends the
   updated file. The user runs `tcli --fetch` or `tcli --import`
   to pick up the new expiry, but the old behavior silently
   discarded the update.

2. **Third-party certifications.** A contact's certificate
   accumulates new certifications over time (e.g., from key-signing
   parties). Importing the updated certificate should add these
   signatures to the stored copy.

3. **New subkeys.** A contact adds a new encryption or signing
   subkey. The stored certificate needs the new subkey and its
   binding signatures to encrypt to it.

The underlying wecanencrypt library now provides a proper
`merge_keys()` function (as of v0.9.0) that performs packet-level
certificate merging with signature deduplication, following the
same algorithm as rpgpie/rsop.

## Decision

Replace the skip-on-duplicate logic with merge-on-duplicate:

1. **`tcli --import`**: When the fingerprint already exists in the
   keystore, export the stored certificate, merge the new data into
   it via `wecanencrypt::merge_keys`, and re-import the result.
   Report "Updated ... merged new signatures" if the merge produced
   changes, or "Unchanged ... no new data" if identical.

2. **`tcli --fetch`**: When the fetched key already exists, prompt
   "Key already in keystore. Merge updates?" instead of refusing.
   On confirmation, merge the WKD response into the stored cert.

3. Both paths use a shared `merge_and_reimport()` helper that
   handles export-merge-reimport and returns whether any data
   changed.

## Consequences

### Positive

- Renewed expiry, new certifications, new subkeys, and new UIDs
  from updated certificates are now picked up automatically.
- Re-importing the same unchanged file is harmless (reports
  "Unchanged").
- Consistent behavior between file import and WKD fetch.

### Negative

- A slightly malformed certificate that previously would have been
  silently skipped now triggers a merge attempt that may fail with
  an error. This is preferable to silently discarding data.
- The merge is append-only for signatures. Stale self-signatures
  are not pruned, but this is correct because the wecanencrypt
  policy layer uses "latest self-signature wins" semantics (see
  wecanencrypt ADR-0001) to evaluate key flags and expiry from
  the merged result.

## Alternatives Considered

### Always overwrite (INSERT OR REPLACE) with the new data

This is what `keystore.import_cert()` does internally. However,
blindly replacing means a partial certificate (e.g., one fetched
from a keyserver that strips some UIDs) would lose data that the
stored copy has. Merge preserves the union of both.

### Merge only on explicit `--force` flag

Rejected because the common case (refreshing a key) should work
without extra flags. The merge is safe and append-only, so there
is no reason to require opt-in.
