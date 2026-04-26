#!/bin/bash
# Integration test for `tcli sign / sign-inline / verify`.
#
# Prerequisites:
#   - tcli built (cargo build)
#   - At least one secret signing-capable key in the tumpa keystore.
#     Provision a throwaway one with tests/provision_test_key.sh.
#   - TUMPA_PASSPHRASE set for non-interactive runs.
#
# Usage:
#   TUMPA_PASSPHRASE="passphrase" ./tests/test_sign_verify.sh [FINGERPRINT]
#
# If FINGERPRINT is omitted, the first secret key in the keystore is used.
# To run against a fully throwaway key + keystore, do:
#
#   export TUMPA_KEYSTORE=$(mktemp -d)/keys.db
#   export TUMPA_PASSPHRASE=testpass
#   fp=$(./tests/provision_test_key.sh)
#   ./tests/test_sign_verify.sh "$fp"

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TCLI="$PROJECT_DIR/target/debug/tcli"

if [[ ! -x "$TCLI" ]]; then
    echo "ERROR: tcli not found at $TCLI"
    echo "Run 'cargo build' first."
    exit 1
fi

if [[ -z "${TUMPA_PASSPHRASE:-}" ]]; then
    echo "ERROR: TUMPA_PASSPHRASE must be set for non-interactive testing."
    exit 1
fi

# Pick a key fingerprint and primary email.
if [[ -n "${1:-}" ]]; then
    KEY_FP="$1"
else
    KEY_FP=$("$TCLI" list 2>/dev/null \
        | grep "^sec" \
        | head -1 \
        | awk '{print $2}')
fi
if [[ -z "$KEY_FP" ]]; then
    echo "ERROR: no secret key in keystore. Run tests/provision_test_key.sh first."
    exit 1
fi

# Try to extract the first email from the key info; used for --signer EMAIL
# coverage. Fall back to skipping the email cases if we can't find one.
KEY_EMAIL=$("$TCLI" describe "$KEY_FP" 2>/dev/null \
    | grep -oE '<[^>]+@[^>]+>' \
    | head -1 \
    | tr -d '<>')

echo "Using key: $KEY_FP"
[[ -n "$KEY_EMAIL" ]] && echo "Using email: $KEY_EMAIL" || echo "(no email UID found; skipping email-selection cases)"

# --- Test runner ---

WORK_DIR=$(mktemp -d -t tcli-sv-XXXXXX)
PASS_COUNT=0
FAIL_COUNT=0

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# Run a command, capture its stderr, and check the exit code matches `$1`.
# Usage: expect_rc <expected_rc> <name> -- <cmd> [args...]
expect_rc() {
    local expected="$1"
    local name="$2"
    shift 2
    [[ "$1" == "--" ]] && shift
    local err_log
    err_log=$(mktemp)
    "$@" >/dev/null 2>"$err_log"
    local rc=$?
    if [[ "$rc" -eq "$expected" ]]; then
        echo "  OK   $name (rc=$rc)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  FAIL $name (expected rc=$expected, got rc=$rc)"
        echo "       stderr:"
        sed 's/^/         /' "$err_log"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    rm -f "$err_log"
}

# Run a command, expect rc=0, and check that a file exists.
expect_file() {
    local name="$1"
    local path="$2"
    shift 2
    [[ "$1" == "--" ]] && shift
    if "$@" >/dev/null 2>&1 && [[ -f "$path" ]]; then
        echo "  OK   $name ($path created)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  FAIL $name ($path not created or command failed)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# Run a command, expect its stdout to contain the given string.
expect_grep() {
    local name="$1"
    local pattern="$2"
    local file="$3"
    if grep -q "$pattern" "$file"; then
        echo "  OK   $name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  FAIL $name (pattern '$pattern' not found in $file)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

cd "$WORK_DIR"

# --- Fixtures ---
echo "hello world" > payload.txt
echo "tampered"    > tampered.txt

echo
echo "=== tcli sign / verify integration tests ==="
echo

# 1. Detached, default = ASCII armored, sibling .asc
echo "[1] Detached signature, default armored"
expect_file "  --sign FILE -> FILE.asc" payload.txt.asc \
    -- "$TCLI" sign payload.txt --signer "$KEY_FP"
expect_grep "  output is ASCII armored" "BEGIN PGP SIGNATURE" payload.txt.asc
expect_rc 0 "  verify good" \
    -- "$TCLI" verify payload.txt --signature payload.txt.asc
echo

# 2. Detached, --binary -> sibling .sig
echo "[2] Detached signature, --binary"
rm -f payload.txt.sig
expect_file "  --sign --binary -> FILE.sig" payload.txt.sig \
    -- "$TCLI" sign payload.txt --signer "$KEY_FP" --binary
# Binary form must NOT start with the ASCII armor header.
if LC_ALL=C head -c 64 payload.txt.sig | grep -aq '^-----BEGIN PGP SIGNATURE-----$'; then
    echo "  FAIL  --binary output contains BEGIN PGP marker"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "  OK   --binary output is binary"
    PASS_COUNT=$((PASS_COUNT + 1))
fi
expect_rc 0 "  verify binary signature" \
    -- "$TCLI" verify payload.txt --signature payload.txt.sig
echo

# 3. -o overrides default destination
echo "[3] -o/--output override"
rm -f custom.asc
expect_file "  --sign -o custom.asc" custom.asc \
    -- "$TCLI" sign payload.txt --signer "$KEY_FP" -o custom.asc
expect_rc 0 "  verify custom.asc" \
    -- "$TCLI" verify payload.txt --signature custom.asc
echo

# 4. Inline (cleartext) sign + verify
echo "[4] Inline cleartext sign + verify"
rm -f payload.signed.asc
expect_file "  --sign-inline -> payload.signed.asc" payload.signed.asc \
    -- "$TCLI" sign-inline payload.txt --signer "$KEY_FP" -o payload.signed.asc
expect_grep "  output is cleartext-signed" "BEGIN PGP SIGNED MESSAGE" payload.signed.asc
expect_rc 0 "  verify cleartext message" \
    -- "$TCLI" verify payload.signed.asc
echo

# 5. BAD signature -> exit 1
echo "[5] BAD signature"
expect_rc 1 "  verify tampered data" \
    -- "$TCLI" verify tampered.txt --signature payload.txt.asc
echo

# 6. UNKNOWN signer -> exit 2
echo "[6] UNKNOWN signer (fresh empty keystore)"
FRESH_DB=$(mktemp -d)/empty.db
expect_rc 2 "  verify against empty keystore" \
    -- env TUMPA_KEYSTORE="$FRESH_DB" "$TCLI" verify payload.txt --signature payload.txt.asc
echo

# 7. UNKNOWN keystore + --key-file external pubkey -> exit 0
echo "[7] --key-file external pubkey"
"$TCLI" export "$KEY_FP" -o pub.asc >/dev/null 2>&1
expect_rc 0 "  verify with external --key-file" \
    -- env TUMPA_KEYSTORE="$FRESH_DB" "$TCLI" verify payload.txt --signature payload.txt.asc --key-file pub.asc
expect_rc 0 "  verify inline with external --key-file" \
    -- env TUMPA_KEYSTORE="$FRESH_DB" "$TCLI" verify payload.signed.asc --key-file pub.asc
expect_rc 1 "  external --key-file catches tampered data" \
    -- env TUMPA_KEYSTORE="$FRESH_DB" "$TCLI" verify tampered.txt --signature payload.txt.asc --key-file pub.asc
echo

# 8. stdin -> stdout sign and verify
echo "[8] stdin / stdout sign"
cat payload.txt | "$TCLI" sign - --signer "$KEY_FP" -o - > stdin-sig.asc 2>/dev/null
expect_grep "  stdin sign produces armored output on stdout" "BEGIN PGP SIGNATURE" stdin-sig.asc
expect_rc 0 "  verify stdin-produced signature" \
    -- "$TCLI" verify payload.txt --signature stdin-sig.asc
echo

# 9. --signer by email (if we found one)
if [[ -n "$KEY_EMAIL" ]]; then
    echo "[9] --signer EMAIL"
    rm -f payload.email.asc
    expect_file "  sign --signer $KEY_EMAIL" payload.email.asc \
        -- "$TCLI" sign payload.txt --signer "$KEY_EMAIL" -o payload.email.asc
    expect_rc 0 "  verify email-selected signature" \
        -- "$TCLI" verify payload.txt --signature payload.email.asc
    echo
fi

# 10. Unknown email -> non-zero
echo "[10] Unknown email is rejected"
expect_rc 1 "  sign --signer nonexistent@example.com" \
    -- "$TCLI" sign payload.txt --signer "this-address-does-not-exist@example.com" -o /dev/null
echo

# 11. CLI parse-time rejections (no key/keystore touched)
#
# clap returns rc=2 for unknown or missing arguments; our own
# validator (mode_from_subcommand) returns rc=1 for valid clap parses
# that fail semantic checks (e.g. stdin verify without --signature).
echo "[11] CLI parse rejections"
expect_rc 2 "  sign without --signer" \
    -- "$TCLI" sign payload.txt
expect_rc 2 "  sign-inline without --signer" \
    -- "$TCLI" sign-inline payload.txt
expect_rc 2 "  sign-inline rejects --binary" \
    -- "$TCLI" sign-inline payload.txt --signer "$KEY_FP" --binary
expect_rc 2 "  --signature is rejected outside verify" \
    -- "$TCLI" list --signature payload.txt.asc
expect_rc 2 "  --signer is rejected outside sign/sign-inline" \
    -- "$TCLI" list --signer "$KEY_FP"
expect_rc 2 "  --key-file is rejected outside verify" \
    -- "$TCLI" list --key-file pub.asc
expect_rc 1 "  verify - without --signature (stdin needs detached)" \
    -- bash -c "echo data | '$TCLI' verify -"
echo

# 12. Inline verify of tampered cleartext -> BAD
echo "[12] Inline verify catches tampered cleartext"
# Tamper a single byte inside the cleartext payload region (between
# the SIGNED-MESSAGE header block and the SIGNATURE block).
python3 - <<PY > tampered.signed.asc
import sys
data = open("payload.signed.asc", "rb").read()
# Split on the signature delimiter; mutate one byte in the payload region.
marker = b"-----BEGIN PGP SIGNATURE-----"
idx = data.find(marker)
assert idx > 0, "marker not found"
head, tail = data[:idx], data[idx:]
# Find a printable byte inside the cleartext body and bump it.
body_start = head.find(b"\n\n") + 2
assert body_start > 1
mutated = bytearray(head)
for i in range(body_start, len(mutated) - 1):
    if 0x20 <= mutated[i] < 0x7e:
        mutated[i] = mutated[i] + 1
        break
sys.stdout.buffer.write(bytes(mutated))
sys.stdout.buffer.write(tail)
PY
expect_rc 1 "  inline verify of tampered cleartext" \
    -- "$TCLI" verify tampered.signed.asc
echo

# --- Summary ---

echo "============================================"
echo "Pass: $PASS_COUNT"
echo "Fail: $FAIL_COUNT"
echo "============================================"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
