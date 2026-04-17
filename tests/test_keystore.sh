#!/bin/bash
# Integration tests for tcli key management flags:
#   --import, --export, --info, --desc, --delete, --search, --fetch
#
# Prerequisites:
#   - tcli built (cargo build)
#   - Test key files in tests/keys/
#   - An existing key in ~/.tumpa/keys.db (for --search tests)
#
# Usage:
#   ./tests/test_keystore.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TCLI="$PROJECT_DIR/target/debug/tcli"
KEYS_DIR="$SCRIPT_DIR/keys"

if [[ ! -x "$TCLI" ]]; then
    echo "ERROR: tcli not found at $TCLI"
    echo "Run 'cargo build' first."
    exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

run_test() {
    local name="$1"
    shift
    echo -n "  $name ... "
    if "$@" >/dev/null 2>&1; then
        echo "OK"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

test_output_contains() {
    local name="$1"
    local expected="$2"
    shift 2
    echo -n "  $name ... "
    local actual
    actual=$("$@" 2>&1) || true
    if echo "$actual" | grep -q "$expected"; then
        echo "OK"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL (expected '$expected' in output)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

test_output_not_contains() {
    local name="$1"
    local expected="$2"
    shift 2
    echo -n "  $name ... "
    local actual
    actual=$("$@" 2>&1) || true
    if echo "$actual" | grep -q "$expected"; then
        echo "FAIL (unexpected '$expected' in output)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "OK"
        PASS_COUNT=$((PASS_COUNT + 1))
    fi
}

# Known test key fingerprints (from tests/keys/)
FP_PUBLIC="F4F388BBB194925AE301F844C52B42177857DD79"       # public.asc - test user <test@gmail.com>
FP_HELLOPUBLIC="F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"  # hellopublic.asc - Test User2 <random@example.com>
FP_CV25519="5286C32E7C71E14C4C82F9AE0B207108925CB162"      # cv25519.pub - Good Person2 <gp2@example.com>
FP_NISTP384="4050DD42CAC3C77A44D79962FD7E0629AB6F9641"     # nistp384.pub - Rusty Python <nistp384@example.com>

# Clean up any leftover test keys
cleanup_test_keys() {
    for fp in "$FP_PUBLIC" "$FP_HELLOPUBLIC" "$FP_CV25519" "$FP_NISTP384"; do
        "$TCLI" --delete "$fp" -f 2>/dev/null || true
    done
}

cleanup_test_keys

echo ""
echo "=== tcli key management tests ==="
echo ""

# ----------------------------------------------------------
echo "[1] Import"
# ----------------------------------------------------------

run_test "import single file" "$TCLI" --import "$KEYS_DIR/public.asc"
test_output_contains "import reports count" "Imported 1" "$TCLI" --import "$KEYS_DIR/hellopublic.asc"

# Import same file again — should merge (no new data, but reports as updated)
test_output_contains "import re-import merges" "Updated $FP_PUBLIC" "$TCLI" --import "$KEYS_DIR/public.asc"
test_output_contains "import re-import reports count" "0 new, 1 updated" "$TCLI" --import "$KEYS_DIR/public.asc"

# Import from directory
cleanup_test_keys
test_output_contains "import directory" "Imported 4" "$TCLI" --import "$KEYS_DIR"

# Import multiple files
cleanup_test_keys
test_output_contains "import multiple files" "Imported 2" "$TCLI" --import "$KEYS_DIR/public.asc" "$KEYS_DIR/cv25519.pub"

echo ""

# ----------------------------------------------------------
echo "[2] Info"
# ----------------------------------------------------------

# Make sure keys are imported
"$TCLI" --import "$KEYS_DIR" >/dev/null 2>&1

test_output_contains "info shows fingerprint" "$FP_PUBLIC" "$TCLI" --info "$FP_PUBLIC"
test_output_contains "info shows UID" "test user" "$TCLI" --info "$FP_PUBLIC"
test_output_contains "info shows Created timestamp" "Created:" "$TCLI" --info "$FP_PUBLIC"
test_output_contains "info shows UTC" "UTC" "$TCLI" --info "$FP_PUBLIC"
test_output_contains "info shows Subkeys" "Subkeys:" "$TCLI" --info "$FP_PUBLIC"
test_output_contains "info shows key type" "pub " "$TCLI" --info "$FP_PUBLIC"

# Cv25519 key should show EdDSA
test_output_contains "info cv25519 shows algo" "EdDSA" "$TCLI" --info "$FP_CV25519"

# NistP384 key should show ECDSA or ECDH
test_output_contains "info nistp384 shows algo" "ECDSA\|ECDH" "$TCLI" --info "$FP_NISTP384"

# Info by short key ID (last 16 chars)
SHORT_ID="${FP_PUBLIC:24}"
test_output_contains "info by key ID" "$FP_PUBLIC" "$TCLI" --info "$SHORT_ID"

echo ""

# ----------------------------------------------------------
echo "[2b] Desc (info for a file that isn't in the keystore)"
# ----------------------------------------------------------

# --desc reads a key file directly (no keystore access) and renders
# the same format as --info. Verify it works without the key being
# imported.

# Drop all test keys first, then run --desc on a file.
cleanup_test_keys

test_output_contains "desc shows fingerprint (armored)" \
    "$FP_PUBLIC" "$TCLI" --desc "$KEYS_DIR/public.asc"
test_output_contains "desc shows UID (armored)" \
    "test user" "$TCLI" --desc "$KEYS_DIR/public.asc"
test_output_contains "desc shows Created (armored)" \
    "Created:" "$TCLI" --desc "$KEYS_DIR/public.asc"
test_output_contains "desc shows Subkeys (armored)" \
    "Subkeys:" "$TCLI" --desc "$KEYS_DIR/public.asc"
test_output_contains "desc shows pub marker (public cert)" \
    "^pub " "$TCLI" --desc "$KEYS_DIR/public.asc"

# Binary (non-armored) .pub also works.
test_output_contains "desc shows fingerprint (binary)" \
    "$FP_CV25519" "$TCLI" --desc "$KEYS_DIR/cv25519.pub"

# --desc must NOT import the file into the keystore.
"$TCLI" --desc "$KEYS_DIR/public.asc" >/dev/null 2>&1
test_output_not_contains "desc does not import key" \
    "$FP_PUBLIC" "$TCLI" --list-keys

# Missing file yields an error and non-zero exit.
echo -n "  desc fails on missing file ... "
if "$TCLI" --desc /tmp/tcli-desc-nonexistent.asc >/dev/null 2>&1; then
    echo "FAIL (expected non-zero exit)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
fi

# Non-key file yields an error.
NONKEY=$(mktemp)
echo "not a key" > "$NONKEY"
echo -n "  desc fails on non-key file ... "
if "$TCLI" --desc "$NONKEY" >/dev/null 2>&1; then
    echo "FAIL (expected non-zero exit)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
fi
rm -f "$NONKEY"

# Restore keystore state for the subsequent sections.
"$TCLI" --import "$KEYS_DIR" >/dev/null 2>&1

echo ""

# ----------------------------------------------------------
echo "[3] Export"
# ----------------------------------------------------------

EXPORT_DIR=$(mktemp -d)
trap "rm -rf $EXPORT_DIR; cleanup_test_keys" EXIT

# Export armored (default)
run_test "export armored to stdout" "$TCLI" --export "$FP_PUBLIC"
test_output_contains "export armored has header" "BEGIN PGP PUBLIC KEY BLOCK" "$TCLI" --export "$FP_PUBLIC"

# Export to file
run_test "export to file" "$TCLI" --export "$FP_PUBLIC" -o "$EXPORT_DIR/exported.asc"
echo -n "  exported file exists ... "
if [[ -f "$EXPORT_DIR/exported.asc" ]]; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
test_output_contains "exported file has header" "BEGIN PGP PUBLIC KEY BLOCK" cat "$EXPORT_DIR/exported.asc"

# Export binary
run_test "export binary to file" "$TCLI" --export "$FP_PUBLIC" --binary -o "$EXPORT_DIR/exported.gpg"
echo -n "  binary file exists ... "
if [[ -f "$EXPORT_DIR/exported.gpg" ]]; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi
# Binary should NOT have the ASCII header
test_output_not_contains "binary has no ASCII header" "BEGIN PGP" cat "$EXPORT_DIR/exported.gpg"

# Re-import exported key (round-trip)
"$TCLI" --delete "$FP_PUBLIC" -f >/dev/null 2>&1
run_test "import exported armored" "$TCLI" --import "$EXPORT_DIR/exported.asc"
"$TCLI" --delete "$FP_PUBLIC" -f >/dev/null 2>&1
run_test "import exported binary" "$TCLI" --import "$EXPORT_DIR/exported.gpg"

echo ""

# ----------------------------------------------------------
echo "[4] Search"
# ----------------------------------------------------------

# Re-import all keys
"$TCLI" --import "$KEYS_DIR" >/dev/null 2>&1

test_output_contains "search by name" "$FP_PUBLIC" "$TCLI" --search "test user"
test_output_contains "search by partial name" "$FP_CV25519" "$TCLI" --search "Good Person"
test_output_contains "search shows count" "key(s) found" "$TCLI" --search "test"
test_output_contains "search no results" "No keys found" "$TCLI" --search "nonexistent_xyz_12345"

# Search by email (--email flag means --search value is treated as email)
test_output_contains "search by email" "$FP_HELLOPUBLIC" "$TCLI" --search "random@example.com" --email
test_output_contains "search email no results" "No keys found" "$TCLI" --search "nobody@nowhere.invalid" --email

echo ""

# ----------------------------------------------------------
echo "[5] Delete"
# ----------------------------------------------------------

# Delete with --force
run_test "delete with force" "$TCLI" --delete "$FP_HELLOPUBLIC" -f
test_output_contains "deleted key gone from list" "No keys found" "$TCLI" --search "random@example.com"

# Delete non-existent key
echo -n "  delete non-existent key fails ... "
if "$TCLI" --delete "0000000000000000000000000000000000000000" -f >/dev/null 2>&1; then
    echo "FAIL (should have failed)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
else
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
fi

echo ""

# ----------------------------------------------------------
echo "[6] Import edge cases"
# ----------------------------------------------------------

# Import non-existent file
echo -n "  import non-existent file ... "
OUTPUT=$("$TCLI" --import "/tmp/nonexistent_key_file.asc" 2>&1) || true
if echo "$OUTPUT" | grep -q "failed"; then
    echo "OK (reports failure)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Import non-key file
echo -n "  import non-key file ... "
echo "not a key" > "$EXPORT_DIR/notakey.asc"
OUTPUT=$("$TCLI" --import "$EXPORT_DIR/notakey.asc" 2>&1) || true
if echo "$OUTPUT" | grep -q "failed\|Failed"; then
    echo "OK (reports failure)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Import empty directory (with --recursive, no key files)
mkdir -p "$EXPORT_DIR/emptydir"
test_output_contains "import empty dir" "Imported 0" "$TCLI" --import "$EXPORT_DIR/emptydir"

# ----------------------------------------------------------
echo "[7] Fetch (WKD)"
# ----------------------------------------------------------

FP_KUSHAL="A85FF376759C994A8A1168D8D8219C8C43F6C5E1"

# Dry run — should show info but NOT import
test_output_contains "fetch dry-run shows fingerprint" "$FP_KUSHAL" "$TCLI" --fetch "mail@kushaldas.in" --dry-run
test_output_contains "fetch dry-run shows UID" "Kushal Das" "$TCLI" --fetch "mail@kushaldas.in" --dry-run
test_output_contains "fetch dry-run shows algo" "RSA" "$TCLI" --fetch "mail@kushaldas.in" --dry-run
test_output_contains "fetch dry-run shows subkeys" "Subkeys:" "$TCLI" --fetch "mail@kushaldas.in" --dry-run
test_output_contains "fetch dry-run shows capabilities" "sign" "$TCLI" --fetch "mail@kushaldas.in" --dry-run
test_output_contains "fetch dry-run shows UTC" "UTC" "$TCLI" --fetch "mail@kushaldas.in" --dry-run

echo ""

# --- Cleanup & Summary ---

cleanup_test_keys

echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
