#!/bin/bash
# Integration test for tcli with password-store (pass).
#
# Prerequisites:
#   - pass installed (apt install pass / brew install pass)
#   - tcli built (cargo build)
#   - At least one secret key with an encryption subkey in ~/.tumpa/keys.db
#   - TUMPA_PASSPHRASE set for non-interactive testing
#
# Usage:
#   TUMPA_PASSPHRASE="your-passphrase" ./tests/test_pass.sh [FINGERPRINT]
#
# If FINGERPRINT is omitted, the first secret key in the keystore is used.

set -euo pipefail

# --- Configuration ---

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TCLI="$PROJECT_DIR/target/debug/tcli"

if [[ ! -x "$TCLI" ]]; then
    echo "ERROR: tcli not found at $TCLI"
    echo "Run 'cargo build' first."
    exit 1
fi

if ! command -v pass &>/dev/null; then
    echo "ERROR: pass (password-store) is not installed."
    exit 1
fi

if [[ -z "${TUMPA_PASSPHRASE:-}" ]]; then
    echo "ERROR: TUMPA_PASSPHRASE must be set for non-interactive testing."
    exit 1
fi

# Use provided fingerprint or pick the first secret key
if [[ -n "${1:-}" ]]; then
    KEY_FP="$1"
else
    KEY_FP=$("$TCLI" --list-keys 2>/dev/null \
        | grep "^sec" \
        | head -1 \
        | awk '{print $2}')
fi

if [[ -z "$KEY_FP" ]]; then
    echo "ERROR: No secret key found in tumpa keystore."
    exit 1
fi

echo "Using key: $KEY_FP"

# --- Setup ---

TEST_DIR=$(mktemp -d)
export PASSWORD_STORE_DIR="$TEST_DIR/store"
WRAPPER_DIR="$TEST_DIR/bin"

mkdir -p "$WRAPPER_DIR"
ln -sf "$TCLI" "$WRAPPER_DIR/gpg2"
ln -sf "$TCLI" "$WRAPPER_DIR/gpg"
export PATH="$WRAPPER_DIR:$PATH"

PASS_COUNT=0
FAIL_COUNT=0

pass_test() {
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

pass_test_output() {
    local name="$1"
    local expected="$2"
    shift 2
    echo -n "  $name ... "
    local actual
    actual=$("$@" 2>/dev/null) || true
    if [[ "$actual" == "$expected" ]]; then
        echo "OK"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL (expected '$expected', got '$actual')"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# --- Tests ---

echo ""
echo "=== tcli + pass integration tests ==="
echo ""

echo "[1] Initialization"
pass_test "pass init" pass init "$KEY_FP"

echo ""
echo "[2] Insert and retrieve"
pass_test "insert (multiline)" sh -c "echo 'hunter2' | pass insert -m test/simple"
pass_test_output "show" "hunter2" pass show test/simple

echo ""
echo "[3] Multiline password"
pass_test "insert multiline" sh -c "printf 'line1\nuser: admin\nurl: example.com' | pass insert -m test/multi"
pass_test_output "show multiline" "line1
user: admin
url: example.com" pass show test/multi

echo ""
echo "[4] Password generation"
pass_test "generate" pass generate -f test/generated 24
# Verify it's retrievable and has the right length
echo -n "  show generated (length) ... "
GEN_PASS=$(pass show test/generated 2>/dev/null)
GEN_LEN=${#GEN_PASS}
if [[ "$GEN_LEN" -eq 24 ]]; then
    echo "OK ($GEN_LEN chars)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (expected 24 chars, got $GEN_LEN)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[5] Overwrite"
pass_test "overwrite" sh -c "echo 'newpass' | pass insert -m -f test/simple"
pass_test_output "show overwritten" "newpass" pass show test/simple

echo ""
echo "[6] Nested paths"
pass_test "insert nested" sh -c "echo 'deep' | pass insert -m a/b/c/deep"
pass_test_output "show nested" "deep" pass show a/b/c/deep

echo ""
echo "[7] Remove"
pass_test "remove" pass rm -f test/simple

echo ""
echo "[8] Reinit (same key, no reencrypt needed)"
pass_test "reinit same key" pass init "$KEY_FP"
pass_test_output "show after reinit" "line1
user: admin
url: example.com" pass show test/multi

echo ""
echo "[9] List"
echo -n "  pass ls ... "
LS_OUTPUT=$(pass ls 2>/dev/null)
if echo "$LS_OUTPUT" | grep -q "test"; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[10] Key listing (GPG compat)"
echo -n "  --list-keys --with-colons (encryption subkey) ... "
SUB_E=$("$TCLI" --list-keys --with-colons "$KEY_FP" 2>/dev/null \
    | sed -n 's/^sub:[^idr:]*:[^:]*:[^:]*:\([^:]*\):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[a-zA-Z]*e[a-zA-Z]*:.*/\1/p')
if [[ -n "$SUB_E" ]]; then
    echo "OK ($SUB_E)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (no encryption subkey found)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo -n "  --list-secret-keys --with-colons (UID) ... "
UID_LINE=$("$TCLI" --list-secret-keys --with-colons 2>/dev/null \
    | grep "^uid:" | head -1 | cut -d: -f10)
if [[ -n "$UID_LINE" ]]; then
    echo "OK ($UID_LINE)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (no UID found)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo -n "  --decrypt --list-only ... "
PUBKEY=$("$TCLI" --decrypt --list-only "$PASSWORD_STORE_DIR/test/multi.gpg" 2>&1 \
    | sed -nE 's/^gpg: public key is ([A-F0-9]+)$/\1/p')
if [[ -n "$PUBKEY" ]]; then
    echo "OK ($PUBKEY)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (no public key line)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# --- Summary ---

echo ""
echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
