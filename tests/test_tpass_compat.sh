#!/bin/bash
# Cross-compatibility test: verify tpass and pass (with tclig as GPG) interoperate.
#
# Prerequisites:
#   - tpass, tcli, and tclig built (cargo build)
#   - pass installed
#   - At least one secret key with an encryption subkey in ~/.tumpa/keys.db
#   - TUMPA_PASSPHRASE set for non-interactive testing
#
# Usage:
#   TUMPA_PASSPHRASE="your-passphrase" ./tests/test_tpass_compat.sh [FINGERPRINT]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TPASS="$PROJECT_DIR/target/debug/tpass"
TCLI="$PROJECT_DIR/target/debug/tcli"
TCLIG="$PROJECT_DIR/target/debug/tclig"

if [[ ! -x "$TPASS" ]]; then
    echo "ERROR: tpass not found. Run 'cargo build' first."
    exit 1
fi

if [[ ! -x "$TCLIG" ]]; then
    echo "ERROR: tclig not found. Run 'cargo build' first."
    exit 1
fi

if ! command -v pass &>/dev/null; then
    echo "ERROR: pass (password-store) is not installed."
    exit 1
fi

if [[ -z "${TUMPA_PASSPHRASE:-}" ]]; then
    echo "ERROR: TUMPA_PASSPHRASE must be set."
    exit 1
fi

# Use provided fingerprint or pick the first secret key
if [[ -n "${1:-}" ]]; then
    KEY_FP="$1"
else
    KEY_FP=$("$TCLI" list 2>/dev/null \
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

# Create GPG wrapper so pass uses tclig
WRAPPER_DIR="$TEST_DIR/bin"
mkdir -p "$WRAPPER_DIR"
ln -sf "$TCLIG" "$WRAPPER_DIR/gpg2"
ln -sf "$TCLIG" "$WRAPPER_DIR/gpg"
export PATH="$WRAPPER_DIR:$PATH"

PASS_COUNT=0
FAIL_COUNT=0

compat_test_output() {
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

compat_test() {
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

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# --- Tests ---

echo ""
echo "=== tpass <-> pass cross-compatibility tests ==="
echo ""

echo "[1] Init with tpass, read with pass"
compat_test "tpass init" "$TPASS" init "$KEY_FP"
compat_test "tpass insert" sh -c "echo 'tpass-secret' | '$TPASS' insert -m compat/from-tpass"
compat_test_output "pass reads tpass entry" "tpass-secret" pass show compat/from-tpass

echo ""
echo "[2] Insert with pass, read with tpass"
compat_test "pass insert" sh -c "echo 'pass-secret' | pass insert -m compat/from-pass"
compat_test_output "tpass reads pass entry" "pass-secret" "$TPASS" show compat/from-pass

echo ""
echo "[3] Generate with tpass, read with pass"
compat_test "tpass generate" "$TPASS" generate -f compat/tpass-gen 16
echo -n "  pass reads tpass generated ... "
GEN=$( pass show compat/tpass-gen 2>/dev/null)
if [[ ${#GEN} -eq 16 ]]; then
    echo "OK (${#GEN} chars)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (expected 16 chars, got ${#GEN})"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[4] Multiline round-trip"
compat_test "tpass insert multiline" sh -c "printf 'mypass\nuser: me\nurl: https://example.com' | '$TPASS' insert -m -f compat/multiline"
compat_test_output "pass reads multiline" "mypass
user: me
url: https://example.com" pass show compat/multiline

echo ""
echo "[5] .gpg-id file compatibility"
echo -n "  .gpg-id format matches ... "
GPG_ID_CONTENT=$(cat "$PASSWORD_STORE_DIR/.gpg-id")
if [[ "$GPG_ID_CONTENT" == "$KEY_FP" ]]; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (expected '$KEY_FP', got '$GPG_ID_CONTENT')"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[6] Reinit with pass, verify tpass still works"
compat_test "pass reinit" pass init "$KEY_FP"
compat_test_output "tpass after pass reinit" "tpass-secret" "$TPASS" show compat/from-tpass

# --- Summary ---

echo ""
echo "=== Compat Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
