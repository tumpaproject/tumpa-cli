#!/bin/bash
# Integration test for tpass (password-store replacement).
#
# Prerequisites:
#   - tpass built (cargo build)
#   - At least one secret key with an encryption subkey in ~/.tumpa/keys.db
#   - TUMPA_PASSPHRASE set for non-interactive testing
#
# Usage:
#   TUMPA_PASSPHRASE="your-passphrase" ./tests/test_tpass.sh [FINGERPRINT]
#
# If FINGERPRINT is omitted, the first secret key in the keystore is used.

set -euo pipefail

# --- Configuration ---

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TPASS="$PROJECT_DIR/target/debug/tpass"
TCLI="$PROJECT_DIR/target/debug/tcli"

if [[ ! -x "$TPASS" ]]; then
    echo "ERROR: tpass not found at $TPASS"
    echo "Run 'cargo build' first."
    exit 1
fi

if [[ ! -x "$TCLI" ]]; then
    echo "ERROR: tcli not found at $TCLI"
    echo "Run 'cargo build' first."
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
OUTSIDE_DIR="$TEST_DIR/outside"
mkdir -p "$OUTSIDE_DIR"

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
echo "=== tpass integration tests ==="
echo ""

echo "[1] Initialization"
pass_test "tpass init" "$TPASS" init "$KEY_FP"

echo ""
echo "[2] Insert and retrieve"
pass_test "insert (multiline)" sh -c "echo 'hunter2' | '$TPASS' insert -m test/simple"
pass_test_output "show" "hunter2" "$TPASS" show test/simple

echo ""
echo "[3] Multiline password"
pass_test "insert multiline" sh -c "printf 'line1\nuser: admin\nurl: example.com' | '$TPASS' insert -m test/multi"
pass_test_output "show multiline" "line1
user: admin
url: example.com" "$TPASS" show test/multi

echo ""
echo "[4] Password generation"
pass_test "generate" "$TPASS" generate -f test/generated 24
# Verify it's retrievable and has the right length
echo -n "  show generated (length) ... "
GEN_PASS=$("$TPASS" show test/generated 2>/dev/null)
GEN_LEN=${#GEN_PASS}
if [[ "$GEN_LEN" -eq 24 ]]; then
    echo "OK ($GEN_LEN chars)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (expected 24 chars, got $GEN_LEN)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[5] Generate with no symbols"
pass_test "generate no-symbols" "$TPASS" generate -n -f test/gen-nosym 16
echo -n "  show gen-nosym (alphanumeric) ... "
NOSYM_PASS=$("$TPASS" show test/gen-nosym 2>/dev/null)
if echo "$NOSYM_PASS" | grep -qP '^[a-zA-Z0-9]+$'; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (contains symbols: '$NOSYM_PASS')"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[6] Generate in-place"
pass_test "insert for in-place" sh -c "printf 'oldpass\nuser: test\nurl: example.com' | '$TPASS' insert -m -f test/inplace"
pass_test "generate in-place" "$TPASS" generate -i test/inplace 20
echo -n "  in-place preserves metadata ... "
INPLACE=$("$TPASS" show test/inplace 2>/dev/null)
FIRST_LINE=$(echo "$INPLACE" | head -1)
SECOND_LINE=$(echo "$INPLACE" | sed -n '2p')
if [[ ${#FIRST_LINE} -eq 20 && "$SECOND_LINE" == "user: test" ]]; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (first='$FIRST_LINE' second='$SECOND_LINE')"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[7] Overwrite"
pass_test "overwrite" sh -c "echo 'newpass' | '$TPASS' insert -m -f test/simple"
pass_test_output "show overwritten" "newpass" "$TPASS" show test/simple

echo ""
echo "[8] Nested paths"
pass_test "insert nested" sh -c "echo 'deep' | '$TPASS' insert -m a/b/c/deep"
pass_test_output "show nested" "deep" "$TPASS" show a/b/c/deep

echo ""
echo "[9] Path and symlink safety"
printf '%s\n' "$KEY_FP" > "$OUTSIDE_DIR/.gpg-id"
echo -n "  reject absolute path escape ... "
if ! sh -c "echo 'escaped' | '$TPASS' insert -m '$OUTSIDE_DIR/abs-escape'" >/dev/null 2>&1 \
    && [[ ! -e "$OUTSIDE_DIR/abs-escape.gpg" ]]; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

mkdir -p "$PASSWORD_STORE_DIR/safe"
pass_test "insert symlink target" sh -c "echo 'symlink-secret' | '$TPASS' insert -m safe/real"
mv "$PASSWORD_STORE_DIR/safe/real.gpg" "$OUTSIDE_DIR/real.gpg"
ln -s "$OUTSIDE_DIR/real.gpg" "$PASSWORD_STORE_DIR/safe/link.gpg"
echo -n "  reject symlinked file read ... "
if ! "$TPASS" show safe/link >/dev/null 2>&1; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

mkdir -p "$OUTSIDE_DIR/symlink-dir"
printf '%s\n' "$KEY_FP" > "$OUTSIDE_DIR/symlink-dir/.gpg-id"
ln -s "$OUTSIDE_DIR/symlink-dir" "$PASSWORD_STORE_DIR/linkdir"
echo -n "  reject symlinked directory write ... "
if ! sh -c "echo 'blocked' | '$TPASS' insert -m linkdir/entry" >/dev/null 2>&1 \
    && [[ ! -e "$OUTSIDE_DIR/symlink-dir/entry.gpg" ]]; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[10] Edit"
EDITOR_SCRIPT="$TEST_DIR/editor.sh"
cat > "$EDITOR_SCRIPT" <<'EOF'
#!/bin/sh
printf 'edited-pass\nuser: edited\n' > "$1"
EOF
chmod +x "$EDITOR_SCRIPT"
pass_test "edit" env EDITOR="$EDITOR_SCRIPT" "$TPASS" edit test/edited
pass_test_output "show edited" "edited-pass
user: edited" "$TPASS" show test/edited

echo ""
echo "[11] Remove"
pass_test "remove" "$TPASS" rm -f test/simple

echo ""
echo "[12] Reinit (same key, no reencrypt needed)"
pass_test "reinit same key" "$TPASS" init "$KEY_FP"
pass_test_output "show after reinit" "line1
user: admin
url: example.com" "$TPASS" show test/multi

echo ""
echo "[13] List"
echo -n "  tpass ls ... "
LS_OUTPUT=$("$TPASS" ls 2>/dev/null)
if echo "$LS_OUTPUT" | grep -q "test"; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[14] Find"
echo -n "  tpass find multi ... "
FIND_OUTPUT=$("$TPASS" find multi 2>/dev/null)
if echo "$FIND_OUTPUT" | grep -q "multi"; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[15] Copy"
pass_test "copy" "$TPASS" cp test/multi test/multi-copy
pass_test_output "show copy" "line1
user: admin
url: example.com" "$TPASS" show test/multi-copy

echo ""
echo "[16] Move"
pass_test "move" "$TPASS" mv -f test/multi-copy test/multi-moved
pass_test_output "show moved" "line1
user: admin
url: example.com" "$TPASS" show test/multi-moved
echo -n "  source removed after move ... "
if ! "$TPASS" show test/multi-copy >/dev/null 2>&1; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (source still exists)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[17] Grep"
echo -n "  tpass grep admin ... "
GREP_OUTPUT=$("$TPASS" grep admin 2>/dev/null) || true
if echo "$GREP_OUTPUT" | grep -q "admin"; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[18] Remove recursive"
pass_test "remove recursive" "$TPASS" rm -rf test

echo ""
echo "[19] Version"
echo -n "  tpass version ... "
VERSION_OUTPUT=$("$TPASS" version 2>/dev/null)
if echo "$VERSION_OUTPUT" | grep -q "tpass"; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
echo "[20] Git integration"
pass_test "git init" "$TPASS" git init
echo -n "  git log has commits ... "
GIT_LOG=$(cd "$PASSWORD_STORE_DIR" && git log --oneline 2>/dev/null)
if [[ -n "$GIT_LOG" ]]; then
    echo "OK"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Insert after git init to verify auto-commits
pass_test "insert with git" sh -c "echo 'gitpass' | '$TPASS' insert -m git-test/entry"
echo -n "  git auto-commit ... "
GIT_LOG2=$(cd "$PASSWORD_STORE_DIR" && git log --oneline 2>/dev/null | wc -l)
if [[ "$GIT_LOG2" -gt 1 ]]; then
    echo "OK ($GIT_LOG2 commits)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "FAIL (expected >1 commits, got $GIT_LOG2)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# Regression: non-init git subcommands must detect the existing repo.
# Pre-fix, find_git_dir was invoked with prefix.join(".") and Path::parent()
# skipped the CurDir component, so tpass misreported the store as non-git.
pass_test "git status on existing repo" "$TPASS" git status
pass_test "git log on existing repo" "$TPASS" git log --oneline

# --- Summary ---

echo ""
echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
