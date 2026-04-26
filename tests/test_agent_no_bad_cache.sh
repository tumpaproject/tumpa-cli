#!/bin/bash
# Regression test for tumpa-cli issue #19:
# https://github.com/tumpaproject/tumpa-cli/issues/19
#
# The unified agent must NOT cache a PIN / passphrase that turned out to
# be wrong. Pre-fix, get_passphrase eagerly cached every value it
# produced from TUMPA_PASSPHRASE / pinentry / terminal, *before*
# verifying it via sign / decrypt. A single typo would then poison the
# cache and either silently fail every subsequent op (software keys) or
# burn through a card's three PIN attempts.
#
# This script exercises that path with software-key signing using
# TUMPA_PASSPHRASE as a non-interactive driver.
#
# Usage:
#   TUMPA_PASSPHRASE="<correct>" ./tests/test_agent_no_bad_cache.sh [FINGERPRINT]

set -euo pipefail

# --- Locate binaries ---

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TCLI="$PROJECT_DIR/target/debug/tcli"
TCLIG="$PROJECT_DIR/target/debug/tclig"

if [[ ! -x "$TCLI" || ! -x "$TCLIG" ]]; then
    echo "ERROR: tcli/tclig not built. Run 'cargo build' first."
    exit 1
fi

if [[ -z "${TUMPA_PASSPHRASE:-}" ]]; then
    echo "ERROR: TUMPA_PASSPHRASE must hold the correct passphrase."
    exit 1
fi

CORRECT_PASS="$TUMPA_PASSPHRASE"
WRONG_PASS="definitely-not-the-passphrase-${RANDOM}-${RANDOM}"

# --- Pick a signing key ---

if [[ -n "${1:-}" ]]; then
    KEY_FP="$1"
else
    KEY_FP=$("$TCLI" list 2>/dev/null \
        | grep "^sec" | head -1 | awk '{print $2}' || true)
fi
if [[ -z "$KEY_FP" ]]; then
    echo "ERROR: No secret key found in tumpa keystore."
    exit 1
fi
echo "Using key: $KEY_FP"

# --- Hermetic HOME so the real user agent isn't touched ---

ORIG_HOME="${HOME}"
ORIG_KEYSTORE="${TUMPA_KEYSTORE:-$ORIG_HOME/.tumpa/keys.db}"
TEST_HOME=$(mktemp -d)
mkdir -p "$TEST_HOME/.tumpa"
export HOME="$TEST_HOME"
export TUMPA_KEYSTORE="$ORIG_KEYSTORE"

AGENT_PID=""
DATA_FILE=$(mktemp)
echo "regression test for issue #19" > "$DATA_FILE"

cleanup() {
    if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    rm -f "$DATA_FILE"
    rm -rf "$TEST_HOME"
}
trap cleanup EXIT

# --- Start the agent in our hermetic HOME ---

# Strip TUMPA_PASSPHRASE from the agent's own env: the agent doesn't
# consult it, but leaving it set would obscure intent.
env -u TUMPA_PASSPHRASE "$TCLI" agent >/dev/null 2>&1 &
AGENT_PID=$!

SOCKET="$HOME/.tumpa/agent.sock"
for _ in $(seq 1 50); do
    if [[ -S "$SOCKET" ]]; then
        break
    fi
    sleep 0.1
done
if [[ ! -S "$SOCKET" ]]; then
    echo "ERROR: agent did not bind $SOCKET within 5s."
    exit 1
fi

# --- Test helpers ---

PASS_COUNT=0
FAIL_COUNT=0

assert_pass() {
    local name="$1"; shift
    echo -n "  $name ... "
    if "$@"; then
        echo "OK"; PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL"; FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}
assert_fail() {
    local name="$1"; shift
    echo -n "  $name ... "
    if ! "$@"; then
        echo "OK"; PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "FAIL (expected non-zero exit)"; FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

sign_with() {
    local pass_env=("$@")
    "${pass_env[@]}" "$TCLIG" -bsau "$KEY_FP" \
        < "$DATA_FILE" > /dev/null 2>&1
}

run_sign_wrong()   { sign_with env "TUMPA_PASSPHRASE=$WRONG_PASS";   }
run_sign_correct() { sign_with env "TUMPA_PASSPHRASE=$CORRECT_PASS"; }
run_sign_no_env()  { sign_with env -u TUMPA_PASSPHRASE;              }

# --- Tests ---

echo ""
echo "=== Issue #19: agent must not cache wrong passphrase ==="
echo ""

# 1. A wrong passphrase must fail signing.
assert_fail "[1] sign with wrong passphrase fails" run_sign_wrong

# 2. Immediately after, the correct passphrase must succeed.
#    Pre-fix, step 1 cached the wrong value under the fingerprint and
#    get_passphrase preferred cache over env → this would also fail.
assert_pass "[2] sign with correct passphrase succeeds" run_sign_correct

# 3. With TUMPA_PASSPHRASE unset, signing must still succeed because
#    the correct value from step 2 is now cached. Guards against an
#    over-zealous fix that also disables caching of good values.
assert_pass "[3] re-sign uses cached good passphrase" run_sign_no_env

# --- Summary ---

echo ""
echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="
exit "$FAIL_COUNT"
