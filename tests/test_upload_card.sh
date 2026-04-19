#!/bin/bash
# Integration tests for `tcli --upload-to-card`.
#
# This test assumes tcli was built with the `experimental` Cargo
# feature:
#
#     cargo build --features experimental
#
# On a default build the experimental flags do not exist on the
# binary, and this script exits early with an explanatory error
# instead of producing misleading failures.
#
# Stage A (always runs): CLI argument validation. No smart card
# needed. Covers --which disambiguation and keystore-resolution
# errors.
#
# Stage B (runs only when a writable OpenPGP card is plugged in and
# TCLI_TEST_CARD_UPLOAD=1 is exported by the caller): end-to-end flow.
# Generates a key, imports to the keystore, uploads to the signing slot,
# and verifies a git commit signature via tclig. Skipped in CI unless
# the environment explicitly opts in.
#
# Usage:
#   cargo build --features experimental && ./tests/test_upload_card.sh
#   TCLI_TEST_CARD_UPLOAD=1 ADMIN_PIN=12345678 TUMPA_PASSPHRASE=testpass \
#       ./tests/test_upload_card.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TCLI="$PROJECT_DIR/target/debug/tcli"
TCLIG="$PROJECT_DIR/target/debug/tclig"

[[ -x "$TCLI"  ]] || { echo "ERROR: build tcli first (cargo build)";  exit 1; }
[[ -x "$TCLIG" ]] || { echo "ERROR: build tclig first (cargo build)"; exit 1; }

TEST_DIR=$(mktemp -d -t tumpa-upload-card-XXXXXX)
export TUMPA_KEYSTORE="$TEST_DIR/keys.db"

cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

PASS=0; FAIL=0
ok()   { echo "  OK   $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL $1${2:+ — $2}"; FAIL=$((FAIL+1)); }

# Assert that the given command exits non-zero AND the combined output
# contains the expected substring.
expect_error_containing() {
    local name="$1"; shift
    local needle="$1"; shift
    local out rc
    out=$("$@" 2>&1) && rc=0 || rc=$?
    if [[ $rc -eq 0 ]]; then
        fail "$name" "expected non-zero exit, got 0; output: $out"
        return
    fi
    if ! grep -qF -- "$needle" <<<"$out"; then
        fail "$name" "missing expected text '$needle'; got: $out"
        return
    fi
    ok "$name"
}

# ---------------------------------------------------------------------
# Preflight: require a feature-experimental build
# ---------------------------------------------------------------------
#
# A default build rejects `--upload-to-card` as an unknown argument
# ("unexpected argument"). A feature build gets past argv parsing and
# falls through to keystore resolution ("key not found"). Anything
# else means something unrelated went wrong and we should not run
# Stage A at all.

preflight_out=$("$TCLI" --upload-to-card 0000000000000000000000000000000000000000 2>&1 || true)
if [[ "$preflight_out" == *"unexpected argument"* ]]; then
    echo "ERROR: tcli was built without the 'experimental' Cargo feature." >&2
    echo "       Rebuild with:  cargo build --features experimental" >&2
    exit 2
fi
if [[ "$preflight_out" != *"key not found"* ]]; then
    echo "ERROR: unexpected --upload-to-card preflight output:" >&2
    echo "$preflight_out" >&2
    exit 2
fi

# ---------------------------------------------------------------------
# Stage A — CLI argument validation (no card required)
# ---------------------------------------------------------------------

echo ""
echo "=== Stage A: CLI argument validation ==="

# A1: --which alone (no --upload-to-card) is an input error.
expect_error_containing \
    "rejects --which without --upload-to-card" \
    "--which only applies to --upload-to-card" \
    "$TCLI" --which primary

# A2: --which with an unknown value is rejected.
expect_error_containing \
    "rejects invalid --which value" \
    "invalid --which value" \
    "$TCLI" --upload-to-card AAAA --which bogus

# A3: unknown fingerprint is surfaced as "key not found".
expect_error_containing \
    "surfaces unknown fingerprint" \
    "key not found" \
    "$TCLI" --upload-to-card \
    0000000000000000000000000000000000000000

# A4: --which primary / --which sub both parse (without any keystore key,
# they must still reach keystore resolution and fail there with a lookup
# error — this proves the flag value is accepted).
expect_error_containing \
    "accepts --which primary" \
    "key not found" \
    "$TCLI" \
    --upload-to-card 0000000000000000000000000000000000000000 \
    --which primary

expect_error_containing \
    "accepts --which sub" \
    "key not found" \
    "$TCLI" \
    --upload-to-card 0000000000000000000000000000000000000000 \
    --which sub

# A5: even on a feature build the flag is hidden from --help.
if "$TCLI" --help 2>&1 | grep -q -- '--upload-to-card'; then
    fail "--upload-to-card stays hidden in --help" \
        "flag leaked to visible --help"
else
    ok "--upload-to-card stays hidden in --help"
fi

# ---------------------------------------------------------------------
# Stage B — End-to-end upload + card sign (requires opt-in + real card)
# ---------------------------------------------------------------------

if [[ "${TCLI_TEST_CARD_UPLOAD:-}" != "1" ]]; then
    echo ""
    echo "=== Stage B: skipped (set TCLI_TEST_CARD_UPLOAD=1 to enable) ==="
    echo ""
    echo "================================="
    echo "Results: $PASS passed, $FAIL failed"
    echo "================================="
    exit $((FAIL > 0 ? 1 : 0))
fi

: "${TUMPA_PASSPHRASE:?TUMPA_PASSPHRASE must be set for Stage B}"
: "${ADMIN_PIN:?ADMIN_PIN must be set for Stage B}"

# tcli's pinentry helper reads TUMPA_ADMIN_PIN for admin-PIN prompts
# (to keep the key passphrase and the admin PIN separable in CI).
# Fresh jcecard after a factory reset defaults to 12345678.
export TUMPA_ADMIN_PIN="$ADMIN_PIN"

command -v gpg >/dev/null || { echo "ERROR: gpg not installed"; exit 1; }
command -v git >/dev/null || { echo "ERROR: git not installed"; exit 1; }

# A card must actually be reachable. Listing cards should succeed AND
# return at least one connected reader.
if ! "$TCLI" --card-status 2>&1 | grep -qE 'Serial number|Manufacturer'; then
    echo "ERROR: Stage B requested but no OpenPGP card detected." >&2
    "$TCLI" --card-status >&2 || true
    exit 1
fi

# Start from a known-clean card: block the admin PIN, factory-reset.
# This makes Stage B idempotent across local reruns — critical for the
# virtual jcecard, whose state file persists across pcscd restarts.
# After reset the admin PIN is back to its default of 12345678.
if ! "$TCLI" --reset-card >"$TEST_DIR/reset.out" 2>&1; then
    fail "card reset (Stage B setup)" "$(cat "$TEST_DIR/reset.out")"
    exit 1
fi
ok "card reset to factory defaults"

echo ""
echo "=== Stage B: end-to-end upload + card sign ==="

# B1: generate a dual-sign key (primary sign+cert, subkey sign) in gpg,
# import the secret into the tumpa keystore.
GNUPGHOME_B="$TEST_DIR/gpghome"
mkdir -p "$GNUPGHOME_B"
chmod 700 "$GNUPGHOME_B"
export GNUPGHOME="$GNUPGHOME_B"
echo "allow-loopback-pinentry" > "$GNUPGHOME/gpg-agent.conf"
echo "pinentry-mode loopback"  > "$GNUPGHOME/gpg.conf"

cat > "$TEST_DIR/keygen.batch" <<EOF
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign,cert
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: sign
Name-Real: Card Uploader
Name-Email: upload@example.local
Expire-Date: 1y
Passphrase: $TUMPA_PASSPHRASE
%commit
EOF
gpg --batch --gen-key "$TEST_DIR/keygen.batch" 2>/dev/null
KEY_FP=$(gpg --list-keys --with-colons upload@example.local \
    | awk -F: '/^fpr:/ {print $10; exit}')
echo "$KEY_FP:6:" | gpg --import-ownertrust 2>/dev/null

gpg --pinentry-mode loopback --passphrase "$TUMPA_PASSPHRASE" \
    --batch --yes --armor --export-secret-keys "$KEY_FP" \
    > "$TEST_DIR/secret.asc"
"$TCLI" --import "$TEST_DIR/secret.asc" >/dev/null
ok "imported sign+cert+sign-subkey cert $KEY_FP into keystore"

# B2: ambiguous upload (primary AND signing subkey) without --which
# must refuse.
expect_error_containing \
    "refuses ambiguous upload without --which" \
    "--which primary" \
    "$TCLI" --upload-to-card "$KEY_FP"

# B3: upload the PRIMARY with --which primary.
if "$TCLI" --upload-to-card "$KEY_FP" --which primary \
        >"$TEST_DIR/upload.out" 2>&1; then
    ok "upload primary → signing slot"
else
    fail "upload primary → signing slot" "$(cat "$TEST_DIR/upload.out")"
    cat "$TEST_DIR/upload.out"
    exit 1
fi

# B4: tclig signs a commit (it should use the card now).
REPO_DIR="$TEST_DIR/repo"
mkdir -p "$REPO_DIR"
cd "$REPO_DIR"
git init --quiet
git config user.name "Card Uploader"
git config user.email "upload@example.local"
git config user.signingkey "$KEY_FP"
git config commit.gpgsign true
git config gpg.program "$TCLIG"

printf 'commit with non-ASCII byte \xa7\n' > "$TEST_DIR/msg.txt"
echo "hello" > file1.txt
git add file1.txt
if git commit -F "$TEST_DIR/msg.txt" --quiet 2>"$TEST_DIR/commit.err"; then
    C1=$(git rev-parse HEAD)
    ok "tclig signs via card: $C1"
else
    fail "tclig signs via card" "$(cat "$TEST_DIR/commit.err")"
    exit 1
fi

if git verify-commit "$C1" 2>"$TEST_DIR/v1.err"; then
    ok "tclig verifies the card-signed commit"
else
    fail "tclig verify" "$(cat "$TEST_DIR/v1.err")"
fi

# B5: gpg verifies too.
REAL_GPG=$(command -v gpg)
WRAPPER="$TEST_DIR/gpg-noprompt"
cat > "$WRAPPER" <<EOF
#!/bin/bash
exec "$REAL_GPG" --pinentry-mode loopback --passphrase "$TUMPA_PASSPHRASE" --batch --yes "\$@"
EOF
chmod +x "$WRAPPER"
git config gpg.program "$WRAPPER"
if git verify-commit "$C1" 2>"$TEST_DIR/v2.err"; then
    ok "gpg verifies the card-signed commit"
else
    fail "gpg verify" "$(cat "$TEST_DIR/v2.err")"
fi

echo ""
echo "================================="
echo "Results: $PASS passed, $FAIL failed"
echo "================================="
exit $((FAIL > 0 ? 1 : 0))
