#!/bin/bash
# Integration test: tclig <-> gpg interop for git commit signing.
#
# Verifies:
#   - tclig can sign a commit whose message contains non-UTF-8 bytes (a lone 0xa7).
#   - gpg verifies that tclig-signed commit.
#   - gpg can sign with the same key and tclig verifies that commit.
#   - All commits in the chain verify under both signers.
#
# A throwaway gpg homedir, tumpa keystore, and git repo are created in $TMPDIR.
# The user's real ~/.tumpa and ~/.gnupg are NOT touched.
#
# Usage:
#   ./tests/test_git_sign.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TCLI="$PROJECT_DIR/target/debug/tcli"
TCLIG="$PROJECT_DIR/target/debug/tclig"

[[ -x "$TCLI"  ]] || { echo "ERROR: build tcli first (cargo build)";  exit 1; }
[[ -x "$TCLIG" ]] || { echo "ERROR: build tclig first (cargo build)"; exit 1; }
command -v gpg >/dev/null || { echo "ERROR: gpg not installed"; exit 1; }
command -v git >/dev/null || { echo "ERROR: git not installed"; exit 1; }

TEST_PASS="testpass"
TEST_UID="Sign Tester <signtest@example.local>"

# --- Sandbox ---
TEST_DIR=$(mktemp -d -t tumpa-git-sign-XXXXXX)
export GNUPGHOME="$TEST_DIR/gpghome"
export TUMPA_KEYSTORE="$TEST_DIR/keys.db"
export TUMPA_PASSPHRASE="$TEST_PASS"
WRAPPER_DIR="$TEST_DIR/bin"
REPO_DIR="$TEST_DIR/repo"

mkdir -p "$GNUPGHOME" "$WRAPPER_DIR" "$REPO_DIR"
chmod 700 "$GNUPGHOME"

# Wrapper around real gpg that injects --pinentry-mode loopback + passphrase
# so git commit -S succeeds non-interactively.
REAL_GPG=$(command -v gpg)
cat > "$WRAPPER_DIR/gpg-noprompt" <<EOF
#!/bin/bash
exec "$REAL_GPG" --pinentry-mode loopback --passphrase "$TEST_PASS" --batch --yes "\$@"
EOF
chmod +x "$WRAPPER_DIR/gpg-noprompt"

PASS=0; FAIL=0
ok()   { echo "  OK   $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL $1${2:+ — $2}"; FAIL=$((FAIL+1)); }

cleanup() {
    # gpg-agent inside our throwaway homedir
    gpgconf --homedir "$GNUPGHOME" --kill all 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# --- Step 1: generate RSA-4096 key in gpg, import to tumpa keystore ---
echo ""
echo "=== Setup: generate key in gpg, import into tumpa keystore ==="

cat > "$TEST_DIR/keygen.batch" <<EOF
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign,cert
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: sign
Name-Real: Sign Tester
Name-Email: signtest@example.local
Expire-Date: 1y
Passphrase: $TEST_PASS
%commit
EOF
# Allow loopback pinentry so the keygen passphrase can be applied non-interactively
echo "allow-loopback-pinentry" > "$GNUPGHOME/gpg-agent.conf"
echo "pinentry-mode loopback"  > "$GNUPGHOME/gpg.conf"
gpg --homedir "$GNUPGHOME" --batch --gen-key "$TEST_DIR/keygen.batch" 2>/dev/null
KEY_FP=$(gpg --homedir "$GNUPGHOME" --list-keys --with-colons signtest@example.local \
    | awk -F: '/^fpr:/ {print $10; exit}')
echo "  generated key: $KEY_FP"

# Export secret key, import into tumpa keystore
gpg --homedir "$GNUPGHOME" --pinentry-mode loopback --passphrase "$TEST_PASS" \
    --batch --yes --armor --export-secret-keys "$KEY_FP" > "$TEST_DIR/secret.asc"
"$TCLI" --keystore "$TUMPA_KEYSTORE" --import "$TEST_DIR/secret.asc" >/dev/null
ok "key generated and imported into tumpa keystore"

# --- Step 2: init git repo, configure tclig as signing tool ---
echo ""
echo "=== Init repo and configure tclig as gpg.program ==="
cd "$REPO_DIR"
git init --quiet
git config user.name "Sign Tester"
git config user.email "signtest@example.local"
git config commit.gpgsign true
git config user.signingkey "$KEY_FP"
git config gpg.program "$TCLIG"
ok "git repo initialised with tclig as signer"

# --- Step 3: commit with non-UTF-8 char in message, signed by tclig ---
echo ""
echo "=== Commit 1: tclig signs message containing a lone 0xa7 (invalid UTF-8) ==="
echo "first" > file1.txt
git add file1.txt
# Build commit message file with raw 0xa7 byte (Latin-1 §, NOT valid UTF-8)
printf 'add file1: section \xa7 1\n\nNon-UTF-8 byte in body.\n' > "$TEST_DIR/msg1.txt"
if git commit -F "$TEST_DIR/msg1.txt" --quiet 2>"$TEST_DIR/commit1.err"; then
    C1=$(git rev-parse HEAD)
    ok "tclig signed commit 1: $C1"
else
    fail "tclig failed to sign commit 1" "$(cat "$TEST_DIR/commit1.err")"
    exit 1
fi

# --- Step 4: switch to gpg, verify commit 1 ---
echo ""
echo "=== Switch gpg.program=gpg-noprompt, verify commit 1 ==="
git config gpg.program "$WRAPPER_DIR/gpg-noprompt"
# Mark our key as ultimately trusted so gpg verification gives a clean exit.
echo "$KEY_FP:6:" | gpg --homedir "$GNUPGHOME" --import-ownertrust 2>/dev/null

if git verify-commit "$C1" 2>"$TEST_DIR/v1.err"; then
    ok "gpg verifies tclig-signed commit 1"
else
    fail "gpg rejected tclig-signed commit 1" "$(cat "$TEST_DIR/v1.err")"
fi

# --- Step 5: gpg signs commit 2 ---
echo ""
echo "=== Commit 2: gpg signs (gpg.program is now gpg) ==="
echo "second" > file2.txt
git add file2.txt
if git commit -m "add file2 (gpg-signed)" --quiet 2>"$TEST_DIR/commit2.err"; then
    C2=$(git rev-parse HEAD)
    ok "gpg signed commit 2: $C2"
else
    fail "gpg failed to sign commit 2" "$(cat "$TEST_DIR/commit2.err")"
    exit 1
fi

# --- Step 6: switch back to tclig, verify both commits ---
echo ""
echo "=== Switch gpg.program back to tclig, verify commits 1 and 2 ==="
git config gpg.program "$TCLIG"
if git verify-commit "$C1" 2>"$TEST_DIR/v1b.err"; then
    ok "tclig verifies tclig-signed commit 1"
else
    fail "tclig rejected its own commit 1" "$(cat "$TEST_DIR/v1b.err")"
fi
if git verify-commit "$C2" 2>"$TEST_DIR/v2.err"; then
    ok "tclig verifies gpg-signed commit 2"
else
    fail "tclig rejected gpg-signed commit 2" "$(cat "$TEST_DIR/v2.err")"
fi

# --- Step 7: two more commits with tclig, verify everything ---
echo ""
echo "=== Commits 3 & 4: tclig signs, then verify the whole chain ==="
echo "third" > file3.txt
git add file3.txt
git commit -m "add file3 (tclig-signed, ascii)" --quiet
C3=$(git rev-parse HEAD)
ok "tclig signed commit 3: $C3"

echo "fourth" > file4.txt
git add file4.txt
printf 'add file4 with non-utf8: \xa7\n' > "$TEST_DIR/msg4.txt"
git commit -F "$TEST_DIR/msg4.txt" --quiet
C4=$(git rev-parse HEAD)
ok "tclig signed commit 4: $C4"

echo ""
echo "=== Final verification of all 4 commits ==="
for c in "$C1" "$C2" "$C3" "$C4"; do
    if git verify-commit "$c" 2>"$TEST_DIR/v_$c.err"; then
        ok "verify $c"
    else
        fail "verify $c" "$(cat "$TEST_DIR/v_$c.err")"
    fi
done

# Also verify with gpg directly
echo ""
echo "=== Cross-check: verify all 4 via gpg ==="
git config gpg.program "$WRAPPER_DIR/gpg-noprompt"
for c in "$C1" "$C2" "$C3" "$C4"; do
    if git verify-commit "$c" 2>"$TEST_DIR/v_gpg_$c.err"; then
        ok "gpg verify $c"
    else
        fail "gpg verify $c" "$(cat "$TEST_DIR/v_gpg_$c.err")"
    fi
done

echo ""
echo "================================="
echo "Results: $PASS passed, $FAIL failed"
echo "================================="
exit $((FAIL > 0 ? 1 : 0))
