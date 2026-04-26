#!/bin/bash
# Generate an RSA-4096 test key in a throwaway gpg homedir and import it
# into the tumpa keystore at $TUMPA_KEYSTORE (or the default
# ~/.tumpa/keys.db). Prints the fingerprint to stdout for downstream
# steps to consume.
#
# The passphrase is always "testpass".
#
# Used by CI (and anyone reproducing the test suite locally without a
# card + real key already in the keystore).
#
# Usage:
#   fp=$(./tests/provision_test_key.sh)
#   TUMPA_PASSPHRASE=testpass ./tests/test_tpass.sh "$fp"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TCLI="$PROJECT_DIR/target/debug/tcli"
[[ -x "$TCLI" ]] || { echo "ERROR: build tcli first (cargo build)" >&2; exit 1; }
command -v gpg >/dev/null || { echo "ERROR: gpg not installed" >&2; exit 1; }

TEST_PASS="testpass"
TEST_DIR=$(mktemp -d -t tumpa-provision-XXXXXX)

cleanup() {
    gpgconf --homedir "$TEST_DIR/gpghome" --kill all 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

export GNUPGHOME="$TEST_DIR/gpghome"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
echo "allow-loopback-pinentry" > "$GNUPGHOME/gpg-agent.conf"
echo "pinentry-mode loopback"  > "$GNUPGHOME/gpg.conf"

cat > "$TEST_DIR/keygen.batch" <<EOF
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign,cert
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
Name-Real: CI Repro
Name-Email: ci-repro@test.local
Expire-Date: 1y
Passphrase: $TEST_PASS
%commit
EOF

gpg --homedir "$GNUPGHOME" --batch --gen-key "$TEST_DIR/keygen.batch" 2>/dev/null
KEY_FP=$(gpg --homedir "$GNUPGHOME" --list-keys --with-colons ci-repro@test.local \
    | awk -F: '/^fpr:/ {print $10; exit}')
[[ -n "$KEY_FP" ]] || { echo "ERROR: key generation failed" >&2; exit 1; }

gpg --homedir "$GNUPGHOME" --pinentry-mode loopback --passphrase "$TEST_PASS" \
    --batch --yes --armor --export-secret-keys "$KEY_FP" > "$TEST_DIR/secret.asc"
"$TCLI" import "$TEST_DIR/secret.asc" >&2

echo "$KEY_FP"
