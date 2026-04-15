# tumpa-cli: tcli (GPG replacement) + tpass (password-store replacement)
_default:
  @just --list

# Build both binaries (debug)
build:
    cargo build

# Build both binaries (release)
release:
    cargo build --release

# Run clippy linter
lint:
    cargo clippy

# Run all tests (requires TUMPA_PASSPHRASE and a secret key in ~/.tumpa/keys.db)
test: build
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_tpass.sh

# Run cross-compatibility tests between tpass and pass
test-compat: build
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_tpass_compat.sh

# Run tcli + pass integration tests
test-pass: build
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_pass.sh

# Run tcli key management tests (--import, --export, --info, --delete, --search)
test-keystore: build
    ./tests/test_keystore.sh

# Run all test suites
test-all: test test-compat test-pass test-keystore

# Build, lint, and test
check: build lint test
