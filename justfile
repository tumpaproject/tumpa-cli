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

# Run test_git_sign.sh inside a Fedora 43 container (newer git than the
# host Ubuntu 24.04 ships; matches the CI runner's git version band).
# Builds the image on first run; `docker` must be available.
docker-test-git-sign:
    docker build -t tumpa-cli-fedora43 -f docker/Dockerfile .
    docker run --rm -v "$(pwd):/src:Z" tumpa-cli-fedora43
