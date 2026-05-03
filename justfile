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
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_sign_verify.sh

# Run cross-compatibility tests between tpass and pass
test-compat: build
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_tpass_compat.sh

# Run tcli + pass integration tests
test-pass: build
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_pass.sh

# Run tcli sign/verify integration tests
test-sign-verify: build
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_sign_verify.sh

# Run tcli key management tests (import, export, describe, delete, search)
test-keystore: build
    ./tests/test_keystore.sh

# Regression test for issue #19: agent must not cache a wrong passphrase
test-agent-cache: build
    TUMPA_PASSPHRASE="${TUMPA_PASSPHRASE}" ./tests/test_agent_no_bad_cache.sh

# Run all test suites
test-all: test test-compat test-pass test-sign-verify test-keystore test-agent-cache

# Build, lint, and test
check: build lint test

# Run test_git_sign.sh inside a Fedora 43 container (newer git than the
# host Ubuntu 24.04 ships; matches the CI runner's git version band).
# Builds the image on first run; `docker` must be available.
docker-test-git-sign:
    docker build -t tumpa-cli-fedora43 -f docker/Dockerfile .
    docker run --rm -v "$(pwd):/src:Z" tumpa-cli-fedora43

# --- macOS LaunchAgent helpers (Tumpa user-domain agent) ---
# These manage the per-user Aqua-session LaunchAgent installed by the
# Homebrew tap's `setup-tumpa-agent` script (label
# `in.kushaldas.tumpa.agent`).
LAUNCHD_LABEL := "in.kushaldas.tumpa.agent"
LAUNCHD_PLIST := "$HOME/Library/LaunchAgents/in.kushaldas.tumpa.agent.plist"

# Show launchd status of the Tumpa user agent (macOS only).
mac-agent-status:
    @launchctl print "gui/$(id -u)/{{LAUNCHD_LABEL}}" 2>/dev/null \
        | grep -E '^\s+(state|pid|sessiontype|program)' \
        || echo "{{LAUNCHD_LABEL}} is not loaded"

# Stop the launchd-managed Tumpa agent until next login or mac-agent-start.
mac-agent-stop:
    launchctl bootout "gui/$(id -u)/{{LAUNCHD_LABEL}}"

# Start the launchd-managed Tumpa agent (plist must already be installed).
mac-agent-start:
    launchctl bootstrap "gui/$(id -u)" "{{LAUNCHD_PLIST}}"

# Bootout + bootstrap; picks up plist edits.
mac-agent-restart:
    -launchctl bootout "gui/$(id -u)/{{LAUNCHD_LABEL}}" 2>/dev/null
    launchctl bootstrap "gui/$(id -u)" "{{LAUNCHD_PLIST}}"

# Force-restart the agent, bypassing launchd's spawn throttle (use when `mac-agent-restart` leaves state = not running).
mac-agent-kickstart:
    launchctl kickstart -kp "gui/$(id -u)/{{LAUNCHD_LABEL}}"

# Persistently disable across reboots.
mac-agent-disable:
    launchctl disable "gui/$(id -u)/{{LAUNCHD_LABEL}}"

# Re-enable a previously disabled agent.
mac-agent-enable:
    launchctl enable "gui/$(id -u)/{{LAUNCHD_LABEL}}"

# Bootout the agent and remove its plist from ~/Library/LaunchAgents/.
mac-agent-uninstall:
    -launchctl bootout "gui/$(id -u)/{{LAUNCHD_LABEL}}" 2>/dev/null
    rm -f "{{LAUNCHD_PLIST}}"
