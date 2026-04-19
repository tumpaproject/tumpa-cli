# Reproducer image for test_git_sign.sh.
#
# Why this exists: the CI runner (ubuntu-latest with git 2.53) fails
# the test, but a local Ubuntu 24.04 with git 2.43 passes. This image
# pins a known-newer git (whatever fedora:43 ships at `dnf install`
# time) so the test can be exercised locally in the same shape as CI.
#
# Build:
#   docker build -t tumpa-cli-fedora43 -f docker/Dockerfile .
#
# Run (bind-mount the repo, build, then run only test_git_sign.sh):
#   docker run --rm -v "$PWD:/src:Z" tumpa-cli-fedora43
#
# On SELinux-less hosts (Ubuntu, macOS), `:Z` is a no-op; keep it so
# the same command also works on Fedora/CentOS/RHEL hosts.

FROM fedora:43

# - gnupg2 + git: subjects of the test (gpg signs, git drives).
# - pcsc-lite-devel + sqlite-devel + openssl-devel: native libs that
#   wecanencrypt, rpgp, and reqwest link against during the build.
#   pcscd itself is intentionally not started; libtumpa 0.1.1 treats
#   a missing PCSC service as "no card visible" and falls through to
#   the software sign path exactly like the CI default build does.
# - gcc / make / pkgconf: toolchain for native crates compiled by
#   cargo (ring, aws-lc-rs, sqlite3-sys, etc.).
# - curl + ca-certificates: fetch rustup.
RUN dnf -y install \
      gnupg2 git \
      pcsc-lite-devel sqlite-devel openssl-devel \
      gcc gcc-c++ make pkgconf-pkg-config \
      curl ca-certificates \
 && dnf clean all

ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin

# Rust via rustup (stable, minimal profile -- no docs/components we
# don't use for the test).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- --default-toolchain stable --profile minimal -y \
 && rustc --version && cargo --version

WORKDIR /src

# Default: print versions, build, then run the one test we care about.
# `test_git_sign.sh` uses `target/debug/tcli` and `target/debug/tclig`
# so we just `cargo build` against the mounted repo. The target dir
# lands under the bind mount on the host -- harmless, `target/` is
# already gitignored.
CMD ["bash", "-eu", "-o", "pipefail", "-c", "\
echo '=== host info ==='; cat /etc/os-release | sed -n 's/^PRETTY_NAME=//p'; \
echo '=== git ==='; git --version; \
echo '=== gpg ==='; gpg --version | head -n1; \
echo '=== rust ==='; rustc --version; cargo --version; \
echo '=== build ==='; cargo build; \
echo '=== run test_git_sign.sh ==='; exec ./tests/test_git_sign.sh \
"]
