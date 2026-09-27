# Tap formula for a Homebrew repository named homebrew-mpa-wallet.
# Refresh url, version, and sha256 when the installer scripts change.
# The url commit must already be on GitHub before you hash its archive.
# License is BUSL-1.1 until 2030-01-01, then GPL-3.0-or-later.

class MpaWallet < Formula
  desc "Host installer for a ContinuumDAO MPA wallet node on macOS"
  homepage "https://github.com/ContinuumDAO/mpc-config"
  url "https://github.com/ContinuumDAO/mpc-config/archive/bd794dd82cc8846e9f8bc050d66cfafbdee80015.tar.gz"
  version "1.0.0"
  sha256 "d9aa7d556f6bf97235bbba704a7acb9090e984f26653a5580faf4c461dd6ff0b"
  license "BUSL-1.1"

  livecheck do
    skip "Pinned to a reviewed mpc-config commit"
  end

  depends_on "bash"
  depends_on "git"
  depends_on "openssl@3"
  depends_on "python@3"
  depends_on "socat"
  depends_on "wireguard-tools"
  depends_on "yq"
  depends_on cask: "docker"
  depends_on :macos

  def install
    pkgshare.install "scripts/install-node-macos-docker-desktop.sh"
    pkgshare.install "scripts/uninstall-node-macos-docker-desktop.sh"

    libdir = pkgshare/"lib"
    libdir.mkpath
    Dir["scripts/lib/*"].each do |path|
      next unless File.file?(path)

      base = File.basename(path)
      next if base.end_with?(".test.sh", ".pyc")

      libdir.install path
    end

    bash = Formula["bash"].opt_bin/"bash"

    (bin/"mpa-wallet-install").write <<~SH
      #!/bin/bash
      set -euo pipefail
      if [ "$(uname -s)" != "Darwin" ]; then
        echo "error: mpa-wallet-install is for macOS. Linux uses the AUR, the Ubuntu PPA, or the curl installer." >&2
        exit 1
      fi
      for arg in "$@"; do
        if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
          exec "#{bash}" "#{pkgshare}/install-node-macos-docker-desktop.sh" --help
        fi
      done
      if [ "$(id -u)" -eq 0 ]; then
        echo "error: run mpa-wallet-install as your macOS user, not root." >&2
        exit 1
      fi
      repo="${MPC_REPO_DIR:-${HOME}/mpc-config}"
      if [ ! -d "${repo}/.git" ]; then
        echo "==> Cloning mpc-config to ${repo}" >&2
        git clone --depth 1 --branch main https://github.com/ContinuumDAO/mpc-config.git "$repo"
      fi
      exec "#{bash}" "${repo}/scripts/install-node-macos-docker-desktop.sh" "$@"
    SH

    (bin/"mpa-wallet-uninstall").write <<~SH
      #!/bin/bash
      set -euo pipefail
      if [ "$(uname -s)" != "Darwin" ]; then
        echo "error: mpa-wallet-uninstall is for macOS. Linux uses the AUR, the Ubuntu PPA, or the curl installer." >&2
        exit 1
      fi
      exec "#{bash}" "#{pkgshare}/uninstall-node-macos-docker-desktop.sh" "$@"
    SH
  end

  def caveats
    <<~EOS
      MPA wallet host tools are installed. This did not create a node.
      Open Docker Desktop once so it finishes its own setup.

      Create a node as your macOS user (management key and this Mac's public IPv4):

        mpa-wallet-install --node-mgt-key 0xYour40Hex... --ip YOUR_PUBLIC_IPV4

      The first run clones mpc-config to ~/mpc-config. macOS does not use an mpcnode user.
      Passwordless sudo is required. See docs/INSTALL_NODE_MACOS_DOCKER_DESKTOP.md.

      Remove a node later with:

        sudo "#{HOMEBREW_PREFIX}/bin/mpa-wallet-uninstall" --help
    EOS
  end

  test do
    assert_match "macOS Docker Desktop", shell_output("#{bin}/mpa-wallet-install --help")
  end
end
