# Publish MPA wallet on the Arch User Repository

The AUR package is **`mpa-wallet-git`**. It installs Docker and the other host packages, plus the Continuum install scripts, on a systemd Arch derivative (Arch, Omarchy, Manjaro, EndeavourOS, Garuda, CachyOS, ArcoLinux).

Installing the package does **not** create a node. After `pacman` finishes, the operator runs:

```bash
sudo mpa-wallet-install --node-mgt-key 0xYour40Hex... --ip YOUR_PUBLIC_IPV4
sudo passwd mpcnode
```

That is the same Arch installer as [`scripts/install-node-arch.sh`](../scripts/install-node-arch.sh). Artix, Obarun, and SteamOS stay unsupported.

Files for the AUR live in [`packaging/aur/`](../packaging/aur/):

| File | Role |
|------|------|
| `PKGBUILD` | Build recipe |
| `.SRCINFO` | Metadata the AUR website reads (must be committed) |
| `mpa-wallet-git.install` | Message printed after install |
| `mpa-wallet-install` | `/usr/bin/mpa-wallet-install` |
| `mpa-wallet-uninstall` | `/usr/bin/mpa-wallet-uninstall` |

The name ends in `-git` because the package tracks the `main` branch of [ContinuumDAO/mpc-config](https://github.com/ContinuumDAO/mpc-config). AUR requires that suffix for a package that follows a Git branch.

## 1. Put the Arch installer on GitHub first

The PKGBUILD clones `https://github.com/ContinuumDAO/mpc-config.git` at build time. `install-node-arch.sh` has to be on **`main`** before anyone builds the package, including you. Push this repository to `main`, then continue.

Check the name is free: [https://aur.archlinux.org/packages/mpa-wallet-git](https://aur.archlinux.org/packages/mpa-wallet-git). If that page already exists and it is not yours, pick another name and change `pkgname` in the PKGBUILD, `.SRCINFO`, and the `.install` filename together.

## 2. Create an AUR account

1. Open [https://aur.archlinux.org/register](https://aur.archlinux.org/register).
2. Choose a username, password, email, and the display name that will appear as the package maintainer.
3. Accept the AUR terms. You are agreeing to maintain the package: answer comments, and update it when the installer changes.
4. Open the confirmation link in the email from the AUR.
5. Sign in at [https://aur.archlinux.org/](https://aur.archlinux.org/).

## 3. Add an SSH key

The AUR accepts Git pushes only over SSH, as the user `aur`.

On the machine you will publish from:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/aur_ed25519 -C "aur"
```

Show the public key and copy it:

```bash
cat ~/.ssh/aur_ed25519.pub
```

In the AUR website: **My Account** → **SSH Public Key** → paste the one line from `aur_ed25519.pub` → **Save**.

Use that key for `aur.archlinux.org` only. Add this to `~/.ssh/config`:

```
Host aur.archlinux.org
  User aur
  IdentityFile ~/.ssh/aur_ed25519
  IdentitiesOnly yes
```

Check the login (the first connection asks you to trust the host key):

```bash
ssh aur@aur.archlinux.org help
```

A short help text means the key works. There is no interactive shell.

## 4. Set the maintainer and license

Edit [`packaging/aur/PKGBUILD`](../packaging/aur/PKGBUILD). Replace the first line with your name and a real email:

```bash
# Maintainer: Ada Lovelace <ada@example.com>
```

This repository has no `LICENSE` file, so the PKGBUILD says `license=('unknown')`. If ContinuumDAO publishes an SPDX license, set `license=` to that identifier before the first push (for example `license=('Apache-2.0')`).

If you change `pkgname`, `pkgver`, `pkgrel`, `depends`, or `source`, regenerate metadata from an Arch machine (the next section) so `.SRCINFO` matches the PKGBUILD.

## 5. Build once on Arch, then refresh `.SRCINFO`

`makepkg` is part of Arch’s `base-devel` group. Run this on Arch, Omarchy, or another systemd Arch derivative, from a clone that already contains `packaging/aur/`:

```bash
sudo pacman -S --needed base-devel git
cd packaging/aur
makepkg -f
makepkg --printsrcinfo > .SRCINFO
```

`makepkg -f` clones mpc-config, sets `pkgver` from the Git history (`r<count>.<short-commit>`), and builds a package. Confirm the package contains the installer:

```bash
tar -tf mpa-wallet-git-*.pkg.tar.zst | grep install-node-arch.sh
```

Install it locally if you want to try the command before publishing:

```bash
makepkg -si
sudo mpa-wallet-install --help
```

Commit the regenerated `.SRCINFO` in **this** repository as well as in the AUR repository.

## 6. Push the AUR repository

The AUR Git repo holds only the package files, not the whole mpc-config tree.

```bash
git clone ssh://aur@aur.archlinux.org/mpa-wallet-git.git
cd mpa-wallet-git
```

An empty directory is expected the first time. Copy the five files from mpc-config:

```bash
cp /path/to/mpc-config/packaging/aur/PKGBUILD .
cp /path/to/mpc-config/packaging/aur/.SRCINFO .
cp /path/to/mpc-config/packaging/aur/mpa-wallet-git.install .
cp /path/to/mpc-config/packaging/aur/mpa-wallet-install .
cp /path/to/mpc-config/packaging/aur/mpa-wallet-uninstall .
```

Commit and push. The author of this commit should be the AUR account holder:

```bash
git add PKGBUILD .SRCINFO mpa-wallet-git.install mpa-wallet-install mpa-wallet-uninstall
git commit -m "Initial upload of mpa-wallet-git"
git push origin master
```

The AUR still uses the branch name `master` for package repositories.

When the push succeeds, the package page is:

[https://aur.archlinux.org/packages/mpa-wallet-git](https://aur.archlinux.org/packages/mpa-wallet-git)

## 7. What operators run

On Arch, with an AUR helper:

```bash
yay -S mpa-wallet-git
```

`paru` is the same package name. Without a helper:

```bash
sudo pacman -S --needed base-devel git
git clone https://aur.archlinux.org/mpa-wallet-git.git
cd mpa-wallet-git
makepkg -si
```

Then create the node:

```bash
sudo mpa-wallet-install --node-mgt-key 0xYour40Hex... --ip YOUR_PUBLIC_IPV4
sudo passwd mpcnode
```

Remove the node (this does not uninstall Docker or the `mpa-wallet-git` package):

```bash
sudo mpa-wallet-uninstall --help
```

Manjaro, EndeavourOS, Garuda, CachyOS, and Omarchy can install this AUR package the same way when their AUR helper is enabled. The node-map **Linux** command remains available for people who do not want the AUR package.

## 8. Update the package later

When `main` of mpc-config changes and the installed scripts should follow it:

1. On an Arch machine, `cd` to the AUR clone (`mpa-wallet-git`).
2. `makepkg -f` so `pkgver()` records the new commit.
3. `makepkg --printsrcinfo > .SRCINFO`
4. Copy the updated `.SRCINFO` (and any PKGBUILD edits) back into `mpc-config/packaging/aur/`.
5. Commit and `git push origin master` in the AUR clone.

Bump `pkgrel` when you change the PKGBUILD itself but the upstream Git commit did not change. `pkgver()` covers new upstream commits, so those updates usually keep `pkgrel` at `1`.
