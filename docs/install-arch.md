# Installing smolvm on Arch Linux

smolvm ships an **official pacman repository** maintained by the smol-machines
team. It serves prebuilt packages for `x86_64` and `aarch64`, updated
automatically with every release.

> The `smolvm`, `smolvm-bin` and `smolvm-git` packages on the AUR are
> third-party and not maintained by us. As of 1.4.7 they link against the
> stock Arch `libkrun`, which lacks six symbols smolvm needs — disk overlays,
> snapshots and egress policy do not work with those packages. The official
> package bundles the smol-machines libkrun fork and is fully functional.

## Setup

Add the repository to `/etc/pacman.conf`:

```ini
[smol-machines]
SigLevel = Optional TrustAll
Server = https://github.com/smol-machines/smolvm/releases/download/pacman-repo-$arch
```

Then install:

```sh
sudo pacman -Sy smolvm
```

Upgrades arrive with your normal `pacman -Syu`.

## Notes

- The repository is served from rolling GitHub releases
  (`pacman-repo-x86_64`, `pacman-repo-aarch64`); packages are built by CI
  from the signed release artifacts (`.github/workflows/pacman-repo.yml`).
- Package signing (GPG) is planned; until then integrity is provided by
  sha256-pinned sources built in CI and served over HTTPS.
- The package bundles the smol-machines `libkrun`/`libkrunfw` fork under
  `/usr/lib/smolvm/lib` — it does not conflict with the system `libkrun`
  package, which other software may continue to use.
