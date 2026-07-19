# Asterinas Envnt upstreaming ledger

**Status:** active product integration
**Last organized:** 2026-07-18

This repository has one live branch for the Envnt/Asterinas machine:
`feat/asterinas-envnt-machine`. It is the branch Envnt should use. It is an
integration branch, not a pull-request branch for the canonical SmolVM project.

## Repository roles

| Repository | Role | Write target |
| --- | --- | --- |
| `regularkevvv/smolvm` (`origin`) | Our fork and integration home | allowed |
| `smol-machines/smolvm` (`upstream`) | Canonical SmolVM | fetch-only |
| `regularkevvv/libkrun` (`fork`) | Our libkrun fork and temporary product dependency | allowed |
| `smol-machines/libkrun` | Canonical libkrun | fetch-only |

Canonical remotes have an intentionally invalid push URL. A change travels to
canonical upstream through a reviewed PR from our fork, never through a direct
push.

## Branch map

| Branch | Role | Rule |
| --- | --- | --- |
| `main` | Mirror of canonical `smol-machines/smolvm:main` | Fast-forward from `upstream/main`, then push to `origin/main`. Do not add product commits here. |
| `feat/asterinas-envnt-machine` | Live Envnt/Asterinas product integration | Merge or rebase updated `main` here after each upstream sync. This is the only branch for running the product. |
| `feat/runtime-egress-proxy` | Preserved source for the runtime-egress PR series | Do not merge this historical branch into an upstream PR. Make a fresh PR branch from current `upstream/main` and cherry-pick/rebase the series. |
| `feat/custom-kernel-boot` | Preserved source for the custom-guest-kernel proposal | Treat as a broad upstream proposal; split only if maintainers request it. |
| `feat/asterinas-guest-profile` and `feat/asterinas-aarch64-smp` | Historical snapshots of product work | Retained as a ledger only. `feat/asterinas-envnt-machine` supersedes them. |

When preparing a canonical SmolVM contribution, create a short-lived branch
such as `pr/smolvm/runtime-egress` directly from `upstream/main`. Keep product
integration commits and merge commits out of that PR branch.

## SmolVM change map

| Change | Commits | Classification | Upstream route |
| --- | --- | --- | --- |
| Runtime SOCKS5 egress proxy, lifecycle hardening, and tests | `a3659c9`, `1068bd6`, `b8a3a6b` | Generic SmolVM feature and fixes | Strong PR candidate to `smol-machines/smolvm`. Rebase as one focused series. |
| Custom guest-kernel support | `cd6b32c` | Generic capability, but broad | PR candidate to canonical SmolVM. Discuss scope with maintainers before splitting it. |
| Golden-clone lifecycle fix | `f6f69e9` | Generic correctness fix, dependent on custom-kernel support | Send after or with the accepted custom-kernel base. |
| Asterinas guest compatibility profile | `8e3f02d` | Product-specific, with possibly separable generic runtime pieces | Keep in the product branch. Propose a profile upstream only if maintainers want to own Asterinas support. |
| Egress-proxy integration merge | `2e0c471` | Integration-only merge | Never submit upstream. |
| Asterinas AArch64 SMP policy and profile enablement | `7b7b97f` | Product-specific policy and documentation | Keep in the product branch; prerequisite architecture support belongs in libkrun. |

The canonical changes through `a0bd544` (CUDA and Docker-socket work included)
are already in our `main`; they are not our patch series.

## Submodule map

| Submodule | Product pin | Classification and routing |
| --- | --- | --- |
| `libkrun` | `regularkevvv/libkrun`, branch `feat/asterinas-envnt-machine`, commit `dd41440` | Required by this product until canonical libkrun carries the series. The six commits below are generic libkrun PR candidates. |
| `libkrunfw` | Canonical pin `37f73dadb7e64610642d7041c163b8dbf0e9a1ef` | Untouched canonical dependency; no outgoing patch. |
| `smolvm-sdk` | Canonical pin `7eaafa4e4b6640864ef51a71fea7bb57901b4dd6` | Untouched canonical dependency; no outgoing patch. |

The `libkrun` series at `dd41440` is based directly on canonical libkrun main:

1. `9d78293` — FDT AArch64 root-node correctness.
2. `462ce3e` — console activation for single-port guests.
3. `fbd92fc` — explicit virtiofs root support.
4. `376cc75` — virtio-block used-length correctness.
5. `a46fede` — inactive-console restore correctness.
6. `dd41440` — preserve the AArch64 PSCI `CPU_ON` context ID.

These are runtime and architecture fixes, not Asterinas-only code. Submit them
as ordered, focused PRs from `regularkevvv/libkrun`; do not submit the SmolVM
submodule pointer as a substitute for the individual libkrun patches. Once
canonical libkrun accepts the necessary commits, update this branch's pointer
back to the corresponding canonical commit and restore the canonical submodule
URL.

## Sync and contribution routine

1. Fetch `upstream`, fast-forward local `main` to `upstream/main`, and push
   that fast-forward to `origin/main`.
2. Merge or rebase `main` into `feat/asterinas-envnt-machine`; resolve only
   product integration conflicts there.
3. Build each proposed upstream fix on a fresh branch from the relevant
   canonical upstream (`smolvm` or `libkrun`), then open a PR from our fork.
4. After an upstream merge, fast-forward `main` and replace the corresponding
   product patch or fork pin with the canonical result.

This gives Envnt one stable integration branch while keeping every upstream
proposal reviewable and independent.
