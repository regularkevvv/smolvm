# Custom guest kernels

SmolVM can boot a host-supplied kernel instead of the kernel bundled in
`libkrunfw`. This is an experimental local-machine feature intended for kernel
development and compatibility testing.

```bash
smolvm machine create \
  --name custom \
  --kernel ./Image \
  --kernel-format raw \
  --initramfs ./initramfs.cpio \
  --kernel-cmdline 'console=hvc0' \
  --guest-profile linux

smolvm machine start --name custom
smolvm machine exec --name custom -- uname -a
```

`machine run` accepts the same five boot options for an ephemeral VM. Supported
kernel formats are `raw`, `elf`, `pe-gz`, `image-gz`, `image-bz2`, and
`image-zstd`; the value is passed to libkrun's `krun_set_kernel` API.

## Artifact ownership and integrity

At machine creation SmolVM copies the kernel and optional initramfs into the
machine's `guest-boot/` data directory and records SHA-256 checksums. It never
persists the caller's source path. Every start resolves the fixed staged names
under that machine's data directory and verifies the files before creating a
VMM context.

- `machine delete` removes the staged files with the rest of the machine data.
- A local machine clone receives independent copies and re-verifies them.
- `pack create --from-vm` rejects custom-kernel machines in this release. Their
  boot artifacts are deliberately local-only until the pack format owns them.

The checksum detects accidental or local post-creation modification; it is not
a signature or a statement of provenance. A supplied kernel and initramfs are
trusted guest code and retain access to every disk, mount, and network device
the user attaches to the VM.

## Asterinas bootstrap profile

`--guest-profile asterinas` preserves libkrun's normal userspace contract while
booting an external Asterinas kernel:

```bash
smolvm machine create \
  --name asterinas \
  --net \
  --kernel ./aster-kernel-osdk-bin.qemu_bin \
  --kernel-format raw \
  --guest-profile asterinas
```

SmolVM obtains libkrun's embedded `init.krun`, builds a newc initramfs around
it, and supplies the exact command-line values needed to mount libkrun's
virtiofs root and execute the existing Alpine `/sbin/init`. A caller-provided
raw or gzip-compressed newc archive is augmented without discarding its other
entries. An archive that already contains a different `init.krun` is rejected.

The profile requires `init=/init.krun`, `rootfstype=virtiofs`,
`KRUN_VIRTIOFS_ROOT_DEVICE=/dev/root`, and `KRUN_ALLOW_PRIVATE_ROOT=1`.
Conflicting values fail at creation. SmolVM supplies `console=hvc0`, `earlycon`,
`loglevel=error`, and `rw` only when the caller did not choose an equivalent
option.

With `--net`, the profile also selects Asterinas's narrow preconfigured-network
contract. SmolVM forces the virtio-net backend, presents the gateway and DNS at
`10.0.2.2`, and routes published ports to the kernel-owned
`10.0.2.15/24` address. IPv6 is disabled for this profile. The guest agent
preserves the kernel's address, MAC, MTU, interface flags, and routes; it only
installs `/etc/resolv.conf` and continues its normal readiness/control work.
An explicit `--net-backend tsi` is rejected rather than silently overriding
the profile. The ordinary `linux` profile and no-network Asterinas boots retain
their existing behavior.

This is intentionally an MVP compatibility contract for Asterinas's current
static network. It can converge toward SmolVM's dynamic Linux network profile
after Asterinas supports the required address and route mutation APIs.

The installed libkrun must export `krun_set_kernel` and, for the Asterinas
profile, `krun_get_default_init`. Asterinas early-console output additionally
uses libkrun's serial-console API. SmolVM reports a bounded update/setup error
when a required API is unavailable.

Asterinas persistent storage uses base ext2 with 4 KiB blocks for both the
writable root overlay and `/storage`; `/workspace` continues to point at that
storage disk. The host therefore needs e2fsprogs (`mkfs.ext2`) the first time a
disk is prepared. Linux guests retain the existing ext4 template path and disk
markers, so selecting the Asterinas profile does not change their storage
contract. The guest also formats an uninitialized disk as ext2 if host-side
formatting was unavailable.
