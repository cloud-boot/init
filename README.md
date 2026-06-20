<p align="center"><img src="https://raw.githubusercontent.com/cloud-boot/brand/main/social/cloud-boot.png" alt="cloud-boot/init" width="720"></p>

# cloud-boot/init

PID-1 Go binary embedded in the cloud-boot bootstrap initramfs. Once
the firmware starts the UKI (built by [`../uki`](../uki)) this
binary runs as `/init` and, depending on the cmdline, either:

- fetches an HCL boot plan from an OCI registry and chain-boots a
  remote kernel + initrd via `kexec` (network / OCI mode), or
- mounts a local virtio-blk disk and `kexec`s into the distro's own
  `/boot/vmlinuz-*` + initrd (disk mode).

The host-side toolchain that assembles the UKI itself (cross-compile
init, build cpio.gz, build PE/UKI, build FAT ESP, build ISO) lives in
the sibling [`cloud-boot/uki`](../uki) repo. Shared infrastructure
(cpio writer, OCI v2 client) is exported here under `pkg/`.

```
┌─ boot.iso (xorriso, El Torito UEFI) ─────────────────────────────────────┐
│  /efiboot.img  (FAT16 ESP)                                               │
│     └─ /EFI/BOOT/BOOT{X64,AA64,RISCV64}.EFI   <- Unified Kernel Image    │
│                                                                          │
│   UKI = systemd UEFI stub (per arch)                                     │
│       + .linux    = vmlinuz (host)                                       │
│       + .initrd   = cpio.gz {/init = cloud-boot-init}                         │
│       + .cmdline  = "... cloudboot.plan=registry/repo:tag ..."               │
└─────────────────────────────┬────────────────────────────────────────────┘
                              │ firmware loads UKI
                              ▼
                   cloud-boot-init (PID 1, statically linked Go)
                              │ mount /proc /sys /dev /run
                              │ DHCPv4 on virtio-net (klibc ip= also OK)
                              │ HTTPS GET plan manifest (multi-arch idx OK)
                              │   └ plan layer (HCL) → pick target by GOARCH
                              │ HTTPS GET kernel / initrd / modules refs
                              │   └ each may be a multi-arch image index
                              │ concat initrd ++ modules.cpio.gz
                              │ kexec_file_load(kernel, final-initrd, cmd)
                              ▼
                     reboot(LINUX_REBOOT_CMD_KEXEC)
```

## Layout

| Path                 | Role |
| -------------------- | ---- |
| `cmd/cloud-boot-init` | PID 1 in the initramfs (Linux; cross-built for the target arch) |
| `pkg/cpio`           | newc cpio writer (exported — also consumed by [../uki](../uki)) |
| `pkg/oci`            | OCI Distribution v2 client (exported — pull at boot, push from host) |
| `internal/kexec`     | `kexec_file_load(2)` + `reboot(KEXEC)` wrapper |
| `internal/netconf`   | netlink link-up + DHCPv4 |
| `internal/cosign`    | Cosign signature verifier (PKIX key, simple-signing) |
| `internal/lldp`      | LLDP RX/TX over AF_PACKET (neighbor discovery + advert.) |
| `internal/plan`      | HCL plan parser + target selection (with EvalContext) |
| `examples/plan.hcl`  | Sample boot plan |

The host-side UKI assembly logic and the OCI push CLI moved to
[`../uki`](../uki) — `cloud-boot-build` and `cloud-boot-push`. The
pure-Go PE/COFF section appender stays in its own module
[`github.com/go-coff/pe`](https://github.com/go-coff/pe); during local
development a `replace` directive in [go.mod](go.mod) points at the
sibling checkout (`../../go-coff/pe`).

## Boot plan (HCL)

```hcl
default_target = "primary"

target "primary" {
    # `index` is the primary OCI ref — typically a multi-arch image
    # index whose per-arch manifest bundles kernel + initrd + modules
    # + cmdline as separate layers. cloud-boot-init merges all
    # recognised layers from this manifest into a single boot.
    index   = "registry.example.com/boot/linux:6.6"
    cmdline = "console=ttyS0 ro root=/dev/vda1"
}

target "rescue" {
    arch    = "amd64"   # optional arch filter
    # Role-specific refs (kernel / initrd / modules) override the
    # matching layer carried by `index`. Use them to swap one piece
    # without rebuilding the full bundle.
    kernel  = "registry.example.com/boot/rescue:latest"
    cmdline = "console=ttyS0 single"
}
```

The plan itself is pushed as an OCI artifact whose single layer carries
`application/vnd.cloudboot.plan.v1+hcl`.

### Target attribute reference

| Attribute | HCL type | Notes |
| --------- | -------- | ----- |
| `arch`    | string | Optional filter (`amd64` / `arm64` / `riscv64`). Plan.Pick skips non-matching targets. |
| `version` | string | Free-form release tag. Exposed inside the target as `self.version`. |
| `label`   | string | Shown in the interactive menu. |
| `index`   | string | Primary OCI ref (often a multi-arch index). |
| `kernel` / `initrd` / `modules` | string | Role-specific OCI refs. Override the matching layer from `index`. |
| `cmdline` | string **or** list of strings | List elements are joined with a single space — useful for multi-token cmdlines (see below). |
| `disk { … }` | block | Mutually exclusive with the OCI refs above. See *Disk mode*. |

### Cmdline as list

When a cmdline has many tokens, the list form keeps each on its own
line. Decode joins them with a single space:

```hcl
target "alpine" {
  version = "3.21"
  index   = "registry/alpine:${self.version}"
  cmdline = [
    "console=ttyS0",
    "ip={{.IPSpec}}",
    "alpine_repo=https://dl-cdn.alpinelinux.org/alpine/v${self.version}/main",
  ]
}
```

### `locals` and `self`

A top-level `locals { … }` block defines reusable values, evaluated
once against the plan's EvalContext (so they can themselves reference
`arch`, `lldp.*`, etc.). Inside a target, `self` exposes that target's
scalar fields (`self.name`, `self.arch`, `self.version`), so URLs and
labels can be composed without DRY violations:

```hcl
locals {
  registry    = "_oci._tcp.registry.example.com/boot"
  alpine_repo = "https://dl-cdn.alpinelinux.org/alpine"
  console     = arch == "arm64" ? "ttyAMA0" : "ttyS0"   # locals see `arch`
}

target "alpine" {
  version = "3.21"
  label   = "Alpine ${self.version}"
  index   = "${local.registry}/alpine:${self.version}"
  cmdline = [
    "console=${local.console}",
    "ip={{.IPSpec}}",
    "alpine_repo=${local.alpine_repo}/v${self.version}/main",
  ]
}
```

`self` only carries the scalars decoded *before* the per-target
expression pass — i.e. `name`, `arch`, `version`. Cross-referencing
the other resolved fields (e.g. `self.index`) is intentionally not
supported, since it would be circular.

### Cmdline templating (`{{.…}}`)

After HCL decoding, each target's cmdline goes through a Go
`text/template` pass against runtime facts cloud-boot has learned:

| Variable | Meaning |
| -------- | ------- |
| `{{.IP}}` / `{{.Netmask}}` / `{{.CIDR}}` / `{{.Gateway}}` / `{{.Iface}}` | DHCP-resolved (or static-`ip=`-supplied) network facts. |
| `{{.DNS}}` / `{{.DNSAll}}` | First / all DNS servers from the lease. |
| `{{.IPSpec}}` | Pre-built klibc `ip=` value: `client::gw:mask::iface:off[:dns0[:dns1]]`. Drop into `ip={{.IPSpec}}` so the next kernel reuses the lease instead of redoing DHCP. |
| `{{.Registry}}` | host:port of the OCI registry the target resolves to (SRV-resolved when applicable). |
| `{{.RegistryScheme}}` / `{{.RegistryBase}}` | Convenience: `http`/`https` and `<scheme>://<host>/v2`. |
| `{{.ModloopURL}}` | Full SRV-resolved OCI blob URL of the modloop layer when present. |

Templates that reference an unknown key render as the zero value
(`""`), so plans without any `{{…}}` are unaffected.

### DNS override

```hcl
dns = ["10.0.2.2", "1.1.1.1"]   # optional, replaces DHCP DNS
```

`cloudboot.dns=ip,ip,…` on the kernel cmdline takes precedence over
this field.

## Media types

| Layer | mediaType |
| ----- | --------- |
| vmlinuz | `application/vnd.cloud-boot.kernel.v1` |
| initrd  | `application/vnd.cloud-boot.initrd.v1` |
| modules | `application/vnd.cloud-boot.modules.v1.cpio+gzip` |
| modloop | `application/vnd.cloud-boot.modloop.v1+squashfs` |
| apkovl  | `application/vnd.cloud-boot.apkovl.v1+tar.gz` |
| cmdline | `application/vnd.cloudboot.cmdline.v1` |
| plan    | `application/vnd.cloudboot.plan.v1+hcl` |
| config  | `application/vnd.cloud-boot.boot.config.v1+json` |

### Alpine layers: modloop vs apkovl

`modloop` (squashfs) and `apkovl` (system overlay tar.gz) are Alpine-
specific layers handled differently at boot:

- **modloop**: served by URL. cloud-boot-init resolves the OCI host
  (incl. SRV) and auto-injects `modloop=<url>` on the kernel cmdline.
  Alpine's init wgets it at boot. We don't download it ourselves —
  it's typically 16 MB+ and embedding would bloat the initrd we
  kexec into.
- **apkovl**: downloaded by cloud-boot-init and **embedded** in the
  kexec'd initramfs as `/apkovl.tar.gz` (via a cpio.gz concat).
  Auto-injected as `apkovl=/apkovl.tar.gz`. We embed because
  Alpine's `unpack_apkovl` keys its codec on the filename suffix
  (`${ovl##*.}`); an OCI digest URL tail (`sha256:…`) doesn't end
  in `.gz`, which would mis-route into the encrypted-overlay
  branch and crash before `/tmp/repositories` is created. Apkovls
  are KB-scale, so the bloat is negligible.

Plans can still override either by setting `modloop=…` / `apkovl=…`
explicitly in the cmdline — auto-injection only fires when the
directive is absent.

**Known cosmetic quirk** — when Alpine's `/init` reaches its
`remount_fstab_entry` pass (after the apkovl has been unpacked), it
iterates over `$ovl` + `/tmp/repositories` and runs `df -P "$dir"`
to find the device backing each entry. For `$ovl = /apkovl.tar.gz`
the file lives on the initramfs rootfs, which doesn't appear in
`/proc/mounts` — so busybox-df writes `df: /apkovl.tar.gz: can't
find mount point` to stderr and produces the column header on
stdout, which then trips `stat: can't stat 'Filesystem'`. Both
messages are harmless: the function's own logic skips the entry
when no mount info comes back, and the boot completes. Suppressing
the warnings would require patching Alpine's `/init`, which is out
of scope for cloud-boot.

## Kernel command line

| Key | Meaning |
| --- | --- |
| `cloudboot.plan=<ref>`      | OCI ref of the HCL plan (preferred) |
| `cloudboot.image=<ref>`     | OCI ref of a single all-in-one image (legacy) |
| `cloudboot.target=<name>`   | Plan target selector |
| `cloudboot.cmdline=<text>`  | Override the cmdline for the chained kernel (OCI or disk mode) |
| `cloudboot.insecure=1`      | Allow plain HTTP for the plan reference |
| `cloudboot.lldp=0`          | Disable LLDP listen + transmit |
| `cloudboot.lldp.wait=<dur>` | LLDP receive timeout (default `10s`) |
| `cloudboot.lldp.tx=0`       | Disable LLDP transmit only |
| `cloudboot.lldp.name=<text>`| LLDP system-name advertised by this host |
| `cloudboot.cosign=enforce\|warn\|off` | Cosign policy when `/etc/cosign.pub` is present (default `enforce`). `warn` logs failures and continues; `off` skips verification entirely. |
| `cloudboot.dns=ip,ip,…`     | Override DHCP-supplied DNS resolvers before the plan-fetch SRV lookup. Takes precedence over the plan's `dns = […]` field. Useful when the plan registry sits behind a private resolver. |
| `ip=<klibc spec>`           | Static IPv4 instead of DHCP |
| `rd.cloudboot.user=...`     | Registry basic-auth username |
| `rd.cloudboot.pass=...`     | Registry basic-auth password |
| `cloudboot.disk=<device>`   | **Disk mode**: mount this device, kexec into its `/boot` kernel |
| `cloudboot.disk.fs=<type>`  | Filesystem type for `cloudboot.disk` (default `ext4`) |
| `cloudboot.disk.kernel=<path>` | Pin a specific kernel under the mount (default: newest `/boot/vmlinuz-*`) |
| `cloudboot.disk.initrd=<path>` | Pin a specific initrd (default: paired with the kernel) |

## Disk mode

In addition to the OCI / plan-based path, `cloud-boot-init` can also
boot a **local distro** that's already installed on a virtio-blk
disk. This is the typical pattern when the bootstrap UKI lives in
the ESP and the rest of the system is on `/dev/vda2`:

```sh
cloudboot.disk=/dev/vda2
```

flips the init into a stripped-down code path:

1. Mount `/dev/vda2` (ext4 by default) on `/mnt` read-only.
2. Find a kernel: explicit `cloudboot.disk.kernel=…`, or the newest
   `/mnt/boot/vmlinuz-*`.
3. Pair an initrd by version suffix: `initrd.img-X` (Debian / Ubuntu),
   `initramfs-X.img` (Fedora / RHEL), or `initrd-X` (Arch / openSUSE).
4. Build the next kernel's cmdline from `cloudboot.cmdline=…` or
   `/mnt/etc/kernel/cmdline` if present.
5. `kexec_file_load` + `reboot(LINUX_REBOOT_CMD_KEXEC)`.

No network is brought up, no LLDP, no OCI client, no cosign. This is
the right mode for "ephemeral cloud guest where the rootfs already
holds the distro kernel I want to run". Pair with the
[`Dockerfile.{arm64,amd64}-disk`](https://github.com/cloud-boot/kernel)
bootstrap kernels (tiny + virtio + ext4 + kexec, ~2.5 MiB).

## LLDP-aware plans

After bringing the link up, `cloud-boot-init` opens an `AF_PACKET` socket and waits
up to `cloudboot.lldp.wait` for one LLDP frame from the upstream switch. The
decoded TLVs are exposed to the HCL plan as a `lldp` object:

| Variable             | Meaning |
| -------------------- | ------- |
| `lldp.available`     | `true` if any LLDP TLV was decoded |
| `lldp.chassis_id`    | Switch chassis MAC (or other subtype value) |
| `lldp.port_id`       | Upstream port ID (typically the iface name) |
| `lldp.system_name`   | `sysName` advertised by the switch |
| `lldp.system_desc`   | `sysDescr` advertised by the switch |
| `lldp.port_desc`     | Port description (e.g. VLAN label) |
| `lldp.mgmt_addr`     | First management address (v4 or v6) |

In parallel the init transmits one LLDP frame announcing the host (chassis ID
= NIC MAC, port ID = iface, system name = `cloud-boot-<arch>` or
`cloudboot.lldp.name=`), so the switch's LLDP neighbor table sees the booting
machine. Both directions can be disabled selectively from the cmdline.

Plan fields are HCL expressions, so:

```hcl
target "primary" {
  kernel  = "registry.example.com/boot/linux:6.6"
  cmdline = lldp.available
    ? "console=ttyS0 hostname=node-${lldp.port_id}"
    : "console=ttyS0"
}
```

## High availability via DNS SRV

Any OCI reference whose host portion matches the RFC 2782 service-name shape
— `_<service>._tcp.<zone>` or `_<service>._udp.<zone>` — is resolved at
boot by querying DNS for SRV records. The replicas are tried in
priority-ascending / weight-randomised order, with automatic failover on
TCP connection errors, request timeouts, and HTTP 5xx / 408 / 429 responses.
A 30-second in-process cache avoids hammering the resolver on multi-blob
pulls.

```hcl
target "primary" {
  kernel  = "_oci._tcp.registry.example.com/boot/linux:6.6"
  initrd  = "_oci._tcp.registry.example.com/boot/initrd:fedora"
  modules = "_oci._tcp.registry.example.com/boot/modules:6.6"
}
```

Example BIND zone:

```dns
_oci._tcp.registry.example.com. 60 IN SRV 10 50 443 reg-a.example.com.
_oci._tcp.registry.example.com. 60 IN SRV 10 50 443 reg-b.example.com.
_oci._tcp.registry.example.com. 60 IN SRV 20  0 443 reg-dr.example.com.
```

The plan reference baked into the boot UKI (`cloudboot.plan=...`) may itself
use an SRV host: that single string becomes both the bootstrap registry
and the source of truth for every artifact reference inside the plan.
Bearer-token auth is cached per logical SRV name, so re-auth doesn't fire
on each replica swap.

## Multi-arch

- `cloud-boot-build -arch amd64|arm64|riscv64` cross-compiles the init for the
  target arch and selects the right systemd stub
  (`linuxx64.efi.stub`/`linuxaa64.efi.stub`/`linuxriscv64.efi.stub`) and the
  right EFI fallback name (`BOOTX64.EFI`/`BOOTAA64.EFI`/`BOOTRISCV64.EFI`).
- `cloud-boot-push artifact -platform linux/amd64 ...` pushes a single-arch
  manifest (the platform info goes both into the config blob and, later,
  into the index entry).
- `cloud-boot-push index -p linux/amd64=<ref-amd64> -p linux/arm64=<ref-arm64>
  <out-ref>` writes an OCI image index pinning each arch.
- At boot, `cloud-boot-init` walks each ref using `runtime.GOARCH`; if the ref
  points at an index, the matching child manifest is fetched.

## Build dependencies (host)

`go` 1.22+, `mformat`/`mmd`/`mcopy` (mtools), `xorriso`, a Linux `vmlinuz` for
the target arch (with `CONFIG_EFI_STUB`, `CONFIG_VIRTIO_NET`,
`CONFIG_VIRTIO_PCI`, `CONFIG_DEVTMPFS`, `CONFIG_KEXEC_FILE`), and the matching
systemd UEFI stub.

The PE section assembly is done in pure Go (via
[`github.com/go-coff/pe`](https://github.com/go-coff/pe)) so
**binutils/objcopy is not required**.

On macOS: `brew install mtools xorriso qemu` and fetch the kernel + stub from
any Linux distro image.

## Quickstart

All workflow commands go through [Taskfile.yaml](Taskfile.yaml) (install
[Task](https://taskfile.dev) → `brew install go-task`). Run `task -l` for a
full list.

```sh
# 1) Local OCI registry on :5000
task registry

# 2) Push per-arch kernel (and optional initrd/modules) artifacts
task push:artifact ARCH=amd64 \
        KERNEL=./payload/vmlinuz-amd64 \
        INITRD=./payload/initrd-amd64.img \
        MODULES=./payload/modules-amd64.cpio.gz \
        IMAGE=127.0.0.1:5000/boot/linux:6.6-amd64

task push:artifact ARCH=arm64 \
        KERNEL=./payload/vmlinuz-arm64 \
        INITRD=./payload/initrd-arm64.img \
        MODULES=./payload/modules-arm64.cpio.gz \
        IMAGE=127.0.0.1:5000/boot/linux:6.6-arm64

# 3) (optional) Combine the per-arch manifests into a multi-arch index
task push:index \
        PLATFORMS="linux/amd64=127.0.0.1:5000/boot/linux@sha256:...,linux/arm64=127.0.0.1:5000/boot/linux@sha256:..." \
        INDEX_REF=127.0.0.1:5000/boot/linux:6.6

# 4) Push the boot plan that references those refs
task push:plan PLAN=examples/plan.hcl PLAN_REF=127.0.0.1:5000/boot/plan:latest

# 5) Build an ISO for the host arch you intend to boot
task iso ARCH=amd64 \
         KERNEL=./host/vmlinuz-amd64 \
         STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub \
         PLAN_REF=127.0.0.1:5000/boot/plan:latest \
         INSECURE=1

# 6) Boot
task qemu          # amd64 (x86_64) defaults
task qemu:arm64    # arm64 sensible defaults
```

### Packing modules from a host

```sh
./bin/cloud-boot-push modpack -src /lib/modules/6.6.0-amd64 -o modules-amd64.cpio.gz
```

(Equivalent to: `cd /lib/modules && find 6.6.0-amd64 | cpio -o -H newc | gzip`,
but rooted at `lib/modules/<release>/`.)

## How modules end up on the booted kernel

`kexec_file_load(2)` accepts a single initrd FD. The Linux early-init code
handles **concatenated gzipped cpio archives** natively (each terminated by
its own `TRAILER!!!` entry). cloud-boot-init therefore appends `modules.cpio.gz`
to the downloaded initrd byte-for-byte before kexec'ing.

## Security notes

- Prefer HTTPS in production (drop `-insecure`).
- Pulled blobs are SHA-256 verified against the manifest digests.
- Trust comes from the CA bundle Go's `crypto/x509` finds at the standard
  paths; ship `/etc/ssl/certs/ca-certificates.crt` in the initramfs if you
  use a private CA.

### Cosign signatures

Generate a key pair with `cosign generate-key-pair` (or use an existing one).
Embed the public key into the ISO at build time:

```sh
task iso ARCH=amd64 \
         KERNEL=./host/vmlinuz \
         STUB=/usr/lib/systemd/boot/efi/linuxx64.efi.stub \
         PLAN_REF=127.0.0.1:5000/boot/plan:latest \
         COSIGN_KEY=./cosign.pub
```

(`cloud-boot-build -cosign-key cosign.pub` writes the key into the initramfs at
`/etc/cosign.pub`.) Then sign each plan/artifact pushed:

```sh
cosign sign --key cosign.key registry.example.com/boot/plan@sha256:...
```

At boot, `cloud-boot-init` reads `/etc/cosign.pub`, fetches the legacy
`<repo>:sha256-<digest>.sig` tag for the plan manifest, and verifies the
simple-signing envelope (ECDSA / RSA / Ed25519) against the SHA-256 of the
referenced digest. The chain of trust then runs *signed plan → manifest
digests → blob digests* — **so the plan must reference digests, not tags**,
for end-to-end integrity:

```hcl
target "primary" {
  kernel  = "registry/boot/linux@sha256:abc123..."
  initrd  = "registry/boot/initrd@sha256:def456..."
  modules = "registry/boot/modules@sha256:789abc..."
  cmdline = "console=ttyS0 ro"
}
```

`cloudboot.cosign=warn` logs verification failures and continues; `cloudboot.cosign=off`
disables verification entirely. Keyless (Fulcio + Rekor) verification is not
yet supported — it would require online connectivity to Fulcio and Rekor at
boot, plus X.509 OID-based identity validation.

## Limitations / TODO

- No IPv6 / no DHCPv6 yet.
- Cosign verification is **key-based only**. Keyless (Fulcio + Rekor) would
  add ~500 LOC and require network reachability to public CAs at boot.
- Plan HCL is intentionally minimal — variants by mac, hostname, dynamic
  evaluation contexts beyond LLDP are not implemented yet.

## A note on `github.com/go-coff/pe`

The pure-Go PE/COFF section appender lives in its own module
[`github.com/go-coff/pe`](https://github.com/go-coff/pe). It exposes a
single `Append([]byte, []Section) ([]byte, error)`, has no dependencies
outside the standard library, and ships a small CLI (`pe-objcopy`) that
covers the `objcopy --add-section` use case targeted by UKI assembly.
Targeted at the systemd UEFI stub shape (PE32+, pre-allocated header
padding, 8-char section names) but works on any conforming PE32/PE32+ that
has at least one free section-header slot within `SizeOfHeaders`.

For local development of both repos in parallel, cloud-boot's [go.mod](go.mod)
uses a `replace` directive pointing at the sibling checkout
`../go-coff/pe`. Drop the directive once the module is published.
