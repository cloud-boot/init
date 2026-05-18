//go:build linux

// cloud-boot-init runs as PID 1 inside the initramfs embedded in the UKI.
// It mounts pseudo-filesystems, brings up the network, fetches a boot plan
// from an OCI registry (HCL), resolves the matching target for the current
// architecture, pulls the referenced kernel / initrd / kernel-modules images
// — using OCI image indexes for multi-arch resolution — concatenates the
// modules cpio onto the initrd, then kexecs into the new kernel.
//
// Two boot paths share the same init binary and are selected by the
// kernel command line:
//
//   1. **Network / OCI**: fetch an HCL boot plan (or a single image) from
//      an OCI registry, pull kernel+initrd+modules, kexec.
//   2. **Local disk**: mount a virtio-blk device, find the distro's own
//      kernel + initrd under /boot, kexec. No network needed.
//
// Configuration read from the kernel command line:
//
//   OCI mode:
//	cloudboot.plan=<ref>          OCI reference of an HCL boot plan (preferred)
//	cloudboot.image=<ref>         legacy single-image mode (no plan)
//	cloudboot.target=<name>       plan target selector (skips the menu)
//	cloudboot.menu=0|1            force the interactive boot menu off / on
//	cloudboot.menu.timeout=<dur>  override the plan's menu.timeout ("5s", "10")
//	cloudboot.menu.prompt=<text>  override the plan's menu prompt header
//	cloudboot.cmdline=<text>      override the cmdline passed to the downloaded kernel
//	cloudboot.insecure=1          allow plain HTTP for the plan reference
//	cloudboot.lldp=0              disable LLDP listen + transmit
//	cloudboot.lldp.wait=<dur>     how long to wait for an LLDP neighbor (default 10s)
//	cloudboot.lldp.tx=0           disable LLDP transmit only
//	cloudboot.lldp.name=<text>    LLDP system-name advertised by this host
//	cloudboot.cosign=enforce|warn|off  policy when /etc/cosign.pub is present
//	                          (default: enforce; warn logs and continues;
//	                          off disables signature checks entirely)
//	cloudboot.dns=ip[,ip...]  override the DHCP-supplied resolvers before
//	                          the plan-fetch SRV lookup. Useful when the
//	                          plan registry only resolves via a private
//	                          DNS (dev SRV records, internal CoreDNS …).
//	                          Takes precedence over the plan's `dns = []`
//	                          field.
//	ip=<klibc spec>           static IPv4 instead of DHCP
//	rd.cloudboot.user=...     registry basic-auth user
//	rd.cloudboot.pass=...     registry basic-auth pass
//
//   Disk mode (selected when cloudboot.disk= is present):
//	cloudboot.disk=<device>       device to mount, e.g. /dev/vda2
//	cloudboot.disk.fs=<type>      filesystem type (default ext4)
//	cloudboot.disk.kernel=<path>  pin a specific kernel (default: newest /boot/vmlinuz-*)
//	cloudboot.disk.initrd=<path>  pin a specific initrd (default: paired with the kernel)
//	cloudboot.cmdline=<text>      forwarded as the new kernel's cmdline
//
// On any fatal error we sleep forever (PID 1 must not exit) so console logs
// stay visible.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/template"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/cloud-boot/init/internal/cosign"
	"github.com/cloud-boot/init/internal/kexec"
	"github.com/cloud-boot/init/internal/lldp"
	"github.com/cloud-boot/init/internal/menu"
	"github.com/cloud-boot/init/internal/netconf"
	"github.com/cloud-boot/init/pkg/oci"
	"github.com/cloud-boot/init/internal/plan"
)

const downloadDir = "/run/cloud-boot"

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetPrefix("cloud-boot: ")
	if err := run(); err != nil {
		log.Printf("FATAL: %v", err)
		for {
			time.Sleep(time.Hour)
		}
	}
}

func run() error {
	if err := mountPseudoFS(); err != nil {
		return fmt.Errorf("mount pseudo-fs: %w", err)
	}
	if err := os.MkdirAll(downloadDir, 0o755); err != nil {
		return err
	}

	cmd, err := readCmdline()
	if err != nil {
		return err
	}

	// Disk mode short-circuits the rest of the OCI pipeline: no network,
	// no plan, no signature verification — just mount + kexec.
	if cmd["cloudboot.disk"] != "" {
		log.Printf("arch=%s booting from local disk %s",
			runtime.GOARCH, cmd["cloudboot.disk"])
		return runDisk(diskParamsFromCmdline(cmd))
	}

	log.Printf("arch=%s booting via cmdline keys plan=%q image=%q target=%q",
		runtime.GOARCH, cmd["cloudboot.plan"], cmd["cloudboot.image"], cmd["cloudboot.target"])

	log.Printf("bringing up network")
	netCfg, err := netconf.Setup(cmd["ip"])
	if err != nil {
		return fmt.Errorf("network: %w", err)
	}
	// cloudboot.dns=ip,ip,... overrides whatever DHCP wrote into
	// /etc/resolv.conf, before any SRV lookup happens. Useful when the
	// plan registry's SRV record only resolves via a non-default DNS
	// (typical dev setup). The plan can also declare a DNS override
	// further down — see applyDNSOverride.
	if applyDNSOverride(cmd["cloudboot.dns"], "cmdline") {
		oci.ClearSRVCache()
	}

	// LLDP is non-blocking: start the listener now so it runs in parallel
	// with newClient + loadCosign + the plan/manifest fetch in
	// resolveTarget. At HCL evaluation time we'll peek at whatever Facts
	// arrived in the meantime — see pollLLDP / startLLDP for the contract.
	lldpCh := startLLDP(netCfg.Iface, cmd)

	client := newClient(cmd)

	verifier, err := loadCosign(cmd)
	if err != nil {
		return fmt.Errorf("cosign: %w", err)
	}

	target, planDNS, err := resolveTarget(client, cmd, pollLLDP(lldpCh), verifier)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}
	// Plan-level DNS override is applied AFTER the plan is fetched: it
	// can't influence the plan-fetch itself (chicken/egg) but it shapes
	// every SRV lookup the target / modloop / etc. refs do afterwards.
	// Cmdline `cloudboot.dns=` already took effect at startup and wins
	// over the plan, so skip if the cmdline knob was set.
	if cmd["cloudboot.dns"] == "" && len(planDNS) > 0 {
		if applyDNSOverride(strings.Join(planDNS, ","), "plan") {
			oci.ClearSRVCache()
		}
	}

	// Disk-typed targets bypass OCI materialisation entirely: cloud-boot-init
	// mounts the local device and kexecs into the kernel that already lives
	// on it. Nothing is pulled from the registry for this target.
	if target.Disk != nil {
		log.Printf("target=%q disk=%s (boot kernel already on disk)",
			target.Name, target.Disk.Device)
		return runDisk(diskParamsFromTarget(target, cmd))
	}

	// Log only the refs the plan actually set, by role:
	//
	//   index=<ref>    — primary OCI ref, manifest may bundle multiple
	//                    layers (kernel + initrd + modules + cmdline)
	//   kernel=<ref>   — kernel-only ref (overrides index's kernel)
	//   initrd=<ref>   — initrd-only ref (overrides index's initrd)
	//   modules=<ref>  — modules-only ref (overrides index's modules)
	//
	// Empty role-specific fields don't mean "no such layer" — the
	// primary index can carry them. The per-layer progress lines + the
	// "kexec load" line below show what's actually downloaded.
	insecure := cmd["cloudboot.insecure"] == "1"
	var parts []string
	if target.Index != "" {
		parts = append(parts, "index="+target.Index)
	}
	if target.Kernel != "" {
		parts = append(parts, "kernel="+target.Kernel)
	}
	if target.Initrd != "" {
		parts = append(parts, "initrd="+target.Initrd)
	}
	if target.Modules != "" {
		parts = append(parts, "modules="+target.Modules)
	}
	if target.Cmdline != "" {
		// Pre-render against the variables we already know (network
		// from DHCP, registry from SRV) so the log shows e.g.
		// `ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off` instead
		// of the raw `ip={{.IPSpec}}` template. ModloopURL isn't
		// known until pullArtifact runs, so we feed it a self-
		// templating sentinel — it survives this pass and resolves
		// for real inside materialize.
		displayVars := buildCmdlineVars(target, insecure, "{{.ModloopURL}}", netCfg)
		parts = append(parts, fmt.Sprintf("cmdline=%q", renderCmdline(target.Cmdline, displayVars)))
	}
	log.Printf("target=%q %s", target.Name, strings.Join(parts, " "))

	kPath, iPath, kArgs, err := materialize(client, target, insecure, netCfg)
	if err != nil {
		return fmt.Errorf("materialize: %w", err)
	}
	if v := cmd["cloudboot.cmdline"]; v != "" {
		kArgs = v
	}

	log.Printf("kexec load (kernel=%s initrd=%s cmdline=%q)", kPath, iPath, kArgs)
	if err := kexec.Load(kPath, iPath, kArgs); err != nil {
		return fmt.Errorf("kexec load: %w", err)
	}
	log.Printf("kexec boot")
	return kexec.Boot()
}

func newClient(cmd map[string]string) *oci.Client {
	c := oci.NewClient()
	if u, ok := cmd["rd.cloudboot.user"]; ok {
		c.Username = u
	}
	if p, ok := cmd["rd.cloudboot.pass"]; ok {
		c.Password = p
	}
	return c
}

// loadCosign reads /etc/cosign.pub (if present, embedded by cloud-boot-build) and
// returns a Verifier. Absent file → nil, nil (signature verification off).
func loadCosign(cmd map[string]string) (*cosign.Verifier, error) {
	if cmd["cloudboot.cosign"] == "off" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile("/etc/cosign.pub")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	v, err := cosign.ParsePublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	log.Printf("cosign: signature verification enabled (mode=%s)",
		modeOrDefault(cmd["cloudboot.cosign"], "enforce"))
	return v, nil
}

// verifyManifest invokes the cosign verifier on ref and applies the policy
// described by cloudboot.cosign=enforce|warn (default enforce).
func verifyManifest(v *cosign.Verifier, c *oci.Client, ref *oci.Ref, mode string) error {
	if v == nil {
		return nil
	}
	err := v.Verify(c, ref)
	if err == nil {
		log.Printf("cosign OK: %s/%s:%s", ref.Host, ref.Repo, ref.Reference)
		return nil
	}
	if mode == "warn" {
		log.Printf("cosign WARN (ignored): %v", err)
		return nil
	}
	return err
}

// resolveTarget returns the chosen Target plus any plan-level DNS
// override the caller should apply before the target's refs are
// fetched. Three modes:
//
//   - cloudboot.plan=<ref>  : fetch + decode the HCL plan, run target
//                             selection, return the picked Target and
//                             p.DNS so main() can re-write resolv.conf.
//   - cloudboot.image=<ref> : synth a one-target "legacy-image" plan
//                             with the ref as Index; no DNS override.
//   - neither               : error.
//
// facts (may be nil) is exposed to plan expressions as the "lldp"
// variable. v (may be nil) verifies cosign signatures over the plan
// manifest.
func resolveTarget(c *oci.Client, cmd map[string]string, facts *lldp.Facts, v *cosign.Verifier) (*plan.Target, []string, error) {
	if planRef := cmd["cloudboot.plan"]; planRef != "" {
		ref, err := oci.ParseRef(planRef)
		if err != nil {
			return nil, nil, err
		}
		if cmd["cloudboot.insecure"] == "1" {
			ref.Scheme = "http"
		}
		if err := verifyManifest(v, c, ref, cmd["cloudboot.cosign"]); err != nil {
			return nil, nil, fmt.Errorf("plan signature: %w", err)
		}
		m, _, err := c.PullManifestForPlatform(ref, "linux", runtime.GOARCH)
		if err != nil {
			return nil, nil, fmt.Errorf("plan manifest: %w", err)
		}
		hclBytes, err := findAndPullLayer(c, ref, m, oci.MediaTypePlan, "plan")
		if err != nil {
			return nil, nil, err
		}
		p, err := plan.Decode(hclBytes, "plan.hcl", plan.EvalContext(runtime.GOARCH, facts))
		if err != nil {
			return nil, nil, err
		}
		name, err := selectTarget(p, cmd, runtime.GOARCH)
		if err != nil {
			return nil, nil, err
		}
		t, err := p.Pick(name, runtime.GOARCH)
		if err != nil {
			return nil, nil, err
		}
		return t, p.DNS, nil
	}
	if imgRef := cmd["cloudboot.image"]; imgRef != "" {
		// cloudboot.image= is a single-ref legacy shorthand; treat the
		// pointed-at artifact as an index (its manifest may bundle
		// multiple layers).
		return &plan.Target{Name: "legacy-image", Index: imgRef}, nil, nil
	}
	return nil, nil, fmt.Errorf("missing cloudboot.plan= or cloudboot.image= on cmdline")
}

// applyDNSOverride parses spec as a comma-separated list of IPs and,
// if at least one is valid, rewrites /etc/resolv.conf with that set.
// source ("cmdline" / "plan") is the tag that goes into the log line
// — handy when diagnosing precedence between cmdline and plan DNS in
// the post-mortem dmesg. Empty spec or all-invalid → no-op (returns
// false) so the prior resolv.conf keeps its place.
func applyDNSOverride(spec, source string) bool {
	if strings.TrimSpace(spec) == "" {
		return false
	}
	var ips []net.IP
	for _, s := range strings.Split(spec, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			log.Printf("dns: %s override: skipping invalid IP %q", source, s)
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return false
	}
	netconf.WriteResolvConf(ips)
	log.Printf("dns: %s override → %v", source, ips)
	return true
}

// selectTarget decides which target name to pass to Plan.Pick. Precedence:
//
//  1. cloudboot.target=<name> on cmdline → use it verbatim (skip menu)
//  2. cloudboot.menu=0 on cmdline → skip menu, use DefaultTarget
//  3. plan menu{} block present or cloudboot.menu=1 → render the interactive
//     menu against /dev/console with the configured timeout
//  4. otherwise → DefaultTarget (an empty name lets Pick fall back to the
//     single-target case)
//
// cmdline knobs that influence menu behaviour:
//
//	cloudboot.menu=0|1                force menu off / on
//	cloudboot.menu.timeout=<dur>      override Menu.Timeout (e.g. "10s")
//	cloudboot.menu.prompt=<text>      override Menu.Prompt
func selectTarget(p *plan.Plan, cmd map[string]string, arch string) (string, error) {
	if explicit := cmd["cloudboot.target"]; explicit != "" {
		return explicit, nil
	}
	if cmd["cloudboot.menu"] == "0" {
		return p.DefaultTarget, nil
	}
	want := cmd["cloudboot.menu"] == "1" || p.Menu != nil
	if !want {
		return p.DefaultTarget, nil
	}
	cfg, err := buildMenuConfig(p, cmd, arch)
	if err != nil {
		log.Printf("menu: disabled (%v); booting default", err)
		return p.DefaultTarget, nil
	}
	if len(cfg.Options) <= 1 {
		// Nothing to choose — emit a single-target boot directly.
		return p.DefaultTarget, nil
	}
	choice, err := menu.Prompt(cfg)
	if err != nil {
		log.Printf("menu: %v; booting default", err)
		return p.DefaultTarget, nil
	}
	return choice, nil
}

// buildMenuConfig assembles a menu.Config from the plan, the cmdline
// overrides, and the eligible target list for arch. console (if openable)
// is preferred over os.Stdin/Stderr so menu I/O lands on the real serial
// console even when stdio has been redirected.
func buildMenuConfig(p *plan.Plan, cmd map[string]string, arch string) (menu.Config, error) {
	opts := make([]menu.Option, 0, len(p.Targets))
	for _, t := range p.EligibleTargets(arch) {
		opts = append(opts, menu.Option{Name: t.Name, Label: t.Label})
	}
	if len(opts) == 0 {
		return menu.Config{}, fmt.Errorf("no targets eligible for arch %s", arch)
	}

	pm := p.Menu
	if pm == nil {
		pm = &plan.Menu{}
	}
	timeout, err := pm.TimeoutDuration()
	if err != nil {
		return menu.Config{}, fmt.Errorf("plan menu.timeout: %w", err)
	}
	if v := cmd["cloudboot.menu.timeout"]; v != "" {
		override := &plan.Menu{Timeout: v}
		d, err := override.TimeoutDuration()
		if err != nil {
			return menu.Config{}, fmt.Errorf("cloudboot.menu.timeout: %w", err)
		}
		timeout = d
	}
	prompt := pm.Prompt
	if v := cmd["cloudboot.menu.prompt"]; v != "" {
		prompt = v
	}

	in, out := openConsole()
	return menu.Config{
		Out:     out,
		In:      in,
		Prompt:  prompt,
		Timeout: timeout,
		Default: p.DefaultTarget,
		Options: opts,
	}, nil
}

// openConsole returns the pair of streams to use for the menu UI. It tries
// /dev/console first (so output appears even when stdio has been redirected
// by the kernel), and falls back to os.Stdin/os.Stderr otherwise.
func openConsole() (io.Reader, io.Writer) {
	if f, err := os.OpenFile("/dev/console", os.O_RDWR, 0); err == nil {
		return f, f
	}
	return os.Stdin, os.Stderr
}

// startLLDP kicks off LLDP advertise + listen in background goroutines and
// returns a single-use channel that yields the decoded Facts once a
// neighbor responds (or nil once cloudboot.lldp.wait elapses with no
// frame). The caller polls the channel non-blockingly at the moment it
// actually needs the facts (right before HCL plan evaluation), so the
// LLDP listen overlaps with the OCI plan / cosign fetch path that follows
// — it never blocks the boot.
//
// LLDP is opportunistic context: any error or timeout is logged and
// non-fatal, and the boot proceeds with nil facts (lldp.available =
// false in plan expressions). On a real network with an LLDP-emitting
// switch the listen typically wins within a couple seconds and the
// facts are in hand by the time resolveTarget needs them; on QEMU /
// link-local-only setups the channel never fires and we proceed without.
//
// Knobs (cmdline):
//
//	cloudboot.lldp=0              disable LLDP entirely
//	cloudboot.lldp.tx=0           disable LLDP transmit (still listen)
//	cloudboot.lldp.wait=<dur>     max listen window in background (default 10s)
//	cloudboot.lldp.name=<text>    system-name advertised by tx
func startLLDP(iface string, cmd map[string]string) <-chan *lldp.Facts {
	out := make(chan *lldp.Facts, 1)
	if cmd["cloudboot.lldp"] == "0" {
		close(out)
		return out
	}
	if cmd["cloudboot.lldp.tx"] != "0" {
		go func() {
			name := cmd["cloudboot.lldp.name"]
			if name == "" {
				name = "cloud-boot-" + runtime.GOARCH
			}
			if err := lldp.Send(iface, name, "cloud-boot-init"); err != nil {
				log.Printf("lldp tx: %v", err)
			}
		}()
	}
	wait := 10 * time.Second
	if v := cmd["cloudboot.lldp.wait"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			wait = d
		}
	}
	if wait <= 0 {
		close(out)
		return out
	}
	log.Printf("lldp: listening on %s in background for up to %s", iface, wait)
	go func() {
		defer close(out)
		f, err := lldp.Listen(iface, wait)
		if err != nil {
			log.Printf("lldp: no neighbor (%v)", err)
			return
		}
		log.Printf("lldp neighbor: chassis=%s port=%s system=%q desc=%q",
			f.ChassisID, f.PortID, f.SystemName, f.SystemDesc)
		out <- f
	}()
	return out
}

// pollLLDP returns whatever Facts startLLDP has produced by now without
// blocking. If the listen is still in flight or the channel was closed
// without a frame, the result is nil — the caller proceeds with
// lldp.available=false in plan expressions.
func pollLLDP(ch <-chan *lldp.Facts) *lldp.Facts {
	select {
	case f := <-ch:
		return f
	default:
		return nil
	}
}

// materialize pulls the kernel/initrd/modules referenced by the target and
// returns the final on-disk paths to feed kexec. modules.cpio.gz, if present,
// is appended to the initrd file in place (the kernel handles concatenated
// gzipped cpio archives natively).
//
// Cosign signatures are deliberately NOT checked on these artifacts: the
// plan was verified up-front in resolveTarget(), and each layer pulled here
// is content-addressed by SHA-256 in the manifest. The chain of trust runs
// "signed plan → manifest digests → blob digests".
func materialize(c *oci.Client, t *plan.Target, insecure bool, netCfg *netconf.Config) (kernel, initrd, cmdline string, err error) {
	// Cache pulls keyed by ref string so the same ref referenced for several
	// roles is fetched only once.
	cache := map[string]*pulled{}
	get := func(ref string) (*pulled, error) {
		if r, ok := cache[ref]; ok {
			return r, nil
		}
		p, err := pullArtifact(c, ref, insecure)
		if err != nil {
			return nil, err
		}
		cache[ref] = p
		return p, nil
	}

	// Layer-precedence semantics (see plan.Target doc): Index forms the
	// baseline, then role-specific refs override the matching layer.
	// pick(cur, candidate) keeps `candidate` when non-empty so later
	// iterations win.
	var k, i, m, mlURL, ovPath, c2 string
	merge := func(r *pulled) {
		k = pick(k, r.kernel)
		i = pick(i, r.initrd)
		m = pick(m, r.modules)
		mlURL = pick(mlURL, r.modloopURL)
		ovPath = pick(ovPath, r.apkovlPath)
		c2 = pick(c2, r.cmdline)
	}
	if t.Index != "" {
		r, err := get(t.Index)
		if err != nil {
			return "", "", "", fmt.Errorf("index ref: %w", err)
		}
		merge(r)
	}
	if t.Kernel != "" {
		r, err := get(t.Kernel)
		if err != nil {
			return "", "", "", fmt.Errorf("kernel ref: %w", err)
		}
		merge(r)
	}
	if t.Initrd != "" {
		r, err := get(t.Initrd)
		if err != nil {
			return "", "", "", fmt.Errorf("initrd ref: %w", err)
		}
		merge(r)
	}
	if t.Modules != "" {
		r, err := get(t.Modules)
		if err != nil {
			return "", "", "", fmt.Errorf("modules ref: %w", err)
		}
		merge(r)
	}
	if k == "" {
		return "", "", "", fmt.Errorf("no kernel layer found in any referenced artifact")
	}
	// If an apkovl was pulled, wrap it as a cpio.gz with the file
	// surfaced at `/apkovl.tar.gz` in the kexec'd kernel's initramfs.
	// Concatenating that on top of the Alpine initrd makes the file
	// available before /init runs; Alpine then sees `apkovl=` pointing
	// at a local `.gz` file and takes the plain tar.gz unpack branch.
	var apkovlCpio string
	if ovPath != "" {
		apkovlCpio = filepath.Join(downloadDir, "apkovl.cpio.gz")
		if err := wrapAsCpioGz(ovPath, "apkovl.tar.gz", apkovlCpio); err != nil {
			return "", "", "", fmt.Errorf("wrap apkovl: %w", err)
		}
	}

	// Build the final initramfs by concatenating: initrd (if any) +
	// modules (if any) + apkovl-cpio (if any). The Linux kernel unpacks
	// the concatenated stream of gzipped cpio archives transparently.
	// Skip the temp file if only one piece exists.
	pieces := nonEmpty(i, m, apkovlCpio)
	var final string
	switch len(pieces) {
	case 0:
	case 1:
		final = pieces[0]
	default:
		final = filepath.Join(downloadDir, "initrd.joined")
		if err := concat(final, pieces...); err != nil {
			return "", "", "", fmt.Errorf("concat initrd extras: %w", err)
		}
	}
	cmdline = t.Cmdline
	if cmdline == "" {
		cmdline = c2
	}
	// Substitute Go-template variables in the cmdline so plan authors
	// can reference the SRV-resolved registry without hardcoding a
	// host. Built-in variables are documented on cmdlineVars below.
	cmdline = renderCmdline(cmdline, buildCmdlineVars(t, insecure, mlURL, netCfg))
	// Auto-inject `modloop=<url>` and `apkovl=/apkovl.tar.gz` when the
	// matching layer is present and the cmdline doesn't already set
	// the directive. Modloop stays URL-served (16 MB+ squashfs — too
	// big to embed); apkovl is embedded in the initrd above and
	// referenced by its fixed local path.
	if mlURL != "" && !strings.Contains(cmdline, "modloop=") {
		cmdline = appendSpaced(cmdline, "modloop="+mlURL)
	}
	if apkovlCpio != "" && !strings.Contains(cmdline, "apkovl=") {
		cmdline = appendSpaced(cmdline, "apkovl=/apkovl.tar.gz")
	}
	return k, final, cmdline, nil
}

// appendSpaced returns `a + " " + b`, or just b when a is empty. Used
// to glue auto-injected cmdline directives onto the rendered cmdline
// without leaving a leading space.
func appendSpaced(a, b string) string {
	if a == "" {
		return b
	}
	return a + " " + b
}

// cmdlineVars are the substitution variables exposed to Go-template
// expressions inside plan cmdlines. They resolve at materialize time
// against the target's primary OCI ref:
//
//	{{.Registry}}        host[:port] of the OCI registry. If the plan
//	                     ref's host is an RFC-2782 SRV name
//	                     (`_<svc>._tcp.<zone>`) this is the first
//	                     concrete endpoint returned by ResolveEndpoints
//	                     (priority + weight ordered). Otherwise the
//	                     host is passed through unchanged.
//	{{.RegistryScheme}}  "http" or "https". `cloudboot.insecure=1`
//	                     forces http.
//	{{.RegistryBase}}    "{{.RegistryScheme}}://{{.Registry}}/v2" —
//	                     prebuilt base URL for OCI blob endpoints.
//	{{.ModloopURL}}      Full OCI blob URL of the modloop layer when
//	                     the artifact carries one (already SRV-resolved).
//	                     Empty when no modloop layer is present.
//
// (Apkovl has no template var: it's embedded in the initramfs at the
// fixed path `/apkovl.tar.gz` and auto-injected onto the cmdline as
// `apkovl=/apkovl.tar.gz` when an apkovl layer is present.)
//
// Network facts (from the DHCP / static lease cloud-boot already
// negotiated) let plan authors pass the lease through to the next
// kernel so it can skip a second round of DHCP — particularly handy
// for Alpine's initramfs, which honours the klibc `ip=` form:
//
//	{{.IP}}              Client IPv4 address ("192.168.1.10").
//	{{.Netmask}}         Dotted netmask ("255.255.255.0").
//	{{.CIDR}}            "{{.IP}}/<prefix-len>" — for tools that want
//	                     a single addr/prefix token.
//	{{.Gateway}}         Default route, or "" if none was learned.
//	{{.Iface}}           Kernel interface name we configured ("eth0").
//	{{.DNS}}             First DNS server from the lease, or "".
//	{{.DNSAll}}          All DNS servers as a string slice; use with
//	                     text/template's `index` or `range`.
//	{{.IPSpec}}          Pre-built klibc `ip=` value (without the
//	                     "ip=" prefix):
//	                       client::gw:mask::iface:off[:dns0[:dns1]]
//	                     Drop this into "ip={{.IPSpec}}" to reuse the
//	                     cloud-boot lease instead of `ip=dhcp`.
//
// Templates that reference an unknown key render as `<no value>`
// rather than erroring; that keeps backward-compat: existing plans
// with no `{{...}}` aren't affected.
type cmdlineVars struct {
	Registry       string
	RegistryScheme string
	RegistryBase   string
	ModloopURL     string

	IP      string
	Netmask string
	CIDR    string
	Gateway string
	Iface   string
	DNS     string
	DNSAll  []string
	IPSpec  string
}

func buildCmdlineVars(t *plan.Target, insecure bool, modloopURL string, netCfg *netconf.Config) cmdlineVars {
	v := cmdlineVars{ModloopURL: modloopURL}
	if netCfg != nil {
		v.Iface = netCfg.Iface
		if ip4 := netCfg.Addr.IP.To4(); ip4 != nil {
			v.IP = ip4.String()
		} else if netCfg.Addr.IP != nil {
			v.IP = netCfg.Addr.IP.String()
		}
		if netCfg.Addr.Mask != nil {
			v.Netmask = net.IP(netCfg.Addr.Mask).String()
			if ones, _ := netCfg.Addr.Mask.Size(); ones > 0 && v.IP != "" {
				v.CIDR = fmt.Sprintf("%s/%d", v.IP, ones)
			}
		}
		if netCfg.Gateway != nil {
			v.Gateway = netCfg.Gateway.String()
		}
		if len(netCfg.DNS) > 0 {
			v.DNSAll = make([]string, 0, len(netCfg.DNS))
			for _, ip := range netCfg.DNS {
				v.DNSAll = append(v.DNSAll, ip.String())
			}
			v.DNS = v.DNSAll[0]
		}
		// klibc ip= positional form. autoconf=off keeps the kernel /
		// initramfs from running their own DHCP/RARP; we hand them a
		// fully-populated lease instead. DNS slots tack on at the end
		// when DHCP gave us resolvers, so /etc/resolv.conf inside the
		// next root gets seeded for free.
		parts := []string{v.IP, "", v.Gateway, v.Netmask, "", v.Iface, "off"}
		for i := 0; i < len(v.DNSAll) && i < 2; i++ {
			parts = append(parts, v.DNSAll[i])
		}
		v.IPSpec = strings.Join(parts, ":")
	}
	primary := firstNonEmpty(t.Index, t.Kernel, t.Initrd, t.Modules)
	if primary == "" {
		return v
	}
	ref, err := oci.ParseRef(primary)
	if err != nil {
		return v
	}
	v.RegistryScheme = ref.Scheme
	if insecure {
		v.RegistryScheme = "http"
	}
	v.Registry = ref.Host
	if oci.IsSRVHost(ref.Host) {
		if eps, err := oci.ResolveEndpoints(ref.Host); err == nil && len(eps) > 0 {
			v.Registry = eps[0].Host
		}
	}
	v.RegistryBase = v.RegistryScheme + "://" + v.Registry + "/v2"
	return v
}

// renderCmdline runs the cmdline through text/template with vars. The
// fast path bails when there's no `{{` token, so plain-text cmdlines
// pay zero parser cost. Render failures fall back to the raw cmdline
// with a warning — surprising substitution is worse than not boot at
// all because of a typo'd template.
func renderCmdline(in string, vars cmdlineVars) string {
	if !strings.Contains(in, "{{") {
		return in
	}
	tpl, err := template.New("cmdline").Option("missingkey=zero").Parse(in)
	if err != nil {
		log.Printf("cmdline template parse: %v; using raw cmdline", err)
		return in
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, vars); err != nil {
		log.Printf("cmdline template render: %v; using raw cmdline", err)
		return in
	}
	return buf.String()
}

// firstNonEmpty returns the first non-zero string from its arguments,
// or "" if all are empty. Helper for picking the "primary" OCI ref out
// of (Index, Kernel, Initrd, Modules).
func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// nonEmpty returns the input strings filtered for empty values. Used to
// flatten "(maybe) initrd + (maybe) modules" into the argument list
// for concat.
func nonEmpty(s ...string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

type pulled struct {
	kernel, initrd, modules, cmdline string
	// modloopURL is the OCI blob URL we hand to Alpine-style inits as
	// `modloop=<url>`. We *don't* download the squashfs to disk —
	// embedding 16 MB+ into the initramfs we kexec into would bloat the
	// initrd for no gain. Pointing Alpine straight at the registry's
	// content-addressed blob endpoint keeps the initrd lean and matches
	// our DNS-SRV-aware OCI HA story for the rest of the layers.
	modloopURL string
	// apkovlPath is the local on-disk path of the downloaded apkovl
	// blob. Unlike modloop, we *do* embed it — Alpine's init derives
	// the unpack codec from the filename suffix (`${ovl##*.}`), and an
	// OCI blob URL's tail (`sha256:…`) doesn't end in `.gz`, so Alpine
	// would mis-route into the encrypted-apkovl branch and try to
	// `apk add openssl` before /tmp/repositories exists. Embedding as
	// `/apkovl.tar.gz` via a cpio.gz concat sidesteps the whole mess.
	// Apkovls are small (KB-scale), so the initrd bloat is negligible.
	apkovlPath string
}

// pullArtifact resolves a (possibly multi-arch) OCI ref to a single
// manifest for runtime.GOARCH and downloads every recognised layer in
// parallel to /run/cloud-boot.
//
// Per-layer progress is logged at 25/50/75/100% (or every ~1 s for slow
// connections, whichever fires first). We deliberately avoid carriage-
// return / ANSI cursor tricks — the serial console + QEMU stdio + host
// terminal path doesn't render mpb-style multi-bar overlays reliably
// (tried, bars came out invisible), and interleaved progress lines from
// concurrent goroutines stay readable as plain `[label] xx% (a / b)`
// log entries.
//
// Parallelism is bounded by the number of layers in the manifest (usually
// 1-3: kernel, initrd, modules). The shared net/http Transport pools TCP
// connections per host, so concurrent PullBlob calls reuse the same
// connection on HTTP/2 — or get a small fan-out of TCP streams on HTTP/1.1.
//
// No cosign check happens here on purpose — see materialize()'s comment.
func pullArtifact(c *oci.Client, refStr string, insecure bool) (*pulled, error) {
	ref, err := oci.ParseRef(refStr)
	if err != nil {
		return nil, err
	}
	if insecure {
		ref.Scheme = "http"
	}
	m, _, err := c.PullManifestForPlatform(ref, "linux", runtime.GOARCH)
	if err != nil {
		return nil, err
	}

	type layerResult struct {
		kind, path, cmdline, modloopURL string
	}
	results := make([]layerResult, len(m.Layers))
	errs := make([]error, len(m.Layers))
	var wg sync.WaitGroup
	start := time.Now()
	var downloadedBytes int64

	for i, l := range m.Layers {
		i, l := i, l
		title := l.Annotations[ocispec.AnnotationTitle]
		kind := resolveKind(l.MediaType, title)
		label := kind
		if label == "" {
			label = title
		}
		if label == "" {
			label = "layer"
		}

		// Modloop is pointed at, not downloaded — we hand the OCI blob
		// URL to Alpine's init via cmdline (`modloop=<url>`) and let it
		// wget the squashfs at boot. Keeps the initramfs small and
		// reuses the registry's content-addressed storage instead of
		// re-packing 16 MB+ on every boot.
		//
		// If the registry host is an RFC-2782 SRV name we resolve it to
		// a concrete host:port here, because Alpine's wget does plain
		// hostname lookup (no SRV). The OCI blob digest is immutable so
		// the resolved host serves the same bytes any peer would.
		//
		// Apkovl, in contrast, *is* downloaded (the fall-through below):
		// Alpine's init keys its unpack codec on the filename suffix and
		// an OCI digest URL doesn't end in `.gz`, so we embed it into
		// the initramfs at the fixed local path /apkovl.tar.gz instead.
		if kind == "modloop" {
			host := ref.Host
			if oci.IsSRVHost(host) {
				if eps, srvErr := oci.ResolveEndpoints(host); srvErr == nil && len(eps) > 0 {
					host = eps[0].Host
				}
			}
			url := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", ref.Scheme, host, ref.Repo, l.Digest)
			results[i] = layerResult{kind: kind, modloopURL: url}
			log.Printf("  %s: %s served from %s", kind, humanBytes(l.Size), url)
			continue
		}

		path := filepath.Join(downloadDir, sanitize(title+"-"+l.Digest.Encoded()))
		log.Printf("  %s: pulling %s -> %s", label, humanBytes(l.Size), filepath.Base(path))
		atomic.AddInt64(&downloadedBytes, l.Size)

		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := os.Create(path)
			if err != nil {
				errs[i] = fmt.Errorf("%s: create: %w", label, err)
				return
			}
			pw := newProgressWriter(f, label, l.Size)
			_, pullErr := c.PullBlob(ref, l.Digest, pw)
			closeErr := f.Close()
			if pullErr != nil {
				errs[i] = fmt.Errorf("%s: pull: %w", label, pullErr)
				return
			}
			if closeErr != nil {
				errs[i] = fmt.Errorf("%s: close: %w", label, closeErr)
				return
			}
			results[i] = layerResult{kind: kind, path: path}
			if kind == "cmdline" {
				b, _ := os.ReadFile(path)
				results[i].cmdline = strings.TrimSpace(string(b))
			}
		}()
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return nil, e
		}
	}

	out := &pulled{}
	for _, r := range results {
		switch r.kind {
		case "kernel":
			out.kernel = r.path
		case "initrd":
			out.initrd = r.path
		case "modules":
			out.modules = r.path
		case "modloop":
			out.modloopURL = r.modloopURL
		case "apkovl":
			out.apkovlPath = r.path
		case "cmdline":
			out.cmdline = r.cmdline
		}
	}
	elapsed := time.Since(start)
	if elapsed > 0 && downloadedBytes > 0 {
		mbps := float64(downloadedBytes) / (1 << 20) / elapsed.Seconds()
		log.Printf("  pulled %s in %s (%.1f MB/s)", humanBytes(downloadedBytes), elapsed.Truncate(time.Millisecond), mbps)
	}
	return out, nil
}

// progressWriter logs progress at 25 / 50 / 75 / 100 % crossings of
// `total`, plus a heartbeat every second so very slow connections still
// get feedback. Stateless lines mean concurrent goroutines can interleave
// cleanly on a serial console without trying to share cursor position.
type progressWriter struct {
	w        io.Writer
	label    string
	total    int64
	done     atomic.Int64
	lastPct  int
	lastTick time.Time
}

func newProgressWriter(w io.Writer, label string, total int64) *progressWriter {
	return &progressWriter{w: w, label: label, total: total, lastTick: time.Now()}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.done.Add(int64(n))
	d := p.done.Load()

	if p.total > 0 {
		pct := int(d * 100 / p.total)
		for _, t := range []int{25, 50, 75, 100} {
			if p.lastPct < t && pct >= t {
				log.Printf("  %s: %3d%% (%s / %s)", p.label, t, humanBytes(d), humanBytes(p.total))
				p.lastPct = t
				p.lastTick = time.Now()
				break
			}
		}
		return n, err
	}
	// Unknown total: heartbeat every second.
	if time.Since(p.lastTick) >= time.Second {
		log.Printf("  %s: %s", p.label, humanBytes(d))
		p.lastTick = time.Now()
	}
	return n, err
}

// humanBytes formats a byte count with a base-1024 SI-ish unit, so log
// lines stay short on slow consoles (`9.2 MB` vs `9626112 B`).
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// findAndPullLayer downloads the first layer in m matching the given mediaType
// and returns its raw bytes.
func findAndPullLayer(c *oci.Client, ref *oci.Ref, m *ocispec.Manifest, mediaType, label string) ([]byte, error) {
	for _, l := range m.Layers {
		if l.MediaType != mediaType {
			continue
		}
		var buf bytes.Buffer
		if _, err := c.PullBlob(ref, l.Digest, &buf); err != nil {
			return nil, fmt.Errorf("%s blob: %w", label, err)
		}
		return buf.Bytes(), nil
	}
	return nil, fmt.Errorf("%s: no layer with mediaType %s", label, mediaType)
}

func mountPseudoFS() error {
	type m struct{ src, dst, fstype string }
	for _, e := range []m{
		{"proc", "/proc", "proc"},
		{"sys", "/sys", "sysfs"},
		{"dev", "/dev", "devtmpfs"},
		{"run", "/run", "tmpfs"},
	} {
		_ = os.MkdirAll(e.dst, 0o755)
		if err := syscall.Mount(e.src, e.dst, e.fstype, 0, ""); err != nil {
			if err != syscall.EBUSY {
				return fmt.Errorf("mount %s: %w", e.dst, err)
			}
		}
	}
	return nil
}

