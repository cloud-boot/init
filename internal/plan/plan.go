// Package plan parses HCL boot plans pulled from an OCI registry.
//
// A plan describes one or more targets; each target points at an OCI
// primary ref (`index`, typically a multi-arch image index whose
// manifest bundles kernel + initrd + modules + cmdline layers) and/or
// role-specific refs (`kernel` / `initrd` / `modules`) that override
// individual layers. Each referenced ref may itself be a multi-arch
// OCI index; arch resolution happens at pull time, not at plan
// parse time.
//
// HCL example:
//
//	default_target = "primary"
//
//	locals {
//	  registry = "_oci._tcp.registry.example.com/boot"
//	  console  = arch == "arm64" ? "ttyAMA0" : "ttyS0"   # locals see `arch`
//	}
//
//	target "primary" {
//	    version = "6.6"
//	    label   = "Production Linux ${self.version}"
//	    index   = "${local.registry}/linux:${self.version}"
//	    cmdline = "console=${local.console} ro root=/dev/vda1"
//	}
//
//	target "rescue" {
//	    arch    = "amd64"   # optional arch filter
//	    kernel  = "${local.registry}/rescue:latest"
//	    cmdline = [
//	      "console=${local.console}",
//	      "single",
//	      "rd.break",
//	    ]
//	}
//
// Top-level expressions evaluate against an EvalContext exposing
// "arch" (runtime arch) and "lldp" (neighbor facts; .available is
// false when no frame was observed). Inside a target, a per-target
// child context additionally exposes "self" with that target's
// scalars (`self.name`, `self.arch`, `self.version`) so attribute
// expressions can compose values without DRY violations.
//
// Cmdline accepts either a string or a list of strings (joined with
// a single space) for readable multi-token cmdlines.
package plan

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"

	"github.com/cloud-boot/init/internal/lldp"
)

// Plan is the decoded top-level HCL document.
type Plan struct {
	DefaultTarget string   `hcl:"default_target,optional"`
	// DNS lists IP addresses to write into /etc/resolv.conf after the
	// plan has been parsed, replacing whatever DHCP supplied. Useful
	// when the plan's target refs sit behind an SRV name that only
	// resolves via a private DNS (typical dev setup: bring up the
	// guest with public DNS, fetch the plan, then switch to the dev
	// DNS for the target/modloop fetches). `cloudboot.dns=ip,ip,...`
	// on the kernel cmdline takes precedence over this field.
	DNS           []string `hcl:"dns,optional"`
	Menu          *Menu    `hcl:"menu,block"`
	Targets       []Target `hcl:"target,block"`
}

// Menu configures the interactive boot-time chooser. When nil (block absent
// from the plan), no menu is shown and DefaultTarget is selected directly.
// Timeout is parsed by time.ParseDuration ("5s", "1m30s") or, for ergonomics,
// a bare integer is accepted and interpreted as seconds.
type Menu struct {
	Timeout string `hcl:"timeout,optional"` // "5s" / "10" / "1m30s"; "" disables
	Prompt  string `hcl:"prompt,optional"`  // header text; default supplied by caller
}

// Target describes one bootable selection. Either at least one OCI ref
// (Index / Kernel / Initrd / Modules) must be set or Disk must be set —
// the two modes are mutually exclusive. Decode validates that.
//
// The four OCI fields name their role-by-convention:
//
//	Index   — primary ref. Typically an OCI image index (multi-arch
//	          manifest list) whose target manifest carries the full
//	          bundle of layers: kernel + initrd + (modules) + (cmdline).
//	          This is what `task push:alpine:multi` pushes for the
//	          Alpine smoke target, and what production bundles usually
//	          look like.
//	Kernel  — ref whose manifest carries *only* a kernel layer.
//	Initrd  — ref whose manifest carries *only* an initrd layer.
//	Modules — ref whose manifest carries *only* a modules cpio.gz layer.
//
// Mechanically, cloud-boot-init pulls every set ref and merges all
// layers it recognises by media type. Index is processed first so its
// layers form a baseline; an explicit Kernel / Initrd / Modules ref
// then overrides the matching role. This lets you, e.g., bundle a
// stock kernel via Index and swap just the initrd via Initrd.
type Target struct {
	Name    string `hcl:"name,label"`
	Arch    string `hcl:"arch,optional"`    // optional filter: amd64|arm64|riscv64
	Version string `hcl:"version,optional"` // free-form release tag, exposed as `self.version`
	// The label / OCI-ref / cmdline attributes are kept as
	// hcl.Expression instead of plain string so they can reference the
	// `self` variable (`self.name`, `self.arch`, `self.version`) when
	// composing values. Decode evaluates each against a per-target
	// EvalContext after the scalar fields (Name / Arch / Version) are
	// known. The decoded textual form lands in the matching plain-
	// string field below — that's what every other package reads.
	//
	// CmdlineExpr additionally accepts a list of strings (joined with
	// a single space) for readable multi-token cmdlines, e.g.
	//   cmdline = [
	//     "console=ttyS0",
	//     "ip={{.IPSpec}}",
	//     "alpine_repo=${local.alpine_repo}/${self.version}/main",
	//   ]
	LabelExpr   hcl.Expression `hcl:"label,optional"`
	IndexExpr   hcl.Expression `hcl:"index,optional"`
	KernelExpr  hcl.Expression `hcl:"kernel,optional"`
	InitrdExpr  hcl.Expression `hcl:"initrd,optional"`
	ModulesExpr hcl.Expression `hcl:"modules,optional"`
	CmdlineExpr hcl.Expression `hcl:"cmdline,optional"`
	// SubplanExpr makes the target a CHAINED PLAN reference rather
	// than something directly bootable. When set (and non-empty
	// after eval), init fetches the referenced OCI plan, decodes
	// it, and runs target selection on the inner plan — letting
	// an embedded boot.iso ship a tiny static menu whose entries
	// expand into live plans pulled from a registry. Mutually
	// exclusive with the OCI/disk fields.
	SubplanExpr hcl.Expression `hcl:"subplan,optional"`
	Disk        *Disk          `hcl:"disk,block"` // when set, boot from a local disk

	// Resolved string forms, populated by Decode. No HCL tag —
	// gohcl skips them.
	Label   string
	Index   string
	Kernel  string
	Initrd  string
	Modules string
	Cmdline string
	Subplan string
}

// Disk selects "kexec into the kernel that already lives on a local block
// device" instead of fetching one from OCI. cloud-boot-init mounts Device
// read-only, picks Kernel (or the newest /boot/vmlinuz-*) and Initrd (paired
// with the kernel by version suffix), then kexecs with Target.Cmdline.
type Disk struct {
	Device string `hcl:"device"`           // e.g. "/dev/vda2" (required)
	FS     string `hcl:"fs,optional"`      // filesystem; defaults to ext4
	Kernel string `hcl:"kernel,optional"`  // path on the mounted disk; default newest /boot/vmlinuz-*
	Initrd string `hcl:"initrd,optional"`  // path on the mounted disk; default paired with kernel
}

// Decode parses HCL bytes; filename governs the parser (must end in .hcl or .json).
// ctx supplies the variables and functions used during expression evaluation.
//
// Plans may declare a single `locals { … }` block at the top level whose
// attributes are evaluated against ctx (so they can themselves reference
// `arch`, `lldp.*`, etc.) and re-exposed under a `local` namespace for
// the rest of the file. This mirrors Terraform's locals semantics and
// lets multiple targets share a value — typically the SRV-shaped
// registry host:
//
//	locals {
//	  registry = "_oci._tcp.registry.example.com/boot"
//	}
//
//	target "alpine"  { index = "${local.registry}/alpine:3.21" … }
//	target "primary" { index = "${local.registry}/linux:6.6"   … }
func Decode(data []byte, filename string, ctx *hcl.EvalContext) (*Plan, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(data, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("plan parse: %s", diags.Error())
	}
	// Two-pass decode: pull the `locals` block out first so its
	// attributes can land in ctx before the targets reference them.
	body := file.Body
	content, remain, diags := body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "locals"}},
	})
	if diags.HasErrors() {
		return nil, fmt.Errorf("plan locals: %s", diags.Error())
	}
	locals := map[string]cty.Value{}
	for _, b := range content.Blocks {
		attrs, diags := b.Body.JustAttributes()
		if diags.HasErrors() {
			return nil, fmt.Errorf("plan locals attrs: %s", diags.Error())
		}
		for name, attr := range attrs {
			v, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() {
				return nil, fmt.Errorf("plan locals %s: %s", name, diags.Error())
			}
			locals[name] = v
		}
	}
	augmented := ctx
	if len(locals) > 0 {
		augmented = &hcl.EvalContext{
			Variables: make(map[string]cty.Value, len(ctx.Variables)+1),
			Functions: ctx.Functions,
		}
		for k, v := range ctx.Variables {
			augmented.Variables[k] = v
		}
		augmented.Variables["local"] = cty.ObjectVal(locals)
	}

	var p Plan
	if diags := gohcl.DecodeBody(remain, augmented, &p); diags.HasErrors() {
		return nil, fmt.Errorf("plan decode: %s", diags.Error())
	}
	for i := range p.Targets {
		t := &p.Targets[i]
		// Build a per-target child context that exposes `self` (scalar
		// fields already decoded by gohcl: name, arch, version) so the
		// label / index / kernel / initrd / modules / cmdline
		// expressions can reference them. Putting the resolved strings
		// from those very fields in `self` would be circular, so they
		// stay out.
		selfCtx := augmented.NewChild()
		selfCtx.Variables = map[string]cty.Value{"self": selfFor(t)}

		fields := []struct {
			name string
			expr hcl.Expression
			dst  *string
		}{
			{"label", t.LabelExpr, &t.Label},
			{"index", t.IndexExpr, &t.Index},
			{"kernel", t.KernelExpr, &t.Kernel},
			{"initrd", t.InitrdExpr, &t.Initrd},
			{"modules", t.ModulesExpr, &t.Modules},
			{"subplan", t.SubplanExpr, &t.Subplan},
		}
		for _, f := range fields {
			if f.expr == nil {
				continue
			}
			s, err := evalString(f.expr, selfCtx)
			if err != nil {
				return nil, fmt.Errorf("plan target %q %s: %w", t.Name, f.name, err)
			}
			*f.dst = s
		}
		if t.CmdlineExpr != nil {
			s, err := evalCmdline(t.CmdlineExpr, selfCtx)
			if err != nil {
				return nil, fmt.Errorf("plan target %q cmdline: %w", t.Name, err)
			}
			t.Cmdline = s
		}

		hasOCI := t.Index != "" || t.Kernel != "" || t.Initrd != "" || t.Modules != ""
		hasDisk := t.Disk != nil
		hasSubplan := t.Subplan != ""
		n := 0
		for _, b := range []bool{hasOCI, hasDisk, hasSubplan} {
			if b {
				n++
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("plan: target %q must set exactly one of an OCI ref (index/kernel/initrd/modules), disk{} block, or subplan=", t.Name)
		}
	}
	return &p, nil
}

// selfFor builds the `self` object visible inside a target's HCL
// expressions. Limited to scalar fields decoded by gohcl in the prior
// pass — fields that themselves go through expression evaluation are
// intentionally absent (referencing them would be circular).
func selfFor(t *Target) cty.Value {
	return cty.ObjectVal(map[string]cty.Value{
		"name":    cty.StringVal(t.Name),
		"arch":    cty.StringVal(t.Arch),
		"version": cty.StringVal(t.Version),
	})
}

// evalString reduces a single-string HCL expression. Used for the
// label / index / kernel / initrd / modules attributes.
func evalString(expr hcl.Expression, ctx *hcl.EvalContext) (string, error) {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return "", fmt.Errorf("%s", diags.Error())
	}
	if v.IsNull() {
		return "", nil
	}
	if v.Type() != cty.String {
		return "", fmt.Errorf("must be a string, got %s", v.Type().FriendlyName())
	}
	return v.AsString(), nil
}

// evalCmdline reduces a cmdline expression to its textual form. A plain
// string passes through. A tuple / list of strings is joined with a
// single space — the readable form for plans with many cmdline tokens.
// Anything else is a decode error so typos surface at parse time rather
// than at kexec time.
func evalCmdline(expr hcl.Expression, ctx *hcl.EvalContext) (string, error) {
	v, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return "", fmt.Errorf("%s", diags.Error())
	}
	if v.IsNull() {
		return "", nil
	}
	ty := v.Type()
	if ty == cty.String {
		return v.AsString(), nil
	}
	if ty.IsTupleType() || ty.IsListType() {
		parts := make([]string, 0, v.LengthInt())
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			if ev.IsNull() {
				continue
			}
			if ev.Type() != cty.String {
				return "", fmt.Errorf("list element must be string, got %s", ev.Type().FriendlyName())
			}
			s := ev.AsString()
			if s == "" {
				continue
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " "), nil
	}
	return "", fmt.Errorf("must be a string or list of strings, got %s", ty.FriendlyName())
}

// EvalContext builds an HCL evaluation context exposing runtime facts to plan
// expressions. arch is the runtime architecture (defaults to runtime.GOARCH).
// facts is the LLDP neighbor data; pass nil if LLDP is disabled or no frame
// was observed.
func EvalContext(arch string, facts *lldp.Facts) *hcl.EvalContext {
	if arch == "" {
		arch = runtime.GOARCH
	}
	return &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"arch": cty.StringVal(arch),
			"lldp": lldpToCty(facts),
		},
	}
}

func lldpToCty(f *lldp.Facts) cty.Value {
	if f == nil {
		f = &Facts{}
	}
	return cty.ObjectVal(map[string]cty.Value{
		"available":   cty.BoolVal(f.SystemName != "" || f.ChassisID != "" || f.PortID != ""),
		"chassis_id":  cty.StringVal(f.ChassisID),
		"port_id":     cty.StringVal(f.PortID),
		"system_name": cty.StringVal(f.SystemName),
		"system_desc": cty.StringVal(f.SystemDesc),
		"port_desc":   cty.StringVal(f.PortDesc),
		"mgmt_addr":   cty.StringVal(f.MgmtAddr),
	})
}

// Facts re-exports lldp.Facts so callers needn't import both packages.
type Facts = lldp.Facts

// TimeoutDuration parses Menu.Timeout. Accepted forms: a Go duration
// ("5s", "1m30s") or a bare integer interpreted as seconds. An empty string
// returns 0 (menu disabled).
func (m *Menu) TimeoutDuration() (time.Duration, error) {
	if m == nil || m.Timeout == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(m.Timeout); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(m.Timeout)
}

// EligibleTargets returns the subset of targets whose Arch field is empty
// or matches arch. Used to build the interactive menu, so the user never
// sees a target they couldn't actually boot.
func (p *Plan) EligibleTargets(arch string) []*Target {
	if arch == "" {
		arch = runtime.GOARCH
	}
	out := make([]*Target, 0, len(p.Targets))
	for i := range p.Targets {
		t := &p.Targets[i]
		if t.Arch != "" && t.Arch != arch {
			continue
		}
		out = append(out, t)
	}
	return out
}

// Pick returns the matching target by name and current arch.
// An empty name falls back to DefaultTarget, or — if exactly one target is
// defined — to that target. Targets carrying an explicit Arch are filtered
// against the runtime arch (or the supplied arch, if non-empty).
func (p *Plan) Pick(name, arch string) (*Target, error) {
	if arch == "" {
		arch = runtime.GOARCH
	}
	if name == "" {
		name = p.DefaultTarget
	}
	if name == "" && len(p.Targets) == 1 {
		t := p.Targets[0]
		if t.Arch != "" && t.Arch != arch {
			return nil, fmt.Errorf("plan: only target %q is for arch %s, not %s", t.Name, t.Arch, arch)
		}
		return &t, nil
	}
	for i := range p.Targets {
		t := &p.Targets[i]
		if t.Name != name {
			continue
		}
		if t.Arch != "" && t.Arch != arch {
			continue
		}
		return t, nil
	}
	return nil, fmt.Errorf("plan: no target %q for arch %s", name, arch)
}
