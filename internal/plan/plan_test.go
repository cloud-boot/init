package plan

import (
	"strings"
	"testing"
	"time"

	"github.com/cloud-boot/init/internal/lldp"
)

const sample = `
default_target = "primary"

target "primary" {
  kernel  = "registry/boot/linux:6.6"
  initrd  = "registry/boot/initrd:fedora"
  modules = "registry/boot/modules:6.6"
  cmdline = lldp.available ? "console=ttyS0 node-${lldp.port_id}" : "console=ttyS0"
}

target "rescue" {
  arch    = "amd64"
  kernel  = "registry/boot/rescue:latest"
  cmdline = "rd.break"
}
`

func TestDecodeAndPick(t *testing.T) {
	facts := &lldp.Facts{SystemName: "sw1", PortID: "Eth1"}
	p, err := Decode([]byte(sample), "plan.hcl", EvalContext("amd64", facts))
	if err != nil {
		t.Fatal(err)
	}
	if p.DefaultTarget != "primary" {
		t.Errorf("DefaultTarget = %q", p.DefaultTarget)
	}
	tt, err := p.Pick("", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if tt.Name != "primary" {
		t.Errorf("default Pick = %q, want primary", tt.Name)
	}
	if !strings.Contains(tt.Cmdline, "node-Eth1") {
		t.Errorf("lldp interpolation failed: %q", tt.Cmdline)
	}
}

func TestPick_ByName(t *testing.T) {
	p, err := Decode([]byte(sample), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	tt, err := p.Pick("rescue", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if tt.Cmdline != "rd.break" {
		t.Errorf("rescue cmdline = %q", tt.Cmdline)
	}
}

func TestPick_ArchFilter(t *testing.T) {
	p, err := Decode([]byte(sample), "plan.hcl", EvalContext("arm64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pick("rescue", "arm64"); err == nil {
		t.Fatal("expected miss: rescue is amd64-only")
	}
}

func TestPick_SingleTargetFallback(t *testing.T) {
	src := `target "only" { kernel = "x" }`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	tt, err := p.Pick("", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if tt.Name != "only" {
		t.Errorf("single-target fallback = %q", tt.Name)
	}
}

func TestPick_SingleTargetWrongArch(t *testing.T) {
	src := `target "only" {
  arch   = "arm64"
  kernel = "x"
}`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pick("", "amd64"); err == nil {
		t.Fatal("expected arch mismatch error")
	}
}

func TestPick_NotFound(t *testing.T) {
	p, err := Decode([]byte(sample), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pick("nope", "amd64"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestPick_DefaultArchFromRuntime(t *testing.T) {
	p, err := Decode([]byte(sample), "plan.hcl", EvalContext("", nil))
	if err != nil {
		t.Fatal(err)
	}
	// Empty arch falls back to runtime.GOARCH inside Pick. We just want to
	// reach the branch; result depends on the test host so accept either.
	if _, err := p.Pick("primary", ""); err != nil {
		t.Fatal(err)
	}
}

func TestDecode_ParseError(t *testing.T) {
	if _, err := Decode([]byte("not = hcl ="), "plan.hcl", EvalContext("amd64", nil)); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestDecode_DecodeError(t *testing.T) {
	// Missing required `kernel` field.
	if _, err := Decode([]byte(`target "t" {}`), "plan.hcl", EvalContext("amd64", nil)); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestEvalContext_NilFacts(t *testing.T) {
	ctx := EvalContext("amd64", nil)
	v, ok := ctx.Variables["lldp"]
	if !ok {
		t.Fatal("missing lldp var")
	}
	if v.GetAttr("available").True() {
		t.Errorf("lldp.available should be false with nil facts")
	}
}

func TestEvalContext_AvailableWhenAnyFactSet(t *testing.T) {
	ctx := EvalContext("amd64", &lldp.Facts{SystemName: "sw"})
	if !ctx.Variables["lldp"].GetAttr("available").True() {
		t.Error("expected available=true when SystemName is set")
	}
}

func TestDecode_MenuBlock(t *testing.T) {
	src := `
default_target = "primary"

menu {
  timeout = "5s"
  prompt  = "pick one"
}

target "primary" {
  label  = "Prod"
  kernel = "x"
}
target "rescue" {
  label  = "Rescue"
  kernel = "y"
}`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Menu == nil {
		t.Fatal("Menu block not decoded")
	}
	if p.Menu.Prompt != "pick one" {
		t.Errorf("prompt = %q", p.Menu.Prompt)
	}
	d, err := p.Menu.TimeoutDuration()
	if err != nil {
		t.Fatal(err)
	}
	if d != 5*time.Second {
		t.Errorf("timeout = %v", d)
	}
	if p.Targets[0].Label != "Prod" {
		t.Errorf("label = %q", p.Targets[0].Label)
	}
}

func TestMenu_TimeoutDuration_BareInteger(t *testing.T) {
	m := &Menu{Timeout: "12"}
	d, err := m.TimeoutDuration()
	if err != nil {
		t.Fatal(err)
	}
	if d != 12*time.Second {
		t.Errorf("got %v", d)
	}
}

func TestMenu_TimeoutDuration_EmptyAndNil(t *testing.T) {
	var m *Menu
	if d, err := m.TimeoutDuration(); err != nil || d != 0 {
		t.Errorf("nil menu: got %v,%v", d, err)
	}
	if d, err := (&Menu{}).TimeoutDuration(); err != nil || d != 0 {
		t.Errorf("empty menu: got %v,%v", d, err)
	}
}

func TestMenu_TimeoutDuration_Invalid(t *testing.T) {
	if _, err := (&Menu{Timeout: "notaduration"}).TimeoutDuration(); err == nil {
		t.Fatal("expected error")
	}
}

func TestDecode_DiskTarget(t *testing.T) {
	src := `
target "from-disk" {
  cmdline = "console=ttyS0 ro"
  disk {
    device = "/dev/vda2"
    fs     = "ext4"
    kernel = "/boot/vmlinuz-6.6"
  }
}`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	tgt := p.Targets[0]
	if tgt.Index != "" || tgt.Kernel != "" || tgt.Initrd != "" || tgt.Modules != "" {
		t.Errorf("OCI refs should all be empty for disk target, got index=%q kernel=%q initrd=%q modules=%q",
			tgt.Index, tgt.Kernel, tgt.Initrd, tgt.Modules)
	}
	if tgt.Disk == nil {
		t.Fatal("Disk block not decoded")
	}
	if tgt.Disk.Device != "/dev/vda2" {
		t.Errorf("device = %q", tgt.Disk.Device)
	}
	if tgt.Disk.FS != "ext4" {
		t.Errorf("fs = %q", tgt.Disk.FS)
	}
	if tgt.Disk.Kernel != "/boot/vmlinuz-6.6" {
		t.Errorf("disk.kernel = %q", tgt.Disk.Kernel)
	}
}

func TestDecode_RejectsKernelAndDisk(t *testing.T) {
	src := `
target "bad" {
  kernel = "registry/x"
  disk {
    device = "/dev/vda2"
  }
}`
	if _, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil)); err == nil {
		t.Fatal("expected error when both kernel and disk are set")
	}
}

func TestDecode_RejectsNeitherKernelNorDisk(t *testing.T) {
	if _, err := Decode([]byte(`target "bad" {}`), "plan.hcl", EvalContext("amd64", nil)); err == nil {
		t.Fatal("expected error when neither kernel nor disk is set")
	}
}

func TestEligibleTargets_FiltersByArch(t *testing.T) {
	src := `
target "a" { kernel = "x" }
target "b" {
  arch   = "arm64"
  kernel = "y"
}
target "c" {
  arch   = "amd64"
  kernel = "z"
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	got := p.EligibleTargets("amd64")
	if len(got) != 2 {
		t.Fatalf("got %d targets", len(got))
	}
	if got[0].Name != "a" || got[1].Name != "c" {
		t.Errorf("got %q, %q", got[0].Name, got[1].Name)
	}
}

func TestDecode_Locals(t *testing.T) {
	src := `
locals {
  base = "_oci._tcp.registry.example.com/boot"
}
target "alpine" {
  index   = "${local.base}/alpine:3.21"
  cmdline = "console=ttyS0"
}
target "linux" {
  index   = "${local.base}/linux:6.6"
  cmdline = "console=ttyS0"
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	want := "_oci._tcp.registry.example.com/boot"
	for _, tgt := range p.Targets {
		if got, prefix := tgt.Index, want+"/"; len(got) < len(prefix) || got[:len(prefix)] != prefix {
			t.Errorf("target %q index = %q, want prefix %q", tgt.Name, got, prefix)
		}
	}
}

// TestDecode_LocalsReferenceArch confirms locals can themselves use
// `arch` / other runtime variables — the locals block sees the same
// EvalContext the caller passed in.
func TestDecode_LocalsReferenceArch(t *testing.T) {
	src := `
locals {
  flavor = arch == "arm64" ? "boot/arm" : "boot/x86"
}
target "auto" {
  index   = "registry.example.com/${local.flavor}/linux:6.6"
  cmdline = "console=ttyS0"
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("arm64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Targets[0].Index != "registry.example.com/boot/arm/linux:6.6" {
		t.Errorf("got %q", p.Targets[0].Index)
	}
}

func TestDecode_DNS(t *testing.T) {
	src := `
dns = ["10.0.2.2", "1.1.1.1"]
target "alpine" {
  index   = "registry.example.com/boot/alpine:3.21"
  cmdline = "console=ttyS0"
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(p.DNS), 2; got != want {
		t.Fatalf("len(p.DNS) = %d, want %d", got, want)
	}
	if p.DNS[0] != "10.0.2.2" || p.DNS[1] != "1.1.1.1" {
		t.Errorf("p.DNS = %v", p.DNS)
	}
}

func TestDecode_CmdlineList(t *testing.T) {
	src := `
target "alpine" {
  index = "registry.example.com/boot/alpine:3.21"
  cmdline = [
    "console=ttyS0",
    "ip=dhcp",
    "alpine_repo=https://dl-cdn.alpinelinux.org/alpine/v3.21/main",
  ]
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	want := "console=ttyS0 ip=dhcp alpine_repo=https://dl-cdn.alpinelinux.org/alpine/v3.21/main"
	if got := p.Targets[0].Cmdline; got != want {
		t.Errorf("Cmdline = %q, want %q", got, want)
	}
}

// TestDecode_CmdlineListWithLocals confirms list elements still see
// `arch`, `local.*` etc. — i.e. evaluation happens in the augmented
// context, not against an empty one.
func TestDecode_CmdlineListWithLocals(t *testing.T) {
	src := `
locals {
  console = arch == "arm64" ? "ttyAMA0" : "ttyS0"
}
target "alpine" {
  index = "registry.example.com/boot/alpine:3.21"
  cmdline = [
    "console=${local.console}",
    "ip=dhcp",
  ]
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("arm64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.Targets[0].Cmdline, "console=ttyAMA0 ip=dhcp"; got != want {
		t.Errorf("Cmdline = %q, want %q", got, want)
	}
}

func TestDecode_SelfVersion(t *testing.T) {
	src := `
locals {
  alpine_repo = "https://dl-cdn.alpinelinux.org/alpine"
}
target "alpine" {
  version = "v3.21"
  index   = "registry.example.com/boot/alpine:${self.version}"
  label   = "Alpine ${self.version} (${self.name})"
  cmdline = [
    "console=ttyS0",
    "alpine_repo=${local.alpine_repo}/${self.version}/main",
  ]
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	tt := p.Targets[0]
	if tt.Version != "v3.21" {
		t.Errorf("Version = %q", tt.Version)
	}
	if tt.Index != "registry.example.com/boot/alpine:v3.21" {
		t.Errorf("Index = %q", tt.Index)
	}
	if tt.Label != "Alpine v3.21 (alpine)" {
		t.Errorf("Label = %q", tt.Label)
	}
	want := "console=ttyS0 alpine_repo=https://dl-cdn.alpinelinux.org/alpine/v3.21/main"
	if tt.Cmdline != want {
		t.Errorf("Cmdline = %q, want %q", tt.Cmdline, want)
	}
}

// Self stays empty for unset fields — no crash, no fallback magic.
func TestDecode_SelfMissingVersionIsEmpty(t *testing.T) {
	src := `
target "x" {
  index   = "registry/x:${self.version}"
  cmdline = "y"
}
`
	p, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Targets[0].Index != "registry/x:" {
		t.Errorf("Index = %q", p.Targets[0].Index)
	}
}

func TestDecode_CmdlineList_RejectsNonString(t *testing.T) {
	src := `
target "alpine" {
  index = "x"
  cmdline = ["console=ttyS0", 42]
}
`
	if _, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil)); err == nil {
		t.Fatal("expected error: non-string element in cmdline list")
	}
}

func TestDecode_LocalsBadExpr(t *testing.T) {
	src := `
locals {
  broken = no.such.var
}
target "alpine" {
  index   = "x"
  cmdline = "console=ttyS0"
}
`
	_, err := Decode([]byte(src), "plan.hcl", EvalContext("amd64", nil))
	if err == nil {
		t.Fatal("expected error on undefined reference inside locals")
	}
}
