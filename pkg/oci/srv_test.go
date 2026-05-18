package oci

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

func TestIsSRVHost(t *testing.T) {
	cases := map[string]bool{
		"_oci._tcp.example.com":   true,
		"_oci._udp.example.com":   true,
		"oci.example.com":         false,
		"_just-underscored":       false,
		"_oci.example.com":        false, // missing _proto label
		"127.0.0.1":               false,
		"127.0.0.1:5000":          false,
	}
	for in, want := range cases {
		if got := IsSRVHost(in); got != want {
			t.Errorf("IsSRVHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestOrderSRV_PriorityOrder(t *testing.T) {
	// All zero-weighted; expect strict priority asc.
	recs := []*net.SRV{
		{Target: "r3.", Port: 443, Priority: 30, Weight: 0},
		{Target: "r1.", Port: 443, Priority: 10, Weight: 0},
		{Target: "r2.", Port: 443, Priority: 20, Weight: 0},
	}
	out := orderSRV(recs, rand.New(rand.NewSource(1)))
	want := []string{"r1:443", "r2:443", "r3:443"}
	if len(out) != len(want) {
		t.Fatalf("len(out) = %d, want %d", len(out), len(want))
	}
	for i, w := range want {
		if out[i].Host != w {
			t.Errorf("out[%d] = %q, want %q", i, out[i].Host, w)
		}
	}
}

func TestOrderSRV_WeightedWithinPriority(t *testing.T) {
	// 1000 trials; high-weight server should dominate the first slot.
	recs := []*net.SRV{
		{Target: "heavy.", Port: 443, Priority: 10, Weight: 100},
		{Target: "light.", Port: 443, Priority: 10, Weight: 1},
	}
	const trials = 1000
	heavyFirst := 0
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < trials; i++ {
		out := orderSRV(recs, rng)
		if strings.HasPrefix(out[0].Host, "heavy") {
			heavyFirst++
		}
	}
	// With weights 100 vs 1, "heavy" should win ≫ 50% of the time.
	if heavyFirst < trials*9/10 {
		t.Errorf("heavy server won %d/%d trials, expected >= %d",
			heavyFirst, trials, trials*9/10)
	}
}

func TestResolveEndpoints_Passthrough(t *testing.T) {
	out, err := ResolveEndpoints("registry.example.com:5000")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Host != "registry.example.com:5000" {
		t.Errorf("got %v, want [{registry.example.com:5000}]", out)
	}
}

// withSRVLookup pins the inner DNS resolver to a deterministic mock.
func withSRVLookup(t *testing.T, fn func(ctx context.Context, svc, proto, name string) (string, []*net.SRV, error)) {
	t.Helper()
	prev := lookupSRVImpl
	lookupSRVImpl = fn
	t.Cleanup(func() { lookupSRVImpl = prev })
}

func clearSRVCache(t *testing.T) {
	t.Helper()
	srvCacheMu.Lock()
	srvCache = map[string]srvEntry{}
	srvCacheMu.Unlock()
}

func TestResolveEndpoints_SRVHit(t *testing.T) {
	clearSRVCache(t)
	withSRVLookup(t, func(_ context.Context, svc, proto, name string) (string, []*net.SRV, error) {
		if svc != "oci" || proto != "tcp" || name != "example.com" {
			t.Errorf("LookupSRV called with svc=%q proto=%q name=%q", svc, proto, name)
		}
		return "", []*net.SRV{{Target: "reg-a.example.com.", Port: 443, Priority: 10}}, nil
	})
	eps, err := ResolveEndpoints("_oci._tcp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Host != "reg-a.example.com:443" {
		t.Errorf("eps = %v", eps)
	}
}

func TestResolveEndpoints_CacheHit(t *testing.T) {
	clearSRVCache(t)
	calls := 0
	withSRVLookup(t, func(_ context.Context, svc, proto, name string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{{Target: "reg.example.com.", Port: 443}}, nil
	})
	for i := 0; i < 3; i++ {
		if _, err := ResolveEndpoints("_oci._tcp.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("LookupSRV called %d times; expected exactly 1 (cache should serve the rest)", calls)
	}
}

func TestResolveEndpoints_CacheDisabled(t *testing.T) {
	clearSRVCache(t)
	prevTTL := SRVCacheTTL
	SRVCacheTTL = 0
	t.Cleanup(func() { SRVCacheTTL = prevTTL })

	calls := 0
	withSRVLookup(t, func(_ context.Context, svc, proto, name string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{{Target: "reg.example.com.", Port: 443}}, nil
	})
	for i := 0; i < 3; i++ {
		if _, err := ResolveEndpoints("_oci._tcp.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Errorf("LookupSRV called %d times; expected 3 with cache disabled", calls)
	}
}

func TestLookupSRV_DNSError(t *testing.T) {
	clearSRVCache(t)
	withSRVLookup(t, func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, errors.New("dns boom")
	})
	if _, err := ResolveEndpoints("_oci._tcp.example.com"); err == nil {
		t.Fatal("expected DNS error")
	}
}

func TestLookupSRV_EmptyResult(t *testing.T) {
	clearSRVCache(t)
	withSRVLookup(t, func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, nil // no records
	})
	if _, err := ResolveEndpoints("_oci._tcp.example.com"); err == nil {
		t.Fatal("expected no-records error")
	}
}

func TestLookupSRV_InvalidShape(t *testing.T) {
	// Force IsSRVHost to pass while sending a host that lookupSRV's parts
	// validation rejects. The shape `_x._tcp` (no zone label after the two
	// underscored ones) is invalid per the parts check.
	if _, err := lookupSRV("_x._tcp"); err == nil {
		t.Fatal("expected invalid-host error")
	}
}

func TestLookupSRV_MissingSecondUnderscore(t *testing.T) {
	// First label has the leading `_`, second does NOT. The parts validation
	// inside lookupSRV must reject this even though IsSRVHost happens to.
	if _, err := lookupSRV("_x.tcp.example.com"); err == nil {
		t.Fatal("expected invalid-host error")
	}
}

func TestResolveEndpoints_ExpiredCacheRefetches(t *testing.T) {
	clearSRVCache(t)
	prevTTL := SRVCacheTTL
	SRVCacheTTL = 1 * time.Millisecond
	t.Cleanup(func() { SRVCacheTTL = prevTTL })

	calls := 0
	withSRVLookup(t, func(context.Context, string, string, string) (string, []*net.SRV, error) {
		calls++
		return "", []*net.SRV{{Target: "reg.example.com.", Port: 443}}, nil
	})
	if _, err := ResolveEndpoints("_oci._tcp.example.com"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := ResolveEndpoints("_oci._tcp.example.com"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("LookupSRV called %d times; expected 2 (cache expired between calls)", calls)
	}
}
