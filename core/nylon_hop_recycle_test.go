package core

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/state"
)

// recycleTestFactory builds a proactive-mode factory over a 5-port range, in
// the style of the hop-fixtures tests, with the auto-recycle interval preset.
func recycleTestFactory(t *testing.T, n *Nylon, recycleMin time.Duration) *portFactory {
	t.Helper()
	ip := netip.MustParseAddr("192.168.1.2")
	return &portFactory{
		n:          n,
		node:       "b",
		pool:       hopTestPool(ip, 30000, 30004),
		bind:       conn.NewStdNetBind(),
		specs:      []state.EndpointSpec{{Host: ip.String(), Ports: state.PortRange{First: 30000, Last: 30004}}},
		mode:       state.HopModeProactive,
		recycleMin: recycleMin,
	}
}

// rotateUntilStalled drives the rotation loop (draw, retire the drawn
// endpoint, draw again) until NextHopEndpoint reports an error, and returns
// the last successfully drawn endpoint.
func rotateUntilStalled(t *testing.T, f *portFactory) conn.Endpoint {
	t.Helper()
	ep, err := f.NextHopEndpoint(nil, nil)
	if err != nil {
		t.Fatalf("first draw: %v", err)
	}
	for i := 0; i < 32; i++ {
		next, err := f.NextHopEndpoint(nil, ep)
		if err != nil {
			return ep
		}
		ep = next
	}
	t.Fatal("rotation never stalled after 32 rotations over a 5-port pool")
	return nil
}

// TestHopAutoRecycleDisabledByDefault pins the stock exhaustion behaviour:
// with no recycle interval configured, rotation stalls (warn + error) and
// nothing is ever recycled.
func TestHopAutoRecycleDisabledByDefault(t *testing.T) {
	var buf bytes.Buffer
	n := newHopFixturesNylonWithLog(t, time.Hour, &buf)
	f := recycleTestFactory(t, n, 0)

	last := rotateUntilStalled(t, f)
	if !f.pool.IsCooling(last.DstIPPort()) {
		t.Fatal("the carrying endpoint was not retired into the quarantine")
	}

	// the stock behaviour: the retry keeps failing while every port cools down
	if _, err := f.NextHopEndpoint(nil, last); err == nil {
		t.Fatal("rotation succeeded on a fully quarantined pool with auto-recycle disabled")
	}
	if strings.Contains(buf.String(), "auto-recycle") {
		t.Fatal("auto-recycle fired although no recycle interval is configured")
	}
	if !strings.Contains(buf.String(), "port pool exhausted") {
		t.Fatal("the pool-exhaustion warning is missing from the journal")
	}
}

// TestHopAutoRecycleClearsQuarantine pins the opt-in behaviour
// (port_hopping.recycle_seconds): an exhausted pool is recycled in one sweep
// and rotation resumes immediately; a second exhaustion inside the interval
// is refused (the rate limit holds), and once the interval elapses the next
// recycle goes through again.
func TestHopAutoRecycleClearsQuarantine(t *testing.T) {
	var buf bytes.Buffer
	n := newHopFixturesNylonWithLog(t, time.Hour, &buf)
	f := recycleTestFactory(t, n, time.Second)

	// rotate until the first stall: with a zero lastRecycleAt the very first
	// exhaustion already recycles, so the loop keeps drawing until it hits the
	// rate limit (a second exhaustion within one second of the first recycle)
	last := rotateUntilStalled(t, f)

	out := buf.String()
	if !strings.Contains(out, "auto-recycle cleared the retired-port quarantine") {
		t.Fatal("the auto-recycle line is missing from the journal")
	}
	if !strings.Contains(out, "cleared=5") {
		t.Fatalf("the auto-recycle line does not report cleared=5:\n%s", out)
	}
	// exactly one recycle may fire inside the rate-limit window: the loop
	// kept rotating on the recycled pool until the second exhaustion was
	// refused
	if got := strings.Count(out, "auto-recycle cleared the retired-port quarantine"); got != 1 {
		t.Fatalf("got %d auto-recycle lines inside one rate-limit window, want 1:\n%s", got, out)
	}

	// inside the rate-limit window a second exhaustion stalls (stock warn)
	if _, err := f.NextHopEndpoint(nil, last); err == nil {
		t.Fatal("auto-recycle ignored its rate limit")
	}

	// once the interval elapses, the next recycle goes through and rotation
	// resumes on the spot
	f.mu.Lock()
	f.lastRecycleAt = time.Now().Add(-2 * time.Second)
	f.mu.Unlock()
	next, err := f.NextHopEndpoint(nil, last)
	if err != nil {
		t.Fatalf("rotation did not resume after the recycle interval elapsed: %v", err)
	}
	if got := next.DstIPPort(); got.Port() < 30000 || got.Port() > 30004 {
		t.Fatalf("recycled rotation drew %v, outside the range", got)
	}
}

// TestHopRecyclePolicyResolution pins the config plumbing: recycle_seconds
// resolves into the policy's RecycleMinInterval and stays off by default.
func TestHopRecyclePolicyResolution(t *testing.T) {
	if p := (*state.PortHoppingCfg)(nil).Resolve(); p.RecycleMinInterval != 0 {
		t.Fatalf("default policy recycles every %v; the default must be off", p.RecycleMinInterval)
	}
	secs := uint32(2)
	p := (&state.PortHoppingCfg{RecycleSeconds: &secs}).Resolve()
	if p.RecycleMinInterval != 2*time.Second {
		t.Fatalf("recycle_seconds=2 resolved to %v, want 2s", p.RecycleMinInterval)
	}
	zero := uint32(0)
	p = (&state.PortHoppingCfg{RecycleSeconds: &zero}).Resolve()
	if p.RecycleMinInterval != 0 {
		t.Fatalf("recycle_seconds=0 resolved to %v, want off", p.RecycleMinInterval)
	}
}
