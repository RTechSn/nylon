//go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"

	"github.com/encodeous/nylon/core"
	"github.com/encodeous/nylon/state"
)

// TestTimedRetiredPortsGoQuiet reproduces a field report against timed mode:
// after a dozen scheduled rotations, the operator's router still showed a
// tx/rx rate on EVERY port the client had ever used — including the very
// first ones — i.e. retired ports never went quiet.
//
// The rig mirrors the deployment: client "a" (timed mode, period 2s) sending
// sustained traffic to server "b" listening on the port range. The forward
// timeline (per destination port) is the ground truth of "the client is still
// spending packets on this port": a port that rotated away must go quiet
// within the rotation period + tombstone grace + probe slack. A port whose
// activity window stretches to the end of the run is a zombie.
//
// The liveness threshold is raised to 25s, which widens the client's relaxed
// probe interval (0.8 x 25s = 20s) past the 15s tombstone grace — the
// ignition regime. In this regime the server's reply/probe pin (updated only
// by the client's probe pings, which at a 2s period never fire — every
// rotation resets the probe timer) stays on the bootstrap port forever, so
// without the retired-port hygiene the peer keeps feeding the old port and a
// remote (learned) link to it is probed and renewed forever. Operators
// running lossy links (consecutive probe losses) reach the same regime with
// default tunables.
func TestTimedRetiredPortsGoQuiet(t *testing.T) {
	vh, aIdx, bIdx, fwd, _ := portModeRig(t)

	// the ignition regime: relaxed probe interval (20s) > tombstone grace (15s)
	tun := state.DefaultRouterTunables()
	tun.LinkDeadThreshold = 25 * time.Second
	vh.Tunables = &tun

	vh.Local[aIdx].PortMode = state.HopModeTimed
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		PeriodSeconds:   uint32ptr(2),
		PeriodJitterPct: uint32ptr(0),
		CooldownSeconds: uint32ptr(2),
		RecentPorts:     uint32ptr(32),
	}

	deliveries, _, errs := portModeDeliveries(vh)
	defer vh.Stop()

	// sustained traffic: 1 packet per 100ms for 40s => ~20 scheduled rotations
	const runLen = 40 * time.Second
	deadline := time.Now().Add(runLen)
	for time.Now().Before(deadline) {
		select {
		case <-vh.Context.Done():
			t.Fatal("harness context cancelled")
		case err := <-errs:
			t.Fatal(err)
		case <-time.After(100 * time.Millisecond):
			vh.Net.Send("a", "10.0.0.1", "10.0.0.2", []byte{111}, 64)
		}
	}
	time.Sleep(500 * time.Millisecond)
	end := time.Now()

	if got := deliveries.Load(); got < 300 {
		t.Errorf("only %d/%d packets delivered across timed rotations", got, 400)
	}

	// --- diagnostics: the client's link table for the server ----------------
	// Sampled ON THE DISPATCH LOOP (NewDispatchFuture): the link fields
	// (incl. WgEndpoint) are written there; reading them from the test
	// goroutine while the node runs is a data race.
	snapshot := func(n *core.Nylon) []string {
		fut := core.NewDispatchFuture(n, func() ([]string, error) {
			var out []string
			for _, neigh := range n.RouterState.Neighbours {
				for _, ep := range neigh.Eps {
					ne := ep.AsNylonEndpoint()
					pin := ""
					if ph, ok := ne.WgEndpoint.(interface{ PortHint() uint16 }); ok {
						pin = fmt.Sprintf(" pinned=%d", ph.PortHint())
					}
					out = append(out, fmt.Sprintf("%-22s remote=%-5v exhausted=%-5v active=%-5v metric=%d%s",
						ne.Address, ep.IsRemote(), ep.IsExhausted(), ep.IsActive(), ep.Metric(), pin))
				}
			}
			return out, nil
		})
		lines, err := fut.Await(vh.Context)
		if err != nil {
			t.Fatalf("dispatch snapshot failed: %v", err)
		}
		return lines
	}

	na := vh.Nylons[aIdx].Load()
	t.Logf("client links to server:")
	for _, l := range snapshot(na) {
		t.Logf("  client link %s", l)
	}

	// --- diagnostics: the server's link table + reply-port pins -------------
	nb := vh.Nylons[bIdx].Load()
	t.Logf("server links to client:")
	for _, l := range snapshot(nb) {
		t.Logf("  server link %s", l)
	}

	// --- the assertion: every retired port went quiet ------------------------
	// A port carries for ~1 period (2s), then may legitimately absorb stray
	// traffic for the tombstone grace (15s) and probe slack; anything still
	// passing packets later than 25s after its first use is a zombie.
	const quietWindow = 25 * time.Second
	zombies := 0
	for p, tl := range fwd.ForwardTimeline() {
		window := tl.Last.Sub(tl.First)
		age := end.Sub(tl.Last)
		t.Logf("fwd port %d: carried %s (first=%s) last packet %s before end",
			p, window.Round(time.Millisecond), tl.First.Format("15:04:05.000"), age.Round(time.Millisecond))
		if window > quietWindow {
			zombies++
		}
	}
	if zombies > 0 {
		t.Errorf("%d retired ports were still passing packets more than %s after their first use (zombie port-hopping links)", zombies, quietWindow)
	}
}
