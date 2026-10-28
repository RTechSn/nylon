//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/encodeous/nylon/state"
)

// TestTimedReplyPortsSwitchSynchronously pins the second half of the
// retired-port field report: with timed rotations, the server's replies must
// switch to the new carrying port IN STEP with the client's rotation — not
// keep egressing through the previous port while the pin catches up.
//
// The reply egress port is the device peer endpoint (val[0]): the receiver
// refreshes it from the arrival endpoint of every authenticated packet
// (reply-port symmetry), so the reverse timeline's first packet on a port
// must trail the forward timeline's first packet by a moment only. Before
// the fix, val[0] only followed the link pin — moved by the peer's probe
// pings and control adoption — and was re-applied by the 1s SetEndpoints
// tick, so every rotation left the replies answering through the old port
// for a visible lag (the operator's "the server keeps responding through the
// previous port for a while").
//
// The liveness threshold is raised to 25s, putting the client's relaxed probe
// interval (20s) far beyond the 3s rotation period: pin movers that wait for
// probe pings never fire within a rotation, so a reply path that depends on
// them is visibly behind on every single rotation.
//
// Both per-port timelines are also asserted against a quiet window: a port
// that rotated away must stop passing packets (forward AND reverse) within a
// rotation period plus the tombstone grace plus probe slack — the zombie-port
// guarantee of the earlier retired-port tests, now on both directions.
func TestTimedReplyPortsSwitchSynchronously(t *testing.T) {
	vh, aIdx, _, fwd, rev := portModeRig(t)

	// the ignition regime: relaxed probe interval (0.8 x 25s = 20s) >> the
	// 3s rotation period — the reply-port switch must come from the traffic
	// itself, not from the next probe ping
	tun := state.DefaultRouterTunables()
	tun.LinkDeadThreshold = 25 * time.Second
	vh.Tunables = &tun

	vh.Local[aIdx].PortMode = state.HopModeTimed
	vh.Local[aIdx].PortHopping = &state.PortHoppingCfg{
		PeriodSeconds:   uint32ptr(3),
		PeriodJitterPct: uint32ptr(0),
		CooldownSeconds: uint32ptr(2),
		RecentPorts:     uint32ptr(32),
	}

	deliveries, _, errs := portModeDeliveries(vh)
	defer vh.Stop()

	// sustained traffic: 1 packet per 100ms for 40s => ~13 scheduled rotations
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

	fwdTl := fwd.ForwardTimeline()
	revTl := rev.ReverseTimeline()

	// --- diagnostics: per-port forward/reverse activity windows -----------
	for p, tl := range fwdTl {
		t.Logf("fwd port %d: carried %s (first=%s), last packet %s before end",
			p, tl.Last.Sub(tl.First).Round(time.Millisecond), tl.First.Format("15:04:05.000"), end.Sub(tl.Last).Round(time.Millisecond))
	}
	for p, tl := range revTl {
		t.Logf("rev port %d: carried %s (first=%s), last packet %s before end",
			p, tl.Last.Sub(tl.First).Round(time.Millisecond), tl.First.Format("15:04:05.000"), end.Sub(tl.Last).Round(time.Millisecond))
	}

	// --- the zombie net: retired ports go quiet in BOTH directions ---------
	// A port carries for ~1 period (3s), then may legitimately absorb stray
	// traffic for the tombstone grace (15s) and probe slack; anything still
	// passing packets later than that is a zombie.
	const quietWindow = 20 * time.Second
	for p, tl := range fwdTl {
		if window := tl.Last.Sub(tl.First); window > quietWindow {
			t.Errorf("fwd port %d: still passing packets %s after its first use (zombie port-hopping link)", p, window.Round(time.Millisecond))
		}
	}
	for p, tl := range revTl {
		if window := tl.Last.Sub(tl.First); window > quietWindow {
			t.Errorf("rev port %d: still passing packets %s after its first use (zombie reply port)", p, window.Round(time.Millisecond))
		}
	}

	// --- the synchronous switch assertion ----------------------------------
	// For every port the client ever used: the server's replies from that
	// port must begin within a short moment of the client's first packet to
	// it. A lag bounded only by probe/adoption cadences was the reported
	// "the server keeps responding through the previous port".
	const switchLag = 2 * time.Second
	for p, ftl := range fwdTl {
		rtl, ok := revTl[p]
		if !ok {
			continue // no replies observed from this port (idle stretch)
		}
		if lag := rtl.First.Sub(ftl.First); lag > switchLag {
			t.Errorf("rev port %d: the server's replies only started %s after the client began using the port — the reply port lagged the rotation (want <= %s)",
				p, lag.Round(time.Millisecond), switchLag)
		}
	}
}
