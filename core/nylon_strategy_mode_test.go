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

// The strategy-selection fixtures: two strategies over one host — "alpha"
// (30000-30009, first in the candidate list) and "beta" (31000-31009) — under
// a configurable obf.strategy_mode. The ranges are disjoint, so every drawn
// endpoint names its strategy.

// strategyModeNylon builds the hop-fixtures nylon with the central obf block
// set to the given strategy_mode.
func strategyModeNylon(t *testing.T, mode string, w *bytes.Buffer) *Nylon {
	t.Helper()
	n := newHopFixturesNylonWithLog(t, time.Hour, w)
	n.CentralCfg.Obf = &state.CentralObf{
		StrategyMode: mode,
		Strategy: map[string]*state.ObfStrategy{
			"alpha": {Ports: "30000-30009"},
			"beta":  {Ports: "31000-31009"},
		},
	}
	return n
}

// strategyModeFactory builds a proactive-rotation factory over the two
// strategy fixtures, with the per-strategy groups resolved (refreshGroups)
// and the given current state installed.
func strategyModeFactory(t *testing.T, n *Nylon, currentStrategy string) *portFactory {
	t.Helper()
	host := "192.168.1.2"
	p := state.DefaultPortHoppingPolicy()
	p.Mode = state.HopModeProactive
	p.Budget = 12
	cands := []hopCandidate{
		{host: host, ports: state.PortRange{First: 30000, Last: 30009}, strategy: "alpha", policy: p},
		{host: host, ports: state.PortRange{First: 31000, Last: 31009}, strategy: "beta", policy: p},
	}
	f := &portFactory{
		n:               n,
		node:            "b",
		pool:            state.NewPortPool(nil, state.PortPoolConfig{Recent: 4, Cooldown: time.Hour, Samples: 4}),
		bind:            conn.NewStdNetBind(),
		candidates:      cands,
		policies:        candidatePolicies(cands),
		currentStrategy: currentStrategy,
		mode:            state.HopModeProactive,
	}
	f.refreshGroups()
	if len(f.strategyGroupsOf("alpha")) == 0 || len(f.strategyGroupsOf("beta")) == 0 {
		t.Fatal("strategy groups did not resolve over literal IPs")
	}
	// register the factory the way ensurePortFactories does, so the
	// nylon-level hooks (noteHopHeardBack) dispatch to it
	n.portHopping.mu.Lock()
	if n.portHopping.factories == nil {
		n.portHopping.factories = make(map[state.NodeId]*portFactory)
	}
	n.portHopping.factories["b"] = f
	n.portHopping.mu.Unlock()
	return f
}

// strategyOfAp names the fixture strategy owning the drawn endpoint ("" when
// in neither range).
func strategyOfAp(ap netip.AddrPort) string {
	switch {
	case ap.Port() >= 30000 && ap.Port() <= 30009:
		return "alpha"
	case ap.Port() >= 31000 && ap.Port() <= 31009:
		return "beta"
	}
	return ""
}

// drawAndRetire draws one carrying endpoint through the full send path and
// hands the drawn endpoint back as the exhausted one for the next call (the
// rotation loop the device drives in proactive mode).
func drawAndRetire(t *testing.T, f *portFactory, exhausted conn.Endpoint) (conn.Endpoint, string) {
	t.Helper()
	ep, err := f.NextHopEndpoint(nil, exhausted)
	if err != nil {
		t.Fatalf("NextHopEndpoint: %v", err)
	}
	return ep, strategyOfAp(ep.DstIPPort())
}

// TestStrategyModeFixedPinsFirstStrategy pins fixed: every draw — the first
// connection and every rotation alike — lands on the FIRST strategy of the
// candidate list, never the second.
func TestStrategyModeFixedPinsFirstStrategy(t *testing.T) {
	var buf bytes.Buffer
	n := strategyModeNylon(t, state.StrategyModeFixed, &buf)
	f := strategyModeFactory(t, n, "")

	ep, strat := drawAndRetire(t, f, nil)
	if strat != "alpha" {
		t.Fatalf("first draw: strategy = %q, want alpha", strat)
	}
	for i := 0; i < 6; i++ {
		ep, strat = drawAndRetire(t, f, ep)
		if strat != "alpha" {
			t.Fatalf("rotation %d: strategy = %q, want alpha (fixed never switches)", i, strat)
		}
	}
	if strings.Contains(buf.String(), "trial strategy") {
		t.Fatal("fixed mode must not journal trial events")
	}
}

// TestStrategyModeRandomDrawsAcrossStrategies pins random: across a rotation
// sequence both strategies serve draws, and consecutive draws change
// strategy while alternatives exist (the change preference).
func TestStrategyModeRandomDrawsAcrossStrategies(t *testing.T) {
	var buf bytes.Buffer
	n := strategyModeNylon(t, state.StrategyModeRandom, &buf)
	f := strategyModeFactory(t, n, "")

	seen := map[string]int{}
	ep, strat := drawAndRetire(t, f, nil)
	seen[strat]++
	prev := strat
	for i := 0; i < 11; i++ {
		ep, strat = drawAndRetire(t, f, ep)
		seen[strat]++
		if strat == prev {
			t.Fatalf("rotation %d: strategy %q repeated — random must change while alternatives exist", i, strat)
		}
		prev = strat
	}
	if len(seen) != 2 {
		t.Fatalf("random must draw from both strategies, saw %v", seen)
	}
}

// TestStrategyModeTrialPrefersConfirmedStrategy pins trial's memory: with no
// confirmation yet the draws iterate (both strategies serve); once the
// current carrying endpoint is heard back on, its strategy is confirmed and
// every later draw — reconnects and rotations alike — prefers it first.
func TestStrategyModeTrialPrefersConfirmedStrategy(t *testing.T) {
	var buf bytes.Buffer
	n := strategyModeNylon(t, state.StrategyModeTrial, &buf)
	f := strategyModeFactory(t, n, "")

	// the search phase: draw, then confirm the drawn endpoint (the peer was
	// heard back on it — the pong path)
	ep, strat := drawAndRetire(t, f, nil)
	n.noteHopHeardBack("b", ep.DstIPPort())

	f.mu.Lock()
	confirmed := f.lastGoodStrategy
	f.mu.Unlock()
	if confirmed != strat {
		t.Fatalf("lastGood = %q, want the drawn endpoint's strategy %q", confirmed, strat)
	}
	if !strings.Contains(buf.String(), "trial strategy confirmed") {
		t.Fatal("the confirmation journal line is missing")
	}

	// the memory phase: rotations keep preferring the confirmed strategy
	var s string
	for i := 0; i < 6; i++ {
		ep, s = drawAndRetire(t, f, ep)
		if s != strat {
			t.Fatalf("rotation %d after confirmation: strategy = %q, want the confirmed %q", i, s, strat)
		}
	}
}

// TestStrategyModeTrialDeathVerdictDemotes pins trial's failure path on the
// carrying-link death verdict (the same liveness model that drives reactive
// rotation): the first death CONDEMNS the remembered strategy — the
// reconnect still retries it first — and a second death while condemned,
// without a confirmation in between, demotes the memory: the selection
// returns to the random iteration. A budget rotation exhausting its
// endpoint is NOT a death and never demotes.
func TestStrategyModeTrialDeathVerdictDemotes(t *testing.T) {
	var buf bytes.Buffer
	// a tiny liveness threshold so the materialised links age past it
	n := newHopFixturesNylonWithLog(t, 2*time.Millisecond, &buf)
	n.CentralCfg.Obf = &state.CentralObf{
		StrategyMode: state.StrategyModeTrial,
		Strategy: map[string]*state.ObfStrategy{
			"alpha": {Ports: "30000-30009"},
			"beta":  {Ports: "31000-31009"},
		},
	}
	f := strategyModeFactory(t, n, "alpha")
	neigh := n.RouterState.GetNeighbour("b")
	if neigh == nil {
		t.Fatal("fixture neighbour missing")
	}

	// a confirmed connection on alpha, then its carrying link dies
	f.mu.Lock()
	f.current = netip.MustParseAddrPort("192.168.1.2:30001")
	f.lastGoodStrategy = "alpha"
	f.mu.Unlock()
	neigh.Eps = append(neigh.Eps, state.NewEndpoint("192.168.1.2:30001", false, nil, &n.RouterTunables))
	time.Sleep(8 * time.Millisecond)
	f.reconcileLinks() // death verdict #1: condemn
	f.mu.Lock()
	condemned, lastGood := f.lastGoodCondemned, f.lastGoodStrategy
	f.mu.Unlock()
	if !condemned || lastGood != "alpha" {
		t.Fatalf("after the first death: condemned=%v lastGood=%q, want true/alpha (the retry comes first)", condemned, lastGood)
	}
	if !strings.Contains(buf.String(), "trial strategy condemned") {
		t.Fatal("the condemnation journal line is missing")
	}

	// the retry: the draw still prefers the condemned strategy
	exhausted, err := f.bindIfReady().ParseEndpoint("192.168.1.2:30001")
	if err != nil {
		t.Fatalf("parse exhausted endpoint: %v", err)
	}
	retryEp, strat := drawAndRetire(t, f, exhausted)
	if strat != "alpha" {
		t.Fatalf("the reconnect must retry the condemned strategy first, drew %q", strat)
	}

	// the retry's link dies too: the second verdict demotes
	time.Sleep(8 * time.Millisecond)
	f.reconcileLinks() // materialises the retry's link
	time.Sleep(8 * time.Millisecond)
	f.reconcileLinks() // death verdict #2: demote
	f.mu.Lock()
	lastGood = f.lastGoodStrategy
	f.mu.Unlock()
	if lastGood != "" {
		t.Fatalf("lastGood = %q after the second death, want empty (demoted)", lastGood)
	}
	if !strings.Contains(buf.String(), "trial strategy demoted") {
		t.Fatal("the demotion journal line is missing")
	}

	// the selection returns to the iteration: the next draw leaves the
	// twice-failed strategy
	ep, err := f.NextHopEndpoint(nil, retryEp)
	if err != nil {
		t.Fatalf("draw after demotion: %v", err)
	}
	if s := strategyOfAp(ep.DstIPPort()); s != "beta" {
		t.Fatalf("the iteration must leave the failed strategy, drew %q", s)
	}
}

// TestStrategyModeTrialConfirmationRedeems pins the redemption: a
// confirmation on the remembered strategy (the peer was heard back on the
// carrying endpoint — the retry established) clears a pending condemnation,
// so a LATER death starts the two-strike verdict over instead of demoting.
func TestStrategyModeTrialConfirmationRedeems(t *testing.T) {
	var buf bytes.Buffer
	n := newHopFixturesNylonWithLog(t, 2*time.Millisecond, &buf)
	n.CentralCfg.Obf = &state.CentralObf{
		StrategyMode: state.StrategyModeTrial,
		Strategy: map[string]*state.ObfStrategy{
			"alpha": {Ports: "30000-30009"},
			"beta":  {Ports: "31000-31009"},
		},
	}
	f := strategyModeFactory(t, n, "alpha")
	neigh := n.RouterState.GetNeighbour("b")

	// condemned, then redeemed by a confirmation
	f.mu.Lock()
	f.current = netip.MustParseAddrPort("192.168.1.2:30001")
	f.lastGoodStrategy = "alpha"
	f.lastGoodCondemned = true
	f.mu.Unlock()
	n.noteHopHeardBack("b", netip.MustParseAddrPort("192.168.1.2:30001"))
	f.mu.Lock()
	condemned := f.lastGoodCondemned
	f.mu.Unlock()
	if condemned {
		t.Fatal("the confirmation must redeem the condemnation")
	}

	// a later death: the verdict starts over (condemns, does not demote)
	neigh.Eps = append(neigh.Eps, state.NewEndpoint("192.168.1.2:30001", false, nil, &n.RouterTunables))
	time.Sleep(8 * time.Millisecond)
	f.reconcileLinks()
	f.mu.Lock()
	condemned, lastGood := f.lastGoodCondemned, f.lastGoodStrategy
	f.mu.Unlock()
	if !condemned || lastGood != "alpha" {
		t.Fatalf("after the redemption a death must condemn again, not demote: condemned=%v lastGood=%q", condemned, lastGood)
	}
	if strings.Contains(buf.String(), "trial strategy demoted") {
		t.Fatal("a redeemed strategy must not demote on its next death")
	}
}

// TestStrategyModeRandomDeathIsNotATrialEvent pins the verdict gate: the
// two-strike machinery (condemn, then demote) is trial-mode consumption. In
// random a confirmed connection's link death is the mode's own business —
// random draws a fresh strategy per connection, nothing retries the fallen
// one first — so the journal stays free of trial events and the verdict
// state never engages; the memory itself stays recorded (a live mode switch
// starts with the knowledge in hand).
func TestStrategyModeRandomDeathIsNotATrialEvent(t *testing.T) {
	var buf bytes.Buffer
	// a tiny liveness threshold so the materialised links age past it
	n := newHopFixturesNylonWithLog(t, 2*time.Millisecond, &buf)
	n.CentralCfg.Obf = &state.CentralObf{
		StrategyMode: state.StrategyModeRandom,
		Strategy: map[string]*state.ObfStrategy{
			"alpha": {Ports: "30000-30009"},
			"beta":  {Ports: "31000-31009"},
		},
	}
	f := strategyModeFactory(t, n, "alpha")
	neigh := n.RouterState.GetNeighbour("b")
	if neigh == nil {
		t.Fatal("fixture neighbour missing")
	}

	// a confirmed connection on alpha (random records the memory too), then
	// its carrying link dies — the sequence that in trial condemns and then
	// demotes
	f.mu.Lock()
	f.current = netip.MustParseAddrPort("192.168.1.2:30001")
	f.lastGoodStrategy = "alpha"
	f.mu.Unlock()
	neigh.Eps = append(neigh.Eps, state.NewEndpoint("192.168.1.2:30001", false, nil, &n.RouterTunables))
	time.Sleep(8 * time.Millisecond)
	f.reconcileLinks() // would-be death verdict #1 (condemn)
	time.Sleep(8 * time.Millisecond)
	f.reconcileLinks() // would-be death verdict #2 (demote)
	f.mu.Lock()
	condemned, lastGood := f.lastGoodCondemned, f.lastGoodStrategy
	f.mu.Unlock()
	if condemned || lastGood != "alpha" {
		t.Fatalf("random must not run trial verdicts: condemned=%v lastGood=%q, want false/alpha (the memory only records)", condemned, lastGood)
	}
	if out := buf.String(); strings.Contains(out, "trial strategy condemned") || strings.Contains(out, "trial strategy demoted") {
		t.Fatalf("random must not journal trial verdicts:\n%s", out)
	}
}

// TestStrategyModeExhaustionSwitchesStrategy pins the cross-strategy retry
// on exhaustion: random (and trial's iteration) fall through to the next
// strategy when the chosen strategy's ports are all cooling, while fixed
// never switches — its exhaustion is the whole answer.
func TestStrategyModeExhaustionSwitchesStrategy(t *testing.T) {
	// random: alpha's sole port exhausts, the draw falls through to beta
	var buf bytes.Buffer
	n := strategyModeNylon(t, state.StrategyModeRandom, &buf)
	host := "192.168.1.2"
	p := state.DefaultPortHoppingPolicy()
	p.Mode = state.HopModeProactive
	cands := []hopCandidate{
		{host: host, ports: state.PortRange{First: 30000, Last: 30000}, strategy: "alpha", policy: p},
		{host: host, ports: state.PortRange{First: 31000, Last: 31009}, strategy: "beta", policy: p},
	}
	f := &portFactory{
		n: n, node: "b",
		pool:       state.NewPortPool(nil, state.PortPoolConfig{Recent: 4, Cooldown: time.Hour, Samples: 4}),
		bind:       conn.NewStdNetBind(),
		candidates: cands, policies: candidatePolicies(cands),
		mode: state.HopModeProactive,
	}
	f.refreshGroups()

	// seed the current attempt on alpha's sole port and exhaust it
	f.mu.Lock()
	f.current = netip.MustParseAddrPort("192.168.1.2:30000")
	f.currentStrategy = "alpha"
	f.pool.Retire(f.current)
	f.mu.Unlock()

	ep, err := f.NextHopEndpoint(nil, nil)
	if err != nil {
		t.Fatalf("random must fall through to beta on alpha's exhaustion: %v", err)
	}
	if s := strategyOfAp(ep.DstIPPort()); s != "beta" {
		t.Fatalf("drew %q after alpha's exhaustion, want beta", s)
	}

	// fixed: the same exhaustion is terminal — fixed never switches
	buf.Reset()
	n2 := strategyModeNylon(t, state.StrategyModeFixed, &buf)
	f2 := strategyModeFactory(t, n2, "alpha")
	f2.mu.Lock()
	f2.current = netip.MustParseAddrPort("192.168.1.2:30001")
	f2.pool.Retire(f2.current)
	f2.mu.Unlock()
	// burn the rest of alpha's range so the strategy is fully exhausted
	for port := uint16(30000); port <= 30009; port++ {
		if port == 30001 {
			continue
		}
		f2.pool.Retire(netip.MustParseAddrPort("192.168.1.2:" + itoa(port)))
	}
	_, derr := f2.drawCarrying(nil)
	if derr == nil {
		t.Fatal("fixed must not switch strategies on exhaustion — the draw must fail")
	}
	if !strings.Contains(derr.Error(), "exhausted") {
		t.Fatalf("the exhaustion must surface, got: %v", derr)
	}
}

// TestStrategyModeNoteHeardBackOnlyConfirmsCurrent pins the confirmation
// guard: hearing from the peer on an endpoint that is NOT the current
// carrying endpoint (a stale rotation artefact, a remote-learned source)
// confirms nothing — no memory adoption, no redemption.
func TestStrategyModeNoteHeardBackOnlyConfirmsCurrent(t *testing.T) {
	var buf bytes.Buffer
	n := strategyModeNylon(t, state.StrategyModeTrial, &buf)
	f := strategyModeFactory(t, n, "alpha")

	f.mu.Lock()
	f.current = netip.MustParseAddrPort("192.168.1.2:30001")
	f.lastGoodStrategy = ""
	f.mu.Unlock()

	// a pong from a different port of the same strategy: not the carrying
	// endpoint — no confirmation, no memory
	n.noteHopHeardBack("b", netip.MustParseAddrPort("192.168.1.2:30005"))
	f.mu.Lock()
	lastGood, redeemed := f.lastGoodStrategy, !f.lastGoodCondemned
	f.mu.Unlock()
	if lastGood != "" || !redeemed {
		t.Fatalf("a non-carrying endpoint must not confirm: lastGood=%q redeemed=%v", lastGood, redeemed)
	}

	// the carrying endpoint: the strategy is confirmed as the proven one
	n.noteHopHeardBack("b", netip.MustParseAddrPort("192.168.1.2:30001"))
	f.mu.Lock()
	lastGood = f.lastGoodStrategy
	f.mu.Unlock()
	if lastGood != "alpha" {
		t.Fatalf("the carrying endpoint must confirm: lastGood=%q", lastGood)
	}
}

// TestStrategyModeStaticPinIsSticky pins the static rotation mode's interplay
// with the strategy selection: the strategy is selected ONCE per connection
// (on the first draw) and the pin stays on it — random does not re-select
// per send.
func TestStrategyModeStaticPinIsSticky(t *testing.T) {
	var buf bytes.Buffer
	n := strategyModeNylon(t, state.StrategyModeRandom, &buf)
	f := strategyModeFactory(t, n, "")
	f.mu.Lock()
	f.mode = state.HopModeStatic
	f.mu.Unlock()

	first, err := f.staticCarrying()
	if err != nil {
		t.Fatalf("first staticCarrying: %v", err)
	}
	s1 := strategyOfAp(first.DstIPPort())
	if s1 == "" {
		t.Fatalf("static pin drew outside both ranges: %v", first.DstIPPort())
	}
	for i := 0; i < 5; i++ {
		ep, err := f.staticCarrying()
		if err != nil {
			t.Fatalf("staticCarrying %d: %v", i, err)
		}
		if ep.DstIPPort() != first.DstIPPort() {
			t.Fatalf("static pin flapped: %v then %v — the strategy selection must be sticky",
				first.DstIPPort(), ep.DstIPPort())
		}
	}
}

// itoa avoids importing strconv for two call sites.
func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
