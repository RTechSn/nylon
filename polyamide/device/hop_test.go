/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
)

// portEP is a minimal conn.Endpoint with a controllable destination.
type portEP struct {
	ap netip.AddrPort
}

func (e *portEP) ClearSrc()                 {}
func (e *portEP) SrcToString() string       { return e.ap.String() }
func (e *portEP) DstToString() string       { return e.ap.String() }
func (e *portEP) DstToBytes() []byte        { return nil }
func (e *portEP) DstIP() netip.Addr         { return e.ap.Addr() }
func (e *portEP) SrcIP() netip.Addr         { return e.ap.Addr() }
func (e *portEP) DstIPPort() netip.AddrPort { return e.ap }

var _ conn.Endpoint = (*portEP)(nil)

// fakeHopSource hands out sequential endpoints and records retirements.
type fakeHopSource struct {
	next    []*portEP
	drawn   int
	retired []netip.AddrPort
	fail    bool
}

func (f *fakeHopSource) NextHopEndpoint(peer *Peer, exhausted conn.Endpoint) (conn.Endpoint, error) {
	if exhausted != nil {
		f.retired = append(f.retired, exhausted.DstIPPort())
	}
	if f.fail {
		return nil, errors.New("pool exhausted")
	}
	if f.drawn >= len(f.next) {
		f.drawn = len(f.next) // saturate: keep serving the last endpoint
		return &portEP{ap: f.next[len(f.next)-1].ap}, nil
	}
	ep := f.next[f.drawn]
	f.drawn++
	return ep, nil
}

func newHopTestPeer(budget int, src HopSource) *Peer {
	peer := &Peer{device: &Device{Log: &Logger{Verbosef: DiscardLogf}}}
	if src != nil {
		peer.SetHop(src, budget)
	}
	return peer
}

func ap(port uint16) netip.AddrPort {
	return netip.MustParseAddrPort("10.0.0.1:" + itoa(int(port)))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [5]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestHopAccountSendRotatesAtBudget verifies that a batch larger than the
// per-port budget is split across carrying endpoints at exactly the budget
// boundary, and that rotation retires the exhausted endpoint.
func TestHopAccountSendRotatesAtBudget(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}, {ap(1001)}, {ap(1002)}}}
	peer := newHopTestPeer(3, src)

	// 8 buffers, all addressed to the first drawn carrying endpoint
	eps := make([]conn.Endpoint, 8)
	for i := range eps {
		eps[i] = &portEP{ap: ap(1000)}
	}

	// draw the first carrying endpoint
	first := peer.hopCarrying()
	if first == nil {
		t.Fatal("hopCarrying returned nil")
	}
	if got := first.DstIPPort(); got != ap(1000) {
		t.Fatalf("first carrying endpoint = %v, want %v", got, ap(1000))
	}
	for i := range eps {
		eps[i] = first
	}

	peer.hopAccountSend(eps)

	// budget 3 => ports 1000, 1001, 1002 carry 3, 3, 2 packets
	wantPorts := []uint16{1000, 1000, 1000, 1001, 1001, 1001, 1002, 1002}
	for i, ep := range eps {
		if got := ep.DstIPPort().Port(); got != wantPorts[i] {
			t.Fatalf("eps[%d] port = %d, want %d", i, got, wantPorts[i])
		}
	}
	if len(src.retired) != 2 {
		t.Fatalf("retired %d endpoints, want 2 (one per rotation)", len(src.retired))
	}
	if src.retired[0] != ap(1000) || src.retired[1] != ap(1001) {
		t.Fatalf("retired %v, want [%v %v]", src.retired, ap(1000), ap(1001))
	}
}

// TestHopAccountSendIgnoresOtherEndpoints verifies that buffers addressed to
// endpoints other than the carrying one (e.g. a probe to a configured link)
// do not consume the carrying port's budget.
func TestHopAccountSendIgnoresOtherEndpoints(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}, {ap(1001)}}}
	peer := newHopTestPeer(2, src)

	other := &portEP{ap: ap(5000)}
	eps := []conn.Endpoint{other, other, other, other}

	peer.hopAccountSend(eps) // must not even draw a carrying endpoint

	for i, ep := range eps {
		if ep != conn.Endpoint(other) {
			t.Fatalf("eps[%d] was re-addressed to %v", i, ep.DstToString())
		}
	}
	if src.drawn != 0 {
		t.Fatalf("hop source drew %d endpoints; want 0", src.drawn)
	}
}

// TestHopCarryingRotatesWhenBudgetSpent verifies the lazy rotation on the
// next carrying request after the budget ran out.
func TestHopCarryingRotatesWhenBudgetSpent(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}, {ap(1001)}}}
	peer := newHopTestPeer(3, src)

	first := peer.hopCarrying()
	if first.DstIPPort() != ap(1000) {
		t.Fatalf("first = %v", first.DstIPPort())
	}
	// spend the budget
	eps := []conn.Endpoint{first, first, first}
	peer.hopAccountSend(eps)

	second := peer.hopCarrying()
	if second.DstIPPort() != ap(1001) {
		t.Fatalf("after budget exhaustion carrying = %v, want %v", second.DstIPPort(), ap(1001))
	}
	if len(src.retired) != 1 || src.retired[0] != ap(1000) {
		t.Fatalf("retired = %v, want [%v]", src.retired, ap(1000))
	}
}

// TestHopDegradedFallsBack verifies that when the hop source cannot supply
// endpoints, the send path keeps using the last known carrying endpoint for
// a while instead of dropping everything.
func TestHopDegradedFallsBack(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}}}
	peer := newHopTestPeer(2, src)

	first := peer.hopCarrying()
	eps := []conn.Endpoint{first, first}
	peer.hopAccountSend(eps) // budget spent

	src.fail = true
	next := peer.hopCarrying()
	if next == nil {
		t.Fatal("degraded hopCarrying returned nil; expected the stale carrying endpoint")
	}
	if next.DstIPPort() != ap(1000) {
		t.Fatalf("degraded carrying = %v, want stale %v", next.DstIPPort(), ap(1000))
	}

	// degraded mode must not call the source again within the retry delay
	before := src.drawn
	eps = []conn.Endpoint{next, next, next, next}
	peer.hopAccountSend(eps)
	if src.drawn != before {
		t.Fatalf("degraded hopAccountSend drew from the source again (%d -> %d)", before, src.drawn)
	}
}

// TestHopStatusReportsState verifies the observability accessor.
func TestHopStatusReportsState(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}}}
	peer := newHopTestPeer(5, src)

	if _, ok := peer.HopStatus(); !ok {
		t.Fatal("HopStatus reported hopping inactive for a hop-configured peer")
	}
	peer.hopCarrying()
	st, ok := peer.HopStatus()
	if !ok {
		t.Fatal("HopStatus inactive after draw")
	}
	if st.Carrying != ap(1000).String() {
		t.Fatalf("HopStatus.Carrying = %q, want %q", st.Carrying, ap(1000).String())
	}
	if st.Budget != 5 || st.BudgetLeft != 5 {
		t.Fatalf("HopStatus budget = %d/%d, want 5/5", st.BudgetLeft, st.Budget)
	}

	// a peer without hopping must report inactive
	plain := newHopTestPeer(0, nil)
	if _, ok := plain.HopStatus(); ok {
		t.Fatal("HopStatus reported hopping active for a plain peer")
	}
}

// newExternalHopPeer builds a peer whose hop source is externally driven
// (static/reactive/timed modes): no packet budget, no send-path rotation.
func newExternalHopPeer(src HopSource) *Peer {
	peer := &Peer{device: &Device{Log: &Logger{Verbosef: DiscardLogf}}}
	peer.SetHopExternal(src)
	return peer
}

// TestHopExternalModeNeverRotatesOnSendPath verifies that an externally
// driven hop never rotates on the packet send path: an arbitrarily large
// batch stays on the carrying endpoint and never retires it.
func TestHopExternalModeNeverRotatesOnSendPath(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}, {ap(1001)}, {ap(1002)}}}
	peer := newExternalHopPeer(src)

	first := peer.hopCarrying()
	if first == nil || first.DstIPPort() != ap(1000) {
		t.Fatalf("first carrying = %v, want %v", first, ap(1000))
	}

	eps := make([]conn.Endpoint, 64)
	for i := range eps {
		eps[i] = first
	}
	peer.hopAccountSend(eps)

	for i, ep := range eps {
		if ep.DstIPPort() != ap(1000) {
			t.Fatalf("eps[%d] re-addressed to %v; external mode must not rotate mid-batch", i, ep.DstIPPort())
		}
	}
	if len(src.retired) != 0 {
		t.Fatalf("external mode retired %v on the send path; want none", src.retired)
	}
	if st, _ := peer.HopStatus(); !st.External || st.Budget != 0 {
		t.Fatalf("HopStatus = %+v, want External=true Budget=0", st)
	}
}

// TestHopExternalRotateRewiresCarrying verifies the controller-driven
// rotation: the current carrying endpoint is handed over as exhausted and
// its replacement becomes the carrying endpoint for subsequent sends.
func TestHopExternalRotateRewiresCarrying(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}, {ap(1001)}}}
	peer := newExternalHopPeer(src)

	if first := peer.hopCarrying(); first.DstIPPort() != ap(1000) {
		t.Fatalf("first carrying = %v", first.DstIPPort())
	}

	dest, err := peer.HopExternalRotate()
	if err != nil {
		t.Fatalf("HopExternalRotate: %v", err)
	}
	if dest != ap(1001).String() {
		t.Fatalf("rotated to %q, want %q", dest, ap(1001).String())
	}
	if len(src.retired) != 1 || src.retired[0] != ap(1000) {
		t.Fatalf("retired = %v, want [%v]", src.retired, ap(1000))
	}
	if second := peer.hopCarrying(); second.DstIPPort() != ap(1001) {
		t.Fatalf("carrying after external rotation = %v, want %v", second.DstIPPort(), ap(1001))
	}
}

// TestHopExternalRotateFailureKeepsCarrying verifies that a failed external
// rotation (source error, e.g. pool exhausted) leaves the carrying endpoint
// untouched.
func TestHopExternalRotateFailureKeepsCarrying(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}}}
	peer := newExternalHopPeer(src)

	if first := peer.hopCarrying(); first.DstIPPort() != ap(1000) {
		t.Fatalf("first carrying = %v", first.DstIPPort())
	}

	src.fail = true
	if _, err := peer.HopExternalRotate(); err == nil {
		t.Fatal("HopExternalRotate succeeded against a failing source")
	}
	if cur := peer.hopCarrying(); cur == nil || cur.DstIPPort() != ap(1000) {
		t.Fatalf("carrying after failed rotation = %v, want %v", cur, ap(1000))
	}

	// a peer without hop state refuses external rotation
	plain := &Peer{device: &Device{Log: &Logger{Verbosef: DiscardLogf}}}
	if _, err := plain.HopExternalRotate(); err == nil {
		t.Fatal("HopExternalRotate succeeded on a peer without hop state")
	}
}

// TestHopModeSwitchKeepsCarrying verifies live mode switches between the
// budgeted (proactive) and externally driven (static/reactive/timed) hop
// styles: the current carrying endpoint survives the switch, and budget
// accounting resumes when the budgeted style is re-armed.
func TestHopModeSwitchKeepsCarrying(t *testing.T) {
	src := &fakeHopSource{next: []*portEP{{ap(1000)}, {ap(1001)}, {ap(1002)}}}
	peer := newHopTestPeer(3, src)

	first := peer.hopCarrying()
	if first.DstIPPort() != ap(1000) {
		t.Fatalf("first carrying = %v", first.DstIPPort())
	}

	// proactive -> external: the carrying endpoint survives, budget stops
	peer.SetHopExternal(src)
	if cur := peer.hopCarrying(); cur.DstIPPort() != ap(1000) {
		t.Fatalf("carrying after switch to external = %v, want %v", cur.DstIPPort(), ap(1000))
	}
	big := make([]conn.Endpoint, 32)
	for i := range big {
		big[i] = first
	}
	peer.hopAccountSend(big)
	if len(src.retired) != 0 {
		t.Fatalf("external accounting retired %v", src.retired)
	}

	// external -> proactive: budget accounting resumes from the carrying
	peer.SetHop(src, 3)
	if st, _ := peer.HopStatus(); st.External || st.Budget != 3 {
		t.Fatalf("HopStatus after re-arming budget = %+v, want External=false Budget=3", st)
	}
	eps := []conn.Endpoint{first, first, first, first}
	peer.hopAccountSend(eps)
	// budget 3: the 4th buffer forces a rotation onto the next endpoint
	if eps[3].DstIPPort() != ap(1001) {
		t.Fatalf("eps[3] = %v after re-armed budget; want rotation to %v", eps[3].DstIPPort(), ap(1001))
	}
	if len(src.retired) != 1 || src.retired[0] != ap(1000) {
		t.Fatalf("retired after re-armed budget = %v, want [%v]", src.retired, ap(1000))
	}
}
