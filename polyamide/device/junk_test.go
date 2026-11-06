/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/tun/tuntest"
)

// -- fixtures ----------------------------------------------------------------

// captureBind records every outgoing datagram instead of sending it
// anywhere: the send-path emission tests assert the wire composition of a
// handshake initiation (i-packets, junk, initiation — in order) through it.
type captureBind struct {
	mu   sync.Mutex
	sent [][]byte
}

var _ conn.Bind = (*captureBind)(nil)

func (b *captureBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 1, nil }
func (b *captureBind) Close() error                                    { return nil }
func (b *captureBind) BatchSize() int                                  { return 1 }
func (b *captureBind) SetMark(uint32) error                            { return nil }

func (b *captureBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, buf := range bufs {
		b.sent = append(b.sent, bytes.Clone(buf))
	}
	return nil
}

func (b *captureBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &portEP{ap: ap}, nil
}

// take returns the recorded datagrams and clears the record.
func (b *captureBind) take() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.sent
	b.sent = nil
	return out
}

// junkSourceStub serves a switchable spec, recording every peer it is
// consulted for.
type junkSourceStub struct {
	mu    sync.Mutex
	spec  JunkSpec
	ok    bool
	seen  []*Peer
	label string
}

func (s *junkSourceStub) JunkFor(peer *Peer) (JunkSpec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, peer)
	return s.spec, s.ok
}

func (s *junkSourceStub) set(spec JunkSpec, ok bool) {
	s.mu.Lock()
	s.spec, s.ok = spec, ok
	s.mu.Unlock()
}

func (s *junkSourceStub) consults() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func (s *junkSourceStub) JunkLabel() string { return s.label }

var _ JunkSource = (*junkSourceStub)(nil)
var _ JunkLabeler = (*junkSourceStub)(nil)

// newJunkDevice builds one device over a capture bind with the given device
// knobs and one peer carrying a configured endpoint.
func newJunkDevice(t *testing.T, knobs ...string) (*Device, *Peer, *captureBind) {
	t.Helper()
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	bind := &captureBind{}
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), bind, NewLogger(LogLevelError, ""))
	dev.SetPrivateKey(sk)
	if len(knobs) > 0 {
		if err := dev.IpcSet(uapiCfg(knobs...)); err != nil {
			t.Fatalf("device knobs: %v", err)
		}
	}
	peerSk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := dev.NewPeer(peerSk.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	ep, err := bind.ParseEndpoint("192.0.2.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	peer.endpoints.Lock()
	peer.endpoints.val = append(peer.endpoints.val, ep)
	peer.endpoints.Unlock()
	t.Cleanup(dev.Close)
	return dev, peer, bind
}

// sendInitiation drives one handshake initiation, bypassing the rekey rate
// limit so repeated calls within one test all reach the wire.
func sendInitiation(t *testing.T, peer *Peer) {
	t.Helper()
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-time.Hour)
	peer.handshake.mutex.Unlock()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("SendHandshakeInitiation: %v", err)
	}
}

// wantIPacket is the deterministic i-packet buffer of "<b 0xc0ff>" — 2 fixed
// bytes, no randomness.
var wantC0FF = []byte{0xc0, 0xff}

// -- the hook ----------------------------------------------------------------

// TestJunkSpecConsult pins the consult plumbing: no source wired — no
// consult, stock device knobs; a source wired — every consult names the
// peer it serves; unwiring restores stock behaviour.
func TestJunkSpecConsult(t *testing.T) {
	_, peer, _ := newJunkDevice(t)

	if _, ok := peer.junkSpec(); ok {
		t.Fatal("a peer without a junk source must consult nothing (device knobs)")
	}
	if _, _, active := peer.JunkStatus(); active {
		t.Fatal("JunkStatus must report inactive without a source")
	}

	src := &junkSourceStub{spec: JunkSpec{Jc: 3, Jmin: 10, Jmax: 20}, ok: true}
	peer.SetJunkSource(src)
	spec, ok := peer.junkSpec()
	if !ok || spec.Jc != 3 || spec.Jmin != 10 || spec.Jmax != 20 {
		t.Fatalf("consult: ok=%v spec=%+v", ok, spec)
	}
	if got := src.consults(); got != 1 {
		t.Fatalf("the source must be consulted exactly once, got %d", got)
	}
	if s := src.seen[0]; s != peer {
		t.Fatalf("the consult must name the peer it serves: %v != %v", s, peer)
	}

	// the status surfaces the live consult and the label
	gotSpec, label, active := peer.JunkStatus()
	if !active || label != "" || gotSpec.Jc != 3 {
		t.Fatalf("JunkStatus: spec=%+v label=%q active=%v", gotSpec, label, active)
	}
	src.label = "alpha"
	if _, label, _ := peer.JunkStatus(); label != "alpha" {
		t.Fatalf("JunkStatus must surface the source label, got %q", label)
	}

	// unwiring: stock device knobs again
	peer.SetJunkSource(nil)
	if _, ok := peer.junkSpec(); ok {
		t.Fatal("unwiring must restore stock device knobs")
	}
}

// TestSendHandshakeInitiationJunkHook pins the send-path contract: the
// prepend stream of a handshake initiation follows the per-peer junk hook —
// the device knobs (jc/jmin/jmax + i1..i5) only serve peers whose source
// answers "not mine" (or that have none), and a zero spec suppresses junk
// entirely instead of leaking the knobs.
func TestSendHandshakeInitiationJunkHook(t *testing.T) {
	_, peer, bind := newJunkDevice(t,
		"jc", "2",
		"jmin", "50",
		"jmax", "90",
		"i1", "<b 0xc0ff>",
	)

	// stock behaviour: the device knobs decorate the initiation — 1
	// i-packet + 2 junk datagrams of sizes [50, 90) + the initiation itself
	sendInitiation(t, peer)
	sent := bind.take()
	if len(sent) != 4 {
		t.Fatalf("device-knob initiation: %d datagrams, want 4 (i1 + 2 junk + initiation)", len(sent))
	}
	if !bytes.Equal(sent[0], wantC0FF) {
		t.Fatalf("device-knob i-packet: %x, want %x", sent[0], wantC0FF)
	}
	for _, j := range sent[1:3] {
		if len(j) < 50 || len(j) >= 90 {
			t.Fatalf("device-knob junk datagram size %d outside [50, 90)", len(j))
		}
	}
	if len(sent[3]) < MessageInitiationSize {
		t.Fatalf("the initiation must be the final datagram (%d bytes)", len(sent[3]))
	}

	// the hook overrides the knobs: its own trio + i-set
	src := &junkSourceStub{ok: true}
	src.set(JunkSpec{Jc: 1, Jmin: 10, Jmax: 11, I: [5]string{"<b 0xc0ff>", "", "", "", ""}}, true)
	peer.SetJunkSource(src)
	sendInitiation(t, peer)
	sent = bind.take()
	if len(sent) != 3 {
		t.Fatalf("hook initiation: %d datagrams, want 3 (i1 + 1 junk + initiation)", len(sent))
	}
	if !bytes.Equal(sent[0], wantC0FF) {
		t.Fatalf("hook i-packet: %x, want %x", sent[0], wantC0FF)
	}
	if len(sent[1]) != 10 {
		t.Fatalf("hook junk datagram size %d, want exactly 10 ([10, 11))", len(sent[1]))
	}

	// a zero spec suppresses everything: no i-packets, no junk — the device
	// knobs must NOT leak onto a junkless strategy
	src.set(JunkSpec{}, true)
	sendInitiation(t, peer)
	sent = bind.take()
	if len(sent) != 1 {
		t.Fatalf("zero-spec initiation: %d datagrams, want 1 (the initiation alone): %+v", len(sent), sent)
	}

	// the hook answering "not mine" falls back to the device knobs
	src.set(JunkSpec{}, false)
	sendInitiation(t, peer)
	sent = bind.take()
	if len(sent) != 4 {
		t.Fatalf("fallback initiation: %d datagrams, want 4 (the device knobs)", len(sent))
	}
	for _, j := range sent[1:3] {
		if len(j) < 50 || len(j) >= 90 {
			t.Fatalf("fallback junk datagram size %d outside [50, 90)", len(j))
		}
	}
}

// TestSendHandshakeInitiationPerPeerJunk pins the per-peer property: two
// peers of one device, each wired to its own source, emit DIFFERENT prepend
// streams from the same device — the device knobs stay out of both.
func TestSendHandshakeInitiationPerPeerJunk(t *testing.T) {
	dev, peerA, bind := newJunkDevice(t, "jc", "2", "jmin", "50", "jmax", "90")
	peerSk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerB, err := dev.NewPeer(peerSk.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	ep, err := bind.ParseEndpoint("192.0.2.2:51820")
	if err != nil {
		t.Fatal(err)
	}
	peerB.endpoints.Lock()
	peerB.endpoints.val = append(peerB.endpoints.val, ep)
	peerB.endpoints.Unlock()

	srcA := &junkSourceStub{spec: JunkSpec{Jc: 1, Jmin: 10, Jmax: 11}, ok: true}
	srcB := &junkSourceStub{spec: JunkSpec{Jc: 3, Jmin: 200, Jmax: 201}, ok: true}
	peerA.SetJunkSource(srcA)
	peerB.SetJunkSource(srcB)

	sendInitiation(t, peerA)
	sentA := bind.take()
	sendInitiation(t, peerB)
	sentB := bind.take()

	// A: 1 junk of size 10 + initiation; B: 3 junk of size 200 + initiation
	if len(sentA) != 2 || len(sentA[0]) != 10 {
		t.Fatalf("peer A stream: %d datagrams, first %d bytes; want 2 datagrams, 10-byte junk", len(sentA), len(sentA[0]))
	}
	if len(sentB) != 4 {
		t.Fatalf("peer B stream: %d datagrams, want 4 (3 junk + initiation)", len(sentB))
	}
	for _, j := range sentB[:3] {
		if len(j) != 200 {
			t.Fatalf("peer B junk size %d, want 200", len(j))
		}
	}

	// a third peer with no source keeps the device knobs
	peerCSk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peerC, err := dev.NewPeer(peerCSk.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	epC, err := bind.ParseEndpoint("192.0.2.3:51820")
	if err != nil {
		t.Fatal(err)
	}
	peerC.endpoints.Lock()
	peerC.endpoints.val = append(peerC.endpoints.val, epC)
	peerC.endpoints.Unlock()
	sendInitiation(t, peerC)
	sentC := bind.take()
	if len(sentC) != 3 { // 2 device-knob junk + initiation
		t.Fatalf("sourceless peer C stream: %d datagrams, want 3 (device knobs + initiation)", len(sentC))
	}
	for _, j := range sentC[:2] {
		if len(j) < 50 || len(j) >= 90 {
			t.Fatalf("sourceless peer C junk size %d outside [50, 90)", len(j))
		}
	}
}

// TestSendHandshakeInitiationConsultFollowsEndpointSelection pins the
// ordering fix: the carrying endpoint selection adopts the connection's
// strategy (hopCarrying → the hop source), and the junk consult must run
// AFTER it — the flipSource flips its answer from inside NextHopEndpoint,
// and the emitted junk must already be the flipped spec.
func TestSendHandshakeInitiationConsultFollowsEndpointSelection(t *testing.T) {
	_, peer, bind := newJunkDevice(t)

	// flipSource answers jc=1/[10,11) until the hop source runs (the
	// strategy adoption), then jc=3/[200,201).
	flip := &junkSourceStub{spec: JunkSpec{Jc: 1, Jmin: 10, Jmax: 11}, ok: true}
	hop := &flipHopSource{onDraw: func() {
		flip.set(JunkSpec{Jc: 3, Jmin: 200, Jmax: 201}, true)
	}}
	peer.SetJunkSource(flip)
	peer.SetHop(hop, 12)

	sendInitiation(t, peer)
	sent := bind.take()

	// the post-flip spec: 3 junk datagrams of size 200 (the pre-flip spec
	// would emit exactly one 10-byte datagram)
	if len(sent) != 4 {
		t.Fatalf("consult ordering: %d datagrams, want 4 (3 junk + initiation); a pre-selection consult emitted the stale spec", len(sent))
	}
	for _, j := range sent[:3] {
		if len(j) != 200 {
			t.Fatalf("consult ordering: junk size %d, want 200 (the spec adopted by THIS handshake's endpoint selection)", len(j))
		}
	}
}

// flipHopSource draws one fixed endpoint and calls onDraw when it does (the
// send-path hook the strategy adoption rides on).
type flipHopSource struct {
	onDraw func()
}

func (f *flipHopSource) NextHopEndpoint(peer *Peer, exhausted conn.Endpoint) (conn.Endpoint, error) {
	if exhausted == nil && f.onDraw != nil {
		f.onDraw()
	}
	return &portEP{ap: ap(1000)}, nil
}

// -- the chain cache and the draw ---------------------------------------------

// TestJunkChainCacheReuse pins the parse-once contract: one obfChain per
// distinct spec string, shared by pointer; an unparseable spec degrades to
// no i-packet (cached, one error per distinct spec); the empty spec never
// reaches the cache.
func TestJunkChainCacheReuse(t *testing.T) {
	dev, _, _ := newJunkDevice(t)

	a1 := dev.chainFor("<b 0xc0ff>")
	a2 := dev.chainFor("<b 0xc0ff>")
	if a1 == nil || a1 != a2 {
		t.Fatalf("the same spec must parse once and share the chain: %p vs %p", a1, a2)
	}
	b1 := dev.chainFor("<b 0x00ba>")
	if b1 == a1 {
		t.Fatal("distinct specs must parse to distinct chains")
	}

	dev.ichains.mu.Lock()
	cached := len(dev.ichains.m)
	dev.ichains.mu.Unlock()
	if cached != 2 {
		t.Fatalf("the cache must hold exactly the 2 distinct specs, holds %d", cached)
	}

	// an unparseable spec: no i-packet, cached (no re-parse spam), and the
	// parseable specs stay untouched
	if bad := dev.chainFor("<nope 5>"); bad != nil {
		t.Fatalf("an unparseable spec must degrade to no i-packet, got %v", bad)
	}
	if bad2 := dev.chainFor("<nope 5>"); bad2 != nil {
		t.Fatal("the unparseable spec must stay a nil chain on reuse")
	}
	dev.ichains.mu.Lock()
	cached = len(dev.ichains.m)
	dev.ichains.mu.Unlock()
	if cached != 3 {
		t.Fatalf("the cache must hold the bad spec too (parse-once), holds %d", cached)
	}

	// the empty spec never enters the cache
	if empty := dev.chainFor(""); empty != nil {
		t.Fatal("the empty spec must yield no chain")
	}
	dev.ichains.mu.Lock()
	cached = len(dev.ichains.m)
	dev.ichains.mu.Unlock()
	if cached != 3 {
		t.Fatalf("the empty spec must not be cached, holds %d", cached)
	}
}

// TestJunkPacketsDraw pins the datagram draw: count datagrams of sizes in
// [min, max), a degenerate [n, n) range drawing fixed sizes, and nothing at
// all for a zero count or an inverted range.
func TestJunkPacketsDraw(t *testing.T) {
	dev, _, _ := newJunkDevice(t)

	bufs := dev.junkPackets(3, 10, 20)
	if len(bufs) != 3 {
		t.Fatalf("jc=3 drew %d datagrams", len(bufs))
	}
	for _, b := range bufs {
		if len(b) < 10 || len(b) >= 20 {
			t.Fatalf("junk size %d outside [10, 20)", len(b))
		}
	}

	if bufs := dev.junkPackets(4, 64, 64); len(bufs) != 4 {
		t.Fatalf("jc=4 (fixed size) drew %d datagrams", len(bufs))
	} else {
		for _, b := range bufs {
			if len(b) != 64 {
				t.Fatalf("fixed-size junk drew %d bytes, want 64", len(b))
			}
		}
	}

	if bufs := dev.junkPackets(0, 10, 20); len(bufs) != 0 {
		t.Fatalf("jc=0 drew %d datagrams", len(bufs))
	}
	if bufs := dev.junkPackets(3, 20, 10); len(bufs) != 0 {
		t.Fatalf("an inverted range drew %d datagrams", len(bufs))
	}
}

// TestUAPIGetJunkHookLines pins the dump surface: the per-peer junk lines
// appear next to the hop lines when a source is wired (the label, the trio
// and the i-set the NEXT handshake speaks) and stay absent for sourceless
// peers — the device-global jc/jmin/jmax + i1..i5 knobs carry those.
func TestUAPIGetJunkHookLines(t *testing.T) {
	dev, peer, _ := newJunkDevice(t,
		"jc", "2",
		"jmin", "50",
		"jmax", "90",
	)

	src := &junkSourceStub{spec: JunkSpec{Jc: 3, Jmin: 100, Jmax: 200, I: [5]string{"<b 0xc0ff>", "", "<r 16>", "", ""}}, ok: true}
	src.label = "alpha"
	peer.SetJunkSource(src)

	var buf bytes.Buffer
	if err := dev.IpcGetOperation(&buf); err != nil {
		t.Fatalf("IpcGetOperation: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"junk_hook=true\n",
		"junk_strategy=alpha\n",
		"junk_jc=3\n",
		"junk_jmin=100\n",
		"junk_jmax=200\n",
		"junk_i1=<b 0xc0ff>\n",
		"junk_i3=<r 16>\n",
		// the device-level knobs render as-is alongside the hook lines
		"jc=2\n",
		"jmin=50\n",
		"jmax=90\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dump missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "junk_i2=") || strings.Contains(out, "junk_i4=") || strings.Contains(out, "junk_i5=") {
		t.Errorf("unset i-slots must not render:\n%s", out)
	}

	// unwired: the per-peer lines disappear, the device knobs stay
	peer.SetJunkSource(nil)
	buf.Reset()
	if err := dev.IpcGetOperation(&buf); err != nil {
		t.Fatalf("IpcGetOperation: %v", err)
	}
	out = buf.String()
	if strings.Contains(out, "junk_") {
		t.Errorf("an unwired peer must carry no junk_ lines:\n%s", out)
	}
	if !strings.Contains(out, "jc=2\n") {
		t.Errorf("the device knobs must survive the unwiring:\n%s", out)
	}
}
