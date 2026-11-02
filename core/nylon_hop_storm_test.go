package core

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/encodeous/nylon/perf"
	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
)

// TestHopAdoptDataArrivalCoalescesRotationStorm pins the coalescing contract
// of the TC data-arrival adoption: under a rotation storm (hundreds of
// arrival-signature changes per second) at most ONE adoption closure may sit
// on the dispatch channel per peer — the queued closure adopts the LATEST
// arrival when it runs. A dispatch per rotation is exactly the producer that
// saturates the 128+ slot channel whenever the loop stalls for a few hundred
// milliseconds (cgroup CPU throttling, GC), which discards unrelated
// control-plane work.
func TestHopAdoptDataArrivalCoalescesRotationStorm(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")

	linkEp, err := conn.NewStdNetBind().ParseEndpoint("10.1.1.1:1111")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	link := state.NewEndpoint("10.1.1.1:1111", false, linkEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)

	peer := &device.Peer{}
	nt := map[state.NyPublicKey]state.NodeId{state.NyPublicKey(device.NoisePublicKey{}): "b"}
	n.PeerMap.Store(&nt)

	// a 200-rotation storm: the arrival hint sweeps the range while nothing
	// drains the dispatch channel
	var last conn.Endpoint
	for port := uint16(30001); port <= 30200; port++ {
		last = hintWrap(t, "10.1.1.1:1111", port)
		n.hopAdoptDataArrival(peer, last)
	}
	if got := len(n.DispatchChannel); got != 1 {
		t.Fatalf("a rotation storm must coalesce to exactly ONE queued adoption, got %d dispatches", got)
	}

	// the queued adoption adopts the LATEST arrival, not the one that queued it
	drainDispatch(t, n)
	if link.WgEndpoint != last {
		t.Fatalf("the coalesced adoption must adopt the latest arrival %v, got %v", last, link.WgEndpoint)
	}

	// the next rotation after the queue emptied dispatches again immediately
	next := hintWrap(t, "10.1.1.1:1111", 30499)
	n.hopAdoptDataArrival(peer, next)
	if got := len(n.DispatchChannel); got != 1 {
		t.Fatalf("a signature change with an empty queue must dispatch immediately, got %d dispatches", got)
	}
	drainDispatch(t, n)
	if link.WgEndpoint != next {
		t.Fatal("the link pin must have followed the post-storm rotation")
	}
}

// TestGcReapsLeakedTombstones covers the leak-recovery backstop for
// exhausted-link removals: a grace-timer dispatch discarded on a saturated
// channel leaks its tombstone into Neighbour.Eps forever (nothing re-arms
// it), so the GC pass reaps anything still exhausted a full grace past its
// exhaustion mark. Tombstones inside their grace window and healthy links
// must survive.
func TestGcReapsLeakedTombstones(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")

	leaked := state.NewEndpoint("10.1.1.1:1111", false, nil, &n.RouterTunables)
	leaked.MarkExhaustedAt(time.Now().Add(-hopTombstoneGcAge - time.Second))

	leakedRemote := state.NewEndpoint("10.2.2.2:2222", true, nil, &n.RouterTunables)
	leakedRemote.MarkExhaustedAt(time.Now().Add(-2 * hopTombstoneGcAge))

	freshTombstone := state.NewEndpoint("10.1.1.1:3333", false, nil, &n.RouterTunables)
	freshTombstone.MarkExhaustedAt(time.Now())

	healthy := state.NewEndpoint("10.1.1.1:4444", false, nil, &n.RouterTunables)

	neigh.Eps = append(neigh.Eps, leaked, leakedRemote, freshTombstone, healthy)

	n.gcHopTombstones()

	if got := len(neigh.Eps); got != 2 {
		t.Fatalf("the GC must reap exactly the leaked tombstones, got %d remaining links", got)
	}
	if hopLinkByAddr(neigh, "10.1.1.1:1111") != nil {
		t.Error("the leaked tombstone must be reaped")
	}
	if hopLinkByAddr(neigh, "10.2.2.2:2222") != nil {
		t.Error("the leaked remote tombstone (supersede path) must be reaped")
	}
	if hopLinkByAddr(neigh, "10.1.1.1:3333") == nil {
		t.Error("a tombstone inside its grace window must survive (late pongs still match it)")
	}
	if hopLinkByAddr(neigh, "10.1.1.1:4444") == nil {
		t.Error("a healthy link must never be reaped by the tombstone sweep")
	}
}

// TestDispatchDropAccounting verifies that a saturated dispatch channel
// counts every discarded function into perf.DispatchDropsTotal and journals
// at most one ERROR per window (the first drop carries the window count;
// the rest demote to Debug) — a storm of per-drop ERRORs would bury the
// journal exactly when the operator needs to read it.
func TestDispatchDropAccounting(t *testing.T) {
	var buf bytes.Buffer
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	n := &Nylon{
		DispatchChannel: make(chan func() error, 1),
		Context:         ctx,
		Cancel:          cancel,
		Log:             slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}

	// occupy the single queue slot
	n.DispatchChannel <- func() error { return nil }

	base := perf.DispatchDropsTotal.Load()
	nop := func() error { return nil }
	n.Dispatch(nop)
	n.Dispatch(nop)

	if got := perf.DispatchDropsTotal.Load() - base; got != 2 {
		t.Fatalf("both discarded functions must be counted, got %d", got)
	}
	// the first drop emits (lastLog is zero) and resets the window, so the
	// counter holds the drops accumulated SINCE the last emission
	if n.dispatchDrops.window != 1 {
		t.Fatalf("the window counter must hold drops since the last emission, got %d", n.dispatchDrops.window)
	}

	logged := strings.Count(buf.String(), "dispatch channel is full")
	if logged != 2 {
		t.Fatalf("each drop journals exactly once (first at ERROR, rest at Debug), got %d lines", logged)
	}
	if !strings.Contains(buf.String(), "drops_in_window=1") {
		t.Error("the first drop's ERROR line must carry the running window count")
	}

	// draining the channel restores normal dispatch: no drop, no counter move
	<-n.DispatchChannel
	n.Dispatch(nop)
	if got := perf.DispatchDropsTotal.Load() - base; got != 2 {
		t.Fatalf("a healthy queue must not count drops, got %d", got)
	}
	if got := len(n.DispatchChannel); got != 1 {
		t.Fatalf("the function must have been enqueued, got queue len %d", got)
	}

	// the future flavour fails its caller AND counts the drop
	n.Dispatch(nop) // fills the queue again (drops: the slot was taken by nop above)
	before := perf.DispatchDropsTotal.Load()
	fut := NewDispatchFuture[int](n, func() (int, error) { return 42, nil })
	if _, err := fut.Await(context.Background()); err == nil || !strings.Contains(err.Error(), "dispatch channel is full") {
		t.Fatalf("a saturated queue must fail the future, got %v", err)
	}
	if got := perf.DispatchDropsTotal.Load() - before; got != 1 {
		t.Fatalf("the discarded future must be counted, got %d", got)
	}
}
