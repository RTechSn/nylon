package core

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

// blockingSendBind wraps a bind whose Send parks until the test releases it.
// It gives the test a goroutine that deterministically holds the device net
// READ lock (a sender parked inside Peer.SendBuffers) — the send-path half of
// the getPortFactory lock inversion this file pins.
type blockingSendBind struct {
	conn.Bind
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingSendBind() *blockingSendBind {
	return &blockingSendBind{
		Bind:    conn.NewStdNetBind(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *blockingSendBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return nil // the buffers are test dummies; nothing observes them
}

// newDeadlockFixtureNylon builds the hop-fixtures nylon around a blocking
// bind, with the router neighbour "b" configured with a range endpoint and a
// device peer, so ensurePortFactories wires a hop source exactly as in
// production.
func newDeadlockFixtureNylon(t *testing.T) (*Nylon, device.NoisePublicKey, *blockingSendBind) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancelCause(context.Background())
	tunables := state.DefaultRouterTunables()

	key := state.GenerateKey()
	pub := key.Pubkey()

	n := &Nylon{
		Trace:           &NylonTrace{},
		RouterTunables:  tunables,
		Context:         ctx,
		Cancel:          cancel,
		DispatchChannel: make(chan func() error, 128),
		Log:             logger,
		PingBuf: ttlcache.New[uint64, EpPing](
			ttlcache.WithTTL[uint64, EpPing](5*time.Second),
			ttlcache.WithDisableTouchOnHit[uint64, EpPing](),
		),
		EndpointResolver: state.NewEndpointResolver(state.NewDNSResolver(nil)),
		ConfigState: state.ConfigState{
			CentralCfg: state.CentralCfg{
				ObfStrategies: map[string]*state.ObfStrategy{
					"hop": {
						Ports:           "30000-30009",
						PortHoppingMode: state.HopModeProactive,
						PortHopping:     &state.PortHoppingCfg{BudgetPackets: uint32ptr2(12)},
					},
				},
				Routers: []state.RouterCfg{
					{NodeCfg: state.NodeCfg{Id: "a"}},
					{
						NodeCfg:   state.NodeCfg{Id: "b", PubKey: pub},
						Endpoints: []string{"192.168.1.2[hop]"},
					},
				},
				Graph: []string{"a, b"},
			},
			LocalCfg: state.LocalCfg{Id: "a"},
		},
	}
	n.router.log = logger
	n.RouterState = &state.RouterState{
		RouterTunables:  &n.RouterTunables,
		Id:              "a",
		SelfSeqno:       make(map[netip.Prefix]uint16),
		Routes:          make(map[netip.Prefix]state.SelRoute),
		RouteSelectedAt: make(map[netip.Prefix]time.Time),
		Sources:         make(map[state.Source]state.FD),
		Neighbours:      []*state.Neighbour{{Id: "b", Routes: make(map[netip.Prefix]state.NeighRoute)}},
		Advertised:      make(map[netip.Prefix]state.Advertisement),
	}

	bind := newBlockingSendBind()
	dev := device.NewDevice(tun.NewDummyDevice("hopdead", 1420), bind, device.NewLogger(device.LogLevelSilent, "hopdead"))
	n.Device = dev
	peer, err := dev.NewPeer(device.NoisePublicKey(pub))
	if err != nil {
		t.Fatalf("adding device peer: %v", err)
	}
	_ = peer

	t.Cleanup(func() {
		_ = dev.Bind().Close()
		dev.Close()
		n.Cancel(nil)
	})
	return n, device.NoisePublicKey(pub), bind
}

// TestGetPortFactoryBindsWithoutFactoryLock pins the lock order of
// getPortFactory: the device bind (the net WRITE lock) must be acquired
// BEFORE the factory mutex. The packet send path holds the net READ lock
// across its whole body, including the factory mutex sections inside
// NextHopEndpoint, so the old order (f.mu held while waiting for the write
// lock in Device.Bind) is a mutual deadlock:
//
//	dispatch loop:  f.mu -> net.WLock
//	send path:      net.RLock -> f.mu
//
// Both goroutines park forever with an idle CPU; every dispatch after the
// freeze is discarded and no link is ever materialised again (field report:
// the freeze landed with the first pool-exhaustion auto-recycle, when the
// sender began holding the factory locks for hundreds of milliseconds).
//
// The test parks a sender inside bind.Send (holding the READ lock), runs the
// reconciliation concurrently and then takes the factory mutex itself — the
// position of a second send path inside NextHopEndpoint. With the correct
// order the reconciler parks in Device.Bind holding no factory lock, so the
// take succeeds; with the inverted order it holds f.mu and the take fails
// until the sender is released (a deadlock).
func TestGetPortFactoryBindsWithoutFactoryLock(t *testing.T) {
	n, pub, bind := newDeadlockFixtureNylon(t)

	// No matter how the test fails, the parked sender must always be released
	// before cleanup: it holds the device net READ lock, and t.Cleanup's
	// dev.Close() takes the write lock — an unreleased sender would turn any
	// failure into a hang of the whole test binary.
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(bind.release) }) }
	defer release()

	// wire the factory and the hop source as production does
	if err := n.ensurePortFactories(); err != nil {
		t.Fatalf("ensurePortFactories: %v", err)
	}
	drainDispatch(t, n)

	peer := n.Device.LookupPeer(pub)
	if peer == nil {
		t.Fatal("device peer missing")
	}
	n.portHopping.mu.Lock()
	f := n.portHopping.factories["b"]
	n.portHopping.mu.Unlock()
	if f == nil {
		t.Fatal("port factory missing")
	}

	ep, err := bind.ParseEndpoint("192.168.1.2:30000")
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}

	// The device peer needs at least one endpoint to pass SendBuffers' "no
	// known endpoints" guard (production pushes the materialised link's
	// endpoint here on every reconciliation pass).
	peer.SetEndpoints([]conn.Endpoint{ep})

	// The sender parks inside bind.Send while holding the device net READ
	// lock — the position of a send path in the middle of a batch.
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		_ = peer.SendBuffers([][]byte{make([]byte, 128)}, []conn.Endpoint{ep})
	}()
	select {
	case <-bind.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("sender never reached bind.Send")
	}

	// The dispatch loop runs its periodic reconciliation (every
	// SyncApplicationState pass), which refreshes the factory's bind cache
	// through getPortFactory.
	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- n.ensurePortFactories() }()

	// Let the reconciler reach its park: with the correct order it waits for
	// the net WRITE lock (held by the parked sender) holding NO factory lock;
	// with the inverted order it additionally holds f.mu. Both sides reach
	// their park within microseconds; the settle delay only absorbs CI
	// scheduling jitter.
	time.Sleep(250 * time.Millisecond)

	// What a concurrent send path does inside NextHopEndpoint: take the
	// factory mutex while the READ lock is still held elsewhere.
	deadline := time.Now().Add(3 * time.Second)
	for !f.mu.TryLock() {
		if time.Now().After(deadline) {
			t.Fatal("getPortFactory held the factory mutex while waiting for the device net write lock — lock-order regression (dispatch loop vs send path deadlock)")
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Unlock()

	// Let the reconciler through: release the sender, then both goroutines
	// must finish.
	release()
	select {
	case err := <-reconcileDone:
		if err != nil {
			t.Fatalf("ensurePortFactories: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconciler never returned after the sender was released")
	}
	select {
	case <-senderDone:
	case <-time.After(5 * time.Second):
		t.Fatal("sender never returned after the bind was released")
	}
}
