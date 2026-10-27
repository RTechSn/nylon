package core

import (
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/state"
)

// newZombieTestFactory builds a factory for neighbour "b" owning the range
// 192.168.1.2:30000-30099 (registered with the Nylon's portHopping state, so
// hopOwnedEndpoint sees it) and draws its first carrying endpoint.
func newZombieTestFactory(t *testing.T, n *Nylon) (*portFactory, netip.AddrPort) {
	t.Helper()
	ip := netip.MustParseAddr("192.168.1.2")
	pool := state.NewPortPool([]state.PortGroup{{Addr: ip, Ports: state.PortRange{First: 30000, Last: 30099}}},
		state.PortPoolConfig{Recent: 16, Cooldown: time.Hour, Samples: 4})
	f := &portFactory{n: n, node: "b", pool: pool, bind: conn.NewStdNetBind(), specs: []state.EndpointSpec{
		{Host: ip.String(), Ports: state.PortRange{First: 30000, Last: 30099}},
	}}
	n.portHopping.factories = map[state.NodeId]*portFactory{"b": f}
	f.drawAndMaterialize()
	f.mu.Lock()
	cur := f.current
	f.mu.Unlock()
	if !cur.IsValid() {
		t.Fatal("the factory failed to draw a carrying endpoint")
	}
	return f, cur
}

// TestProbePingDoesNotLearnRemoteLinksInsideFactoryRanges pins the zombie
// incubation fix: a probe ping arriving from a port inside a factory-managed
// range, matching no local link, must NOT learn a remote link. Such a ping is
// by construction a stale rotation artefact (the peer answering or probing
// through a port the local node rotated away from); learning it creates an
// immortal zombie — remote links are exempt from the factory's tombstoning,
// are probed at the full stock cadence, and every pong renews them, so the
// peer keeps answering and the port never goes quiet (field report: the
// operator's router showed a tx/rx rate on every port ever used, including
// the very first ones, a dozen rotations later).
func TestProbePingDoesNotLearnRemoteLinksInsideFactoryRanges(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")
	_, cur := newZombieTestFactory(t, n)

	// a ping from an owned range port that matches no link (not the carrying
	// endpoint): must be ignored
	zEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30042")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	handleProbePing(n, "b", wrappedEndpoint{zEp})
	if l := remoteLinkByAddr(neigh, "192.168.1.2:30042"); l != nil {
		t.Fatalf("a ping from a factory-owned port learned a remote link (%s) — zombie incubation; the carrying endpoint is %s", l.AsNylonEndpoint().Address, cur)
	}
	if got := len(neigh.Eps); got != 1 {
		t.Fatalf("the neighbour must hold exactly the carrying link, got %d links", got)
	}

	// control: an address outside every factory range still learns a remote
	// link (that is the stock endpoint-roaming behaviour)
	rEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.9:51820")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	handleProbePing(n, "b", wrappedEndpoint{rEp})
	if l := remoteLinkByAddr(neigh, "192.168.1.9:51820"); l == nil {
		t.Fatal("a ping from an unowned address must still learn a remote link (endpoint roaming)")
	}
}

// TestReconcileTombstonesRemoteLinksInsideFactoryRanges pins the zombie
// cleanup backstop: reconciliation tombstones every non-current link whose
// address lies inside the factory's ranges, INCLUDING remote (learned) links
// (e.g. incubated before the factory was wired, or by an older build). A link
// on an owned port that is not the carrying endpoint is by construction
// retired; remote links outside the ranges keep the stock behaviour.
func TestReconcileTombstonesRemoteLinksInsideFactoryRanges(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")
	f, cur := newZombieTestFactory(t, n)

	// a zombie remote link inside the factory's range
	zEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.2:30042")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	zombie := state.NewEndpoint("192.168.1.2:30042", true, zEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, zombie)

	// a genuine learned remote endpoint outside the range
	gEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.9:51820")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	genuine := state.NewEndpoint("192.168.1.9:51820", true, gEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, genuine)

	f.reconcileLinks()

	if !zombie.IsExhausted() {
		t.Fatal("a remote link inside the factory's range must be tombstoned (an owned non-carrying port is retired by construction)")
	}
	if genuine.IsExhausted() {
		t.Fatal("a learned remote endpoint outside the factory's ranges must keep stock behaviour")
	}
	if l := hopLinkByAddr(neigh, cur.String()); l == nil || l.IsExhausted() {
		t.Fatal("the carrying link must stay healthy")
	}
}

// TestAdoptLinkEndpointFollowsControlTraffic pins the stale-pin fix: a link's
// stored wireguard endpoint follows the arrival endpoint of every non-pong
// nylon packet (route updates, seqno requests and acks ride the peer's
// CURRENT carrying port, so they are the freshest flow to answer and probe
// through), while endpoints matching no link — and nil endpoints — are
// ignored.
func TestAdoptLinkEndpointFollowsControlTraffic(t *testing.T) {
	n := newHopFixturesNylon(t, time.Hour)
	neigh := n.RouterState.GetNeighbour("b")

	oldEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.1:1234")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	link := state.NewEndpoint("192.168.1.1:1234", false, oldEp, &n.RouterTunables)
	neigh.Eps = append(neigh.Eps, link)

	// control traffic arrives through a differently-tagged endpoint on the
	// same address (a range listener's TaggedEndpoint pinned to the current
	// carrying port): the link's stored endpoint must follow it
	fresh := wrappedEndpoint{oldEp}
	n.adoptLinkEndpoint("b", fresh)
	if link.WgEndpoint != conn.Endpoint(fresh) {
		t.Fatalf("the link's stored endpoint did not follow control traffic (still %T)", link.WgEndpoint)
	}

	// an endpoint matching no link of the neighbour: must not disturb it
	otherEp, err := conn.NewStdNetBind().ParseEndpoint("192.168.1.1:9999")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	n.adoptLinkEndpoint("b", wrappedEndpoint{otherEp})
	if link.WgEndpoint != conn.Endpoint(fresh) {
		t.Fatal("an endpoint matching no link must not disturb the link's stored endpoint")
	}

	// nil endpoint (defensive): no-op
	n.adoptLinkEndpoint("b", nil)
	if link.WgEndpoint != conn.Endpoint(fresh) {
		t.Fatal("a nil endpoint must be a no-op")
	}
}

// remoteLinkByAddr returns the neighbour's REMOTE link with the given address.
func remoteLinkByAddr(neigh *state.Neighbour, addr string) state.Endpoint {
	for _, ep := range neigh.Eps {
		if ep.IsRemote() && ep.AsNylonEndpoint().Address == addr {
			return ep
		}
	}
	return nil
}
