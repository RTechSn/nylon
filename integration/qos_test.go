//go:build integration

package integration

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/polyamide/conn/bindtest"
	"github.com/encodeous/nylon/state"
	"go.uber.org/goleak"
)

// qosRig builds a two-node rig: a sends inner traffic to b through the
// tunnel; rules controls where a's priority_rules come from (node = node.yaml
// side, central = the central router entry, centralGlobal = the mesh-wide
// top-level list, centralRouterBeatsGlobal = both — the entry must win,
// centralEmpty = an empty central list that must clear node rules wholesale,
// none = no rules anywhere).
func qosRig(t *testing.T, rules string, nodeRules []state.PriorityRule, centralRules []state.PriorityRule) (*VirtualHarness, string, chan error) {
	t.Helper()
	vh := &VirtualHarness{}
	a1 := "192.168.1.1:1234"
	vh.NewNode("a", "10.0.0.1/32")
	b1 := "192.168.1.2:1234"
	vh.NewNode("b", "10.0.0.2/32")
	vh.Central.Graph = []string{
		"a, b",
	}
	vh.Endpoints = map[string]state.NodeId{
		a1: "a",
		b1: "b",
	}
	vh.AddLink(a1, b1)
	vh.AddLink(b1, a1)

	switch rules {
	case "node":
		aIdx := vh.IndexOf("a")
		vh.Local[aIdx].PriorityRules = nodeRules
	case "central":
		aIdx := vh.IndexOf("a")
		vh.Central.Routers[aIdx].PriorityRules = centralRules
	case "centralGlobal":
		vh.Central.PriorityRules = centralRules
	case "centralRouterBeatsGlobal":
		aIdx := vh.IndexOf("a")
		dscp := 10
		// the router's own list must win wholesale over the mesh-wide
		// default: the entry marks udp/5405 with dscp 10 (TOS 0x28) while
		// the global list would stamp EF (0xb8) — only the entry's marking
		// may appear on the wire
		vh.Central.Routers[aIdx].PriorityRules = []state.PriorityRule{
			{Protocol: "udp", Port: "5405", Priority: state.PriorityHigh, Dscp: &dscp},
		}
		vh.Central.PriorityRules = centralRules
	case "centralEmpty":
		aIdx := vh.IndexOf("a")
		vh.Central.Routers[aIdx].PriorityRules = []state.PriorityRule{}
		vh.Local[aIdx].PriorityRules = nodeRules
	case "none":
		// nothing
	default:
		t.Fatalf("unknown rules source %q", rules)
	}

	errs := vh.Start()
	return vh, b1, errs
}

// qosUDP builds an inner UDP datagram (the payload the virtual network
// injects after the IP header).
func qosUDP(sport, dport uint16, payload byte) []byte {
	b := make([]byte, 9)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], 9)
	b[8] = payload
	return b
}

// qosFlow waits until both probe classes (marked dport 5405 payload 1 and
// control dport 7999 payload 2) have been delivered to b, then reports a's
// device-side per-TOS outer-datagram counts toward b.
func qosFlow(t *testing.T, vh *VirtualHarness, b1 string, errs chan error) (bindtest.ChannelEndpoint2, map[byte]uint64) {
	t.Helper()
	vn := vh.Net
	received := make(chan byte, 1024)
	vn.SelfHandler = func(node state.NodeId, src, dst netip.Addr, data []byte) bool {
		if node == "b" && src.String() == "10.0.0.1" && len(data) >= 9 {
			received <- data[8]
		}
		return true
	}

	go func() {
		for {
			select {
			case <-vh.Context.Done():
				return
			case <-time.After(50 * time.Millisecond):
				vn.SendProto("a", "10.0.0.1", "10.0.0.2", qosUDP(40000, 5405, 1), 64, 17)
				vn.SendProto("a", "10.0.0.1", "10.0.0.2", qosUDP(40000, 7999, 2), 64, 17)
			}
		}
	}()

	gotMarked, gotControl := false, false
	deadline := time.After(15 * time.Second)
	for !(gotMarked && gotControl) {
		select {
		case p := <-received:
			if p == 1 {
				gotMarked = true
			}
			if p == 2 {
				gotControl = true
			}
		case err := <-errs:
			t.Fatal(err)
		case <-deadline:
			t.Fatal("timed out waiting for both probe classes through the tunnel")
		}
	}

	db, ok := vn.DevBind("a").(*bindtest.ChannelBind2)
	if !ok {
		t.Fatalf("device bind of a is %T, want *bindtest.ChannelBind2", vn.DevBind("a"))
	}
	return bindtest.ChannelEndpoint2(netip.MustParseAddrPort(b1)), db.TOSCounts(bindtest.ChannelEndpoint2(netip.MustParseAddrPort(b1)))
}

func TestQoSNodeRulesMarkOuterDatagrams(t *testing.T) {
	defer goleak.VerifyNone(t)
	vh, b1, errs := qosRig(t, "node", []state.PriorityRule{
		{Protocol: "udp", Port: "5405", Priority: state.PriorityHigh},
	}, nil)
	defer vh.Stop()

	bEp, counts := qosFlow(t, vh, b1, errs)

	if counts[0xb8] == 0 {
		t.Errorf("no EF-marked outer datagrams toward %v (counts: %v)", bEp, counts)
	}
	if counts[0] == 0 {
		t.Errorf("no unmarked outer datagrams toward %v — the control flow and the mesh's own control traffic must stay unmarked (counts: %v)", bEp, counts)
	}
	for tos, n := range counts {
		if tos != 0 && tos != 0xb8 {
			t.Errorf("unexpected TOS %#02x on %d outer datagrams toward %v", tos, n, bEp)
		}
	}
}

func TestQoSCentralRulesMarkOuterDatagrams(t *testing.T) {
	defer goleak.VerifyNone(t)
	vh, b1, errs := qosRig(t, "central", nil, []state.PriorityRule{
		{Protocol: "udp", Port: "5405", Priority: state.PriorityHigh},
		{Protocol: "tcp", Port: "22", Priority: state.PriorityHigh},
	})
	defer vh.Stop()

	bEp, counts := qosFlow(t, vh, b1, errs)

	if counts[0xb8] == 0 {
		t.Errorf("no EF-marked outer datagrams toward %v from central rules (counts: %v)", bEp, counts)
	}
	if counts[0] == 0 {
		t.Errorf("no unmarked outer datagrams toward %v (counts: %v)", bEp, counts)
	}
}

func TestQoSCentralEmptyListFallsBackToNodeRules(t *testing.T) {
	defer goleak.VerifyNone(t)
	// an empty central list is indistinguishable from an absent one (yaml
	// omitempty roundtrips drop empty lists): the node rules still apply
	vh, b1, errs := qosRig(t, "centralEmpty", []state.PriorityRule{
		{Protocol: "udp", Port: "5405", Priority: state.PriorityHigh},
	}, nil)
	defer vh.Stop()

	bEp, counts := qosFlow(t, vh, b1, errs)

	if counts[0xb8] == 0 {
		t.Errorf("no EF-marked outer datagrams toward %v from node rules (counts: %v)", bEp, counts)
	}
	if counts[0] == 0 {
		t.Errorf("no unmarked outer datagrams toward %v (counts: %v)", bEp, counts)
	}
}

func TestQoSNoRulesLeaveEverythingUnmarked(t *testing.T) {
	defer goleak.VerifyNone(t)
	vh, b1, errs := qosRig(t, "none", nil, nil)
	defer vh.Stop()

	bEp, counts := qosFlow(t, vh, b1, errs)

	if len(counts) != 1 || counts[0] == 0 {
		t.Errorf("expected only unmarked outer datagrams toward %v, counts: %v", bEp, counts)
	}
}

func TestQoSCentralGlobalRulesMarkOuterDatagrams(t *testing.T) {
	defer goleak.VerifyNone(t)
	// priority_rules at the TOP LEVEL of central.yaml — the mesh-wide
	// default — must reach every node through the distributed config
	vh, b1, errs := qosRig(t, "centralGlobal", nil, []state.PriorityRule{
		{Protocol: "udp", Port: "5405", Priority: state.PriorityHigh},
	})
	defer vh.Stop()

	bEp, counts := qosFlow(t, vh, b1, errs)

	if counts[0xb8] == 0 {
		t.Errorf("no EF-marked outer datagrams toward %v from mesh-wide rules (counts: %v)", bEp, counts)
	}
	if counts[0] == 0 {
		t.Errorf("no unmarked outer datagrams toward %v (counts: %v)", bEp, counts)
	}
}

func TestQoSRouterEntryBeatsCentralGlobalRules(t *testing.T) {
	defer goleak.VerifyNone(t)
	// the node's own routers[] entry (dscp 10 -> TOS 0x28) must win wholesale
	// over the central top-level list (EF 0xb8): only the entry's marking
	// may appear on the wire
	vh, b1, errs := qosRig(t, "centralRouterBeatsGlobal", nil, []state.PriorityRule{
		{Protocol: "udp", Port: "5405", Priority: state.PriorityHigh},
	})
	defer vh.Stop()

	bEp, counts := qosFlow(t, vh, b1, errs)

	if counts[0x28] == 0 {
		t.Errorf("no dscp-10-marked outer datagrams toward %v from the router entry (counts: %v)", bEp, counts)
	}
	if counts[0xb8] != 0 {
		t.Errorf("mesh-wide rules leaked past the router entry toward %v (counts: %v)", bEp, counts)
	}
	if counts[0] == 0 {
		t.Errorf("no unmarked outer datagrams toward %v (counts: %v)", bEp, counts)
	}
}
