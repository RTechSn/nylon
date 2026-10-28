/* SPDX-License-Identifier: MIT *
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
)

// hintEP wraps an endpoint with a local reply-port hint, mirroring what the
// range listener's receive functions produce (conn.TaggedEndpoint).
type hintEP struct {
	conn.Endpoint
	hint uint16
}

func (e *hintEP) PortHint() uint16 { return e.hint }

var (
	_ conn.Endpoint                  = (*hintEP)(nil)
	_ interface{ PortHint() uint16 } = (*hintEP)(nil)
)

func epOf(ap string) conn.Endpoint {
	ep, err := conn.NewStdNetBind().ParseEndpoint(ap)
	if err != nil {
		panic(err)
	}
	return ep
}

// TestSetEndpointFromPacketRefreshesHintOnSameRemote pins the reply-port
// symmetry of the device endpoint under port hopping: an authenticated packet
// arriving from the SAME remote address through a NEW LOCAL PORT (the peer
// rotated its flow onto the next carrying port of our listen range) must
// refresh the stored val[0] endpoint so every reply egresses from the port
// the peer's traffic is currently addressed to. Before this, replies kept
// leaving through the port the peer rotated away from until a slower control
// path moved the pin — visible on the wire as the server answering through
// the previous port for seconds after every rotation.
func TestSetEndpointFromPacketRefreshesHintOnSameRemote(t *testing.T) {
	remote := "192.0.2.9:41414"
	other := "198.51.100.7:51820"

	p := &Peer{}
	p.SetEndpoints([]conn.Endpoint{&hintEP{Endpoint: epOf(remote), hint: 30001}})

	// same remote, new local port: hint must refresh
	fresh := &hintEP{Endpoint: epOf(remote), hint: 30042}
	p.SetEndpointFromPacket(fresh)
	if got := p.CurrentEndpoint(); got != conn.Endpoint(fresh) {
		t.Fatalf("val[0] must follow the same-remote arrival to the new local port (still %v, want %v)", got, fresh)
	}
	if h, ok := p.CurrentEndpoint().(interface{ PortHint() uint16 }); !ok || h.PortHint() != 30042 {
		t.Fatalf("the refreshed endpoint must carry the arrival hint %d", 30042)
	}

	// a DIFFERENT remote is a roaming decision owned by the link table /
	// config (managed endpoints for router peers): must not move val[0]
	roam := &hintEP{Endpoint: epOf(other), hint: 30050}
	p.SetEndpointFromPacket(roam)
	if got := p.CurrentEndpoint(); got == conn.Endpoint(roam) {
		t.Fatal("an arrival from a different remote must not roam a managed router peer's endpoint")
	}

	// duplicate arrival (same object): no change, and no udpWindow churn
	before := p.CurrentEndpoint()
	p.SetEndpointFromPacket(before)
	if got := p.CurrentEndpoint(); got != before {
		t.Fatal("a duplicate arrival must not disturb val[0]")
	}
}

// TestSetEndpointFromPacketRoamingModes pins the pre-existing modes the
// hint-refresh must not regress: preferRoaming peers follow any remote,
// fully-managed (disableRoaming) peers ignore arrivals entirely, and an empty
// endpoint list adopts the first arrival.
func TestSetEndpointFromPacketRoamingModes(t *testing.T) {
	remote := "192.0.2.9:41414"
	other := "198.51.100.7:51820"

	t.Run("preferRoaming follows any remote", func(t *testing.T) {
		p := &Peer{}
		p.SetEndpoints([]conn.Endpoint{epOf(remote)})
		p.SetPreferRoaming(true)
		p.SetEndpointFromPacket(epOf(other))
		if got := p.CurrentEndpoint(); got.DstIPPort().String() != other {
			t.Fatalf("preferRoaming peer must roam to %s, got %v", other, got)
		}
	})

	t.Run("disableRoaming ignores arrivals", func(t *testing.T) {
		p := &Peer{}
		p.SetEndpoints([]conn.Endpoint{&hintEP{Endpoint: epOf(remote), hint: 30001}})
		p.endpoints.disableRoaming = true
		p.SetEndpointFromPacket(&hintEP{Endpoint: epOf(remote), hint: 30002})
		if h := p.CurrentEndpoint().(interface{ PortHint() uint16 }).PortHint(); h != 30001 {
			t.Fatalf("disableRoaming peer must ignore arrivals (hint moved %d -> %d)", 30001, h)
		}
	})

	t.Run("empty adopts first arrival", func(t *testing.T) {
		p := &Peer{}
		p.SetEndpointFromPacket(epOf(remote))
		if got := p.CurrentEndpoint(); got == nil || got.DstIPPort().String() != remote {
			t.Fatalf("first arrival must be adopted, got %v", got)
		}
	})
}

// TestCurrentEndpointEmpty asserts the accessor's nil contract used by the
// probe merge path (hopProbeEndpoint).
func TestCurrentEndpointEmpty(t *testing.T) {
	p := &Peer{}
	if got := p.CurrentEndpoint(); got != nil {
		t.Fatalf("CurrentEndpoint on an empty peer must be nil, got %v", got)
	}
}
