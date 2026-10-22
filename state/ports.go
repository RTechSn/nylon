package state

import (
	"net/netip"

	"github.com/encodeous/nylon/polyamide/conn"
)

// PortRange is re-exported from the transport layer so config and resolution
// code can speak the same port-range vocabulary.
type PortRange = conn.PortRange

// ParsePortRange parses "port" or "portA-portB" (inclusive).
func ParsePortRange(s string) (PortRange, error) {
	return conn.ParsePortRange(s)
}

// AddrPortRange is a resolved endpoint: an address plus an inclusive port
// range. Single-port endpoints are the degenerate case First == Last.
type AddrPortRange struct {
	Addr  netip.Addr
	Ports PortRange
}

// Contains reports whether the given addr:port belongs to this resolved
// endpoint.
func (a AddrPortRange) Contains(ap netip.AddrPort) bool {
	return a.Addr == ap.Addr() && a.Ports.Contains(ap.Port())
}

func (a AddrPortRange) IsSingle() bool {
	return a.Ports.IsSingle()
}

// AddrPort returns the endpoint as a single addr:port (the first port of the
// range). Useful for display and legacy single-port consumers.
func (a AddrPortRange) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(a.Addr, a.Ports.First)
}

func (a AddrPortRange) String() string {
	if a.IsSingle() {
		return a.AddrPort().String()
	}
	host := a.Addr.String()
	if a.Addr.Is4() && !a.Addr.Is4In6() {
		return host + ":" + a.Ports.String()
	}
	return "[" + host + "]:" + a.Ports.String()
}
