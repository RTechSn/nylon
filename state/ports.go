package state

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/encodeous/nylon/polyamide/conn"
)

// PortRange is re-exported from the transport layer so config and resolution
// code can speak the same port-range vocabulary.
type PortRange = conn.PortRange

// MaxInDaemonListenPorts is the ceiling on the number of ports the in-daemon
// (N-socket) range listener will bind; wider ranges must use the netfilter
// DNAT deployment mode.
const MaxInDaemonListenPorts = conn.MaxListenRangePorts

// ParsePortRange parses "port" or "portA-portB" (inclusive).
func ParsePortRange(s string) (PortRange, error) {
	return conn.ParsePortRange(s)
}

// EndpointSpec is a parsed `endpoints` entry: a host plus an inclusive port
// range. Single-port endpoints are the degenerate case Ports.IsSingle().
// A bare host keeps the default port, exactly like the classic resolver.
type EndpointSpec struct {
	Host  string
	Ports PortRange
}

// IsRange reports whether the spec covers more than one port.
func (s EndpointSpec) IsRange() bool {
	return s.Ports.Valid() && !s.Ports.IsSingle()
}

// String renders the spec in config form.
func (s EndpointSpec) String() string {
	host := s.Host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() && !addr.Is4In6() {
		host = "[" + host + "]"
	}
	if !s.Ports.Valid() {
		return host
	}
	return host + ":" + s.Ports.String()
}

// ParseEndpointSpec parses an endpoint string into a host and a port range.
// Accepted forms: "host", "host:port", "host:portA-portB", with IPv6 hosts in
// brackets. Bare hosts keep the default nylon port.
func ParseEndpointSpec(value string) (EndpointSpec, error) {
	if value == "" {
		return EndpointSpec{}, fmt.Errorf("endpoint is empty")
	}
	if strings.Contains(value, "://") {
		return EndpointSpec{}, fmt.Errorf("invalid endpoint %q", value)
	}

	// literal addr or addr:portrange fast paths
	if addr, err := netip.ParseAddr(value); err == nil {
		return EndpointSpec{Host: addr.String(), Ports: PortRange{First: DefaultPort, Last: DefaultPort}}, nil
	}
	if ap, err := netip.ParseAddrPort(value); err == nil {
		return EndpointSpec{Host: ap.Addr().String(), Ports: PortRange{First: ap.Port(), Last: ap.Port()}}, nil
	}

	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		if strings.Contains(value, ":") {
			// could be a bare IPv6 literal with a port range, e.g. [::1]:100-200
			// (SplitHostPort handles brackets; a parse failure here is real)
			return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: %w", value, err)
		}
		// bare hostname
		return EndpointSpec{Host: value, Ports: PortRange{First: DefaultPort, Last: DefaultPort}}, nil
	}
	if host == "" {
		return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: empty host", value)
	}
	// normalize bracketed hosts to bare form
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	ports, err := ParsePortRange(portString)
	if err != nil {
		return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: %w", value, err)
	}
	return EndpointSpec{Host: host, Ports: ports}, nil
}

// FormatAddrPort renders addr:port in endpoint form (bracketed for IPv6).
func FormatAddrPort(ap netip.AddrPort) string {
	return ap.String()
}

// ParsePort parses a plain decimal port.
func ParsePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", s, err)
	}
	if p == 0 {
		return 0, fmt.Errorf("port must be greater than 0")
	}
	return uint16(p), nil
}
