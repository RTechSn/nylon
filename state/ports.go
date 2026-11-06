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

// EndpointSpec is a parsed `endpoints` entry. Three forms exist:
//
//	host                       bare host: default port, or — in a mesh with
//	                           obf strategies — every strategy's ports
//	host:port                  raw fixed-port endpoint, no strategy
//	host[strategy1,strategy2]  strategy-tagged: the ports come from the named
//	                           strategies ("*" or an untagged host = all)
//
// with IPv6 hosts bracketed as usual: "[2001:db8::1]:51820",
// "[2001:db8::1][strats]". Inline port RANGES in endpoints are gone: they
// moved into obf strategies (ParseEndpointSpec rejects them with a migration
// error). Tagged specs carry no port of their own; the strategy provides it.
type EndpointSpec struct {
	Host       string
	Ports      PortRange
	Strategies []string
}

// HasStrategies reports whether the spec selects obf strategies.
func (s EndpointSpec) HasStrategies() bool {
	return len(s.Strategies) > 0
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
	var b strings.Builder
	b.WriteString(host)
	if s.Ports.Valid() {
		b.WriteString(":")
		b.WriteString(s.Ports.String())
	}
	if len(s.Strategies) > 0 {
		b.WriteString("[")
		b.WriteString(strings.Join(s.Strategies, ","))
		b.WriteString("]")
	}
	return b.String()
}

// parseStrategyTagList parses the inside of a "[...]" strategy group:
// comma-separated names ("*" alone means every defined strategy). Names are
// validated with the shared node-name pattern so they cannot smuggle
// separators or address syntax; the referenced strategies' existence is
// checked against the strategy map by EndpointStrategyTags.
func parseStrategyTagList(inner string) ([]string, error) {
	parts := strings.Split(inner, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("empty obf strategy name in %q (remove the empty entry)", "["+inner+"]")
		}
		if p == "*" {
			if len(parts) != 1 {
				return nil, fmt.Errorf("the obf strategy wildcard %q must stand alone in the tag list", "*")
			}
			return []string{"*"}, nil
		}
		if err := NameValidator(p); err != nil {
			return nil, fmt.Errorf("invalid obf strategy tag %q: %w", p, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// ParseEndpointSpec parses an endpoint string into a host, an optional fixed
// port and an optional strategy tag list. Accepted forms: "host",
// "host:port", "host[strats]", "host[*]", with IPv6 hosts in brackets.
// Bare hosts keep the default nylon port when the mesh defines no strategies
// (with strategies, the connect half expands them through every strategy).
// Inline port ranges ("host:portA-portB") moved into obf strategies and are
// rejected with a migration error.
func ParseEndpointSpec(value string) (EndpointSpec, error) {
	if value == "" {
		return EndpointSpec{}, fmt.Errorf("endpoint is empty")
	}
	if strings.Contains(value, "://") {
		return EndpointSpec{}, fmt.Errorf("invalid endpoint %q", value)
	}

	var strategies []string
	if strings.HasSuffix(value, "]") {
		if i := strings.LastIndexByte(value, '['); i >= 0 {
			inner := value[i+1 : len(value)-1]
			// A bracket group containing ':' is a bare IPv6 literal, not a
			// strategy list ("[2001:db8::1]" alone).
			if !strings.Contains(inner, ":") {
				var err error
				strategies, err = parseStrategyTagList(inner)
				if err != nil {
					return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: %w", value, err)
				}
				value = value[:i]
				if value == "" {
					return EndpointSpec{}, fmt.Errorf("invalid endpoint: strategy tags without a host")
				}
			}
		} else {
			return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: unmatched ']'", value)
		}
	}

	// bare bracketed host after tag stripping (e.g. "[2001:db8::1][awg]"):
	// unbracket it before the fast paths
	if len(strategies) > 0 && strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		if addr, err := netip.ParseAddr(value[1 : len(value)-1]); err == nil {
			return EndpointSpec{Host: addr.String(), Strategies: strategies}, nil
		}
		return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: invalid bracketed host", value)
	}

	// literal addr fast path: a bare host (no port, no tags) keeps an
	// invalid Ports — "explicit port" and "bare host" must stay
	// distinguishable (the resolver and the strategy expansion each default
	// it in their own way)
	if addr, err := netip.ParseAddr(value); err == nil {
		if len(strategies) > 0 {
			return EndpointSpec{Host: addr.String(), Strategies: strategies}, nil
		}
		return EndpointSpec{Host: addr.String()}, nil
	}
	if ap, err := netip.ParseAddrPort(value); err == nil {
		if len(strategies) > 0 {
			return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: an explicit port cannot be combined with obf strategy tags — the strategy carries the ports", value)
		}
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
		host = value
		portString = ""
	}
	if host == "" {
		return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: empty host", value)
	}
	// normalize bracketed hosts to bare form
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	spec := EndpointSpec{Host: host, Strategies: strategies}
	if portString != "" {
		if len(strategies) > 0 {
			return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: an explicit port cannot be combined with obf strategy tags — the strategy carries the ports", value)
		}
		if strings.Contains(portString, "-") {
			return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: inline port ranges moved into obf strategies — define a strategy with ports: %q and tag the endpoint host[strategy], or use a single port", value, portString)
		}
		port, err := ParsePort(portString)
		if err != nil {
			return EndpointSpec{}, fmt.Errorf("invalid endpoint %q: %w", value, err)
		}
		// an explicit port is the raw fixed-endpoint form; a bare host keeps
		// an invalid Ports so consumers can tell the two apart
		spec.Ports = PortRange{First: port, Last: port}
	}
	return spec, nil
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
