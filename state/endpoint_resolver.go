package state

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/encodeous/nylon/polyamide/conn"
)

type dnsLookup interface {
	ResolveName(ctx context.Context, host string) ([]netip.Addr, error)
	ResolveSRV(ctx context.Context, service, proto, name string) (string, uint16, error)
}

// EndpointResolver centrally owns resolved endpoint state for a Nylon instance.
// Cache entries are shared by every link configured with the same address.
type EndpointResolver struct {
	dns   dnsLookup
	mu    sync.RWMutex
	cache map[string]*endpointResolution
}

type endpointResolution struct {
	mu      sync.RWMutex
	refresh sync.Mutex
	value   AddrPortRange
	updated time.Time
}

func NewEndpointResolver(dns *DNSResolver) *EndpointResolver {
	if dns == nil {
		dns = NewDNSResolver(nil)
	}
	return newEndpointResolver(dns)
}

func newEndpointResolver(dns dnsLookup) *EndpointResolver {
	return &EndpointResolver{
		dns:   dns,
		cache: make(map[string]*endpointResolution),
	}
}

func (r *EndpointResolver) Resolve(endpoint string, expiry time.Duration) (AddrPortRange, error) {
	if addr, err := netip.ParseAddrPort(endpoint); err == nil {
		return AddrPortRange{Addr: addr.Addr(), Ports: PortRange{First: addr.Port(), Last: addr.Port()}}, nil
	}

	entry := r.entry(endpoint)
	entry.mu.RLock()
	value, updated := entry.value, entry.updated
	entry.mu.RUnlock()
	if value.Addr.IsValid() && time.Since(updated) < expiry {
		return value, nil
	}

	host, ports, err := parseEndpoint(endpoint)
	if err != nil {
		return AddrPortRange{}, err
	}

	// Literal IP hosts never need DNS.
	if ip, ipErr := netip.ParseAddr(host); ipErr == nil {
		value = AddrPortRange{Addr: ip, Ports: ports}
		entry.mu.Lock()
		entry.updated = time.Now()
		entry.value = value
		entry.mu.Unlock()
		return value, nil
	}

	// Only one goroutine refreshes an endpoint at a time, but do not hold the
	// value lock while doing DNS I/O. Dispatch-path readers must be able to keep
	// using the last successful resolution while a refresh is in flight.
	entry.refresh.Lock()
	defer entry.refresh.Unlock()
	entry.mu.RLock()
	value, updated = entry.value, entry.updated
	entry.mu.RUnlock()
	if value.Addr.IsValid() && time.Since(updated) < expiry {
		return value, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// SRV records carry a single port and cannot express ranges; only consult
	// them for single-port endpoints.
	if ports.IsSingle() {
		if target, srvPort, err := r.dns.ResolveSRV(ctx, "nylon", "udp", host); err == nil {
			if addrs, err := r.dns.ResolveName(ctx, target); err == nil && len(addrs) > 0 {
				value = AddrPortRange{Addr: addrs[0], Ports: PortRange{First: srvPort, Last: srvPort}}
				entry.mu.Lock()
				entry.updated = time.Now()
				entry.value = value
				entry.mu.Unlock()
				return value, nil
			}
		}
	}

	addrs, err := r.dns.ResolveName(ctx, host)
	if err != nil {
		return AddrPortRange{}, err
	}
	if len(addrs) == 0 {
		return AddrPortRange{}, fmt.Errorf("no addresses found for %s", host)
	}

	value = AddrPortRange{Addr: addrs[0], Ports: ports}
	entry.mu.Lock()
	entry.updated = time.Now()
	entry.value = value
	entry.mu.Unlock()
	return value, nil
}

func (r *EndpointResolver) Get(endpoint string) (AddrPortRange, error) {
	if addr, err := netip.ParseAddrPort(endpoint); err == nil {
		return AddrPortRange{Addr: addr.Addr(), Ports: PortRange{First: addr.Port(), Last: addr.Port()}}, nil
	}

	r.mu.RLock()
	entry := r.cache[endpoint]
	r.mu.RUnlock()
	if entry == nil {
		return AddrPortRange{}, fmt.Errorf("endpoint not resolved")
	}

	entry.mu.RLock()
	defer entry.mu.RUnlock()
	if entry.value.Addr.IsValid() {
		return entry.value, nil
	}
	return AddrPortRange{}, fmt.Errorf("endpoint not resolved")
}

// Expire makes the next Resolve refresh an endpoint while preserving the last
// usable value until that refresh succeeds.
func (r *EndpointResolver) Expire(endpoint string) {
	r.mu.RLock()
	entry := r.cache[endpoint]
	r.mu.RUnlock()
	if entry == nil {
		return
	}
	entry.mu.Lock()
	entry.updated = time.Time{}
	entry.mu.Unlock()
}

// Retain removes cached resolutions for addresses no longer present in runtime
// state. In-flight resolutions may finish using a removed entry, but it will no
// longer be reachable from the central cache.
func (r *EndpointResolver) Retain(addresses map[string]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for address := range r.cache {
		if _, ok := addresses[address]; !ok {
			delete(r.cache, address)
		}
	}
}

func (r *EndpointResolver) entry(endpoint string) *endpointResolution {
	r.mu.RLock()
	entry := r.cache[endpoint]
	r.mu.RUnlock()
	if entry != nil {
		return entry
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if entry = r.cache[endpoint]; entry == nil {
		entry = new(endpointResolution)
		r.cache[endpoint] = entry
	}
	return entry
}

// parseEndpoint splits an endpoint address into host and port range.
// Accepted forms: "host", "ip", "host:port", "ip:port", "host:portA-portB",
// "[v6]:portA-portB". A missing port yields the default port. Port ranges
// (portA-portB, inclusive) are part of the port-hopping feature.
func parseEndpoint(value string) (host string, ports PortRange, err error) {
	if value == "" {
		return "", PortRange{}, fmt.Errorf("endpoint is empty")
	}
	if strings.Contains(value, "://") {
		return "", PortRange{}, fmt.Errorf("invalid endpoint %q", value)
	}
	if addr, err := netip.ParseAddrPort(value); err == nil {
		return addr.Addr().String(), PortRange{First: addr.Port(), Last: addr.Port()}, nil
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.String(), PortRange{First: DefaultPort, Last: DefaultPort}, nil
	}

	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		if strings.Contains(value, ":") {
			return "", PortRange{}, fmt.Errorf("invalid endpoint %q: %w", value, err)
		}
		return value, PortRange{First: DefaultPort, Last: DefaultPort}, nil
	}
	ports, err = conn.ParsePortRange(portString)
	if err != nil {
		return "", PortRange{}, fmt.Errorf("invalid endpoint %q: %w", value, err)
	}
	return host, ports, nil
}
