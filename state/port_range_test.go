package state

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEndpointPortRanges(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		host    string
		lo, hi  uint16
		wantErr bool
	}{
		{name: "host port", in: "example.com:57175", host: "example.com", lo: 57175, hi: 57175},
		{name: "ipv4 port", in: "192.0.2.1:57175", host: "192.0.2.1", lo: 57175, hi: 57175},
		{name: "ipv4 range", in: "192.0.2.1:30000-40000", host: "192.0.2.1", lo: 30000, hi: 40000},
		{name: "ipv6 range", in: "[2001:db8::1]:30000-40000", host: "2001:db8::1", lo: 30000, hi: 40000},
		{name: "host range", in: "example.com:1-65535", host: "example.com", lo: 1, hi: 65535},
		{name: "single port range", in: "example.com:443-443", host: "example.com", lo: 443, hi: 443},
		{name: "bare host gets default port", in: "example.com", host: "example.com", lo: DefaultPort, hi: DefaultPort},
		{name: "bare ipv6 gets default port", in: "2001:db8::1", host: "2001:db8::1", lo: DefaultPort, hi: DefaultPort},
		{name: "reversed range rejected", in: "example.com:40000-30000", wantErr: true},
		{name: "zero port rejected", in: "example.com:0", wantErr: true},
		{name: "zero range rejected", in: "example.com:0-100", wantErr: true},
		{name: "port overflow rejected", in: "example.com:70000", wantErr: true},
		{name: "range overflow rejected", in: "example.com:30000-70000", wantErr: true},
		{name: "garbage rejected", in: "example.com:abc-def", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, ports, err := parseEndpoint(tc.in)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.lo, ports.First)
			assert.Equal(t, tc.hi, ports.Last)
		})
	}
}

func TestEndpointResolverResolvesRanges(t *testing.T) {
	dns := &countingDNSResolver{}
	resolver := newEndpointResolver(dns)

	got, err := resolver.Resolve("router.example.com:30000-40000", time.Hour)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), got.Addr)
	assert.Equal(t, uint16(30000), got.Ports.First)
	assert.Equal(t, uint16(40000), got.Ports.Last)
	assert.True(t, got.Contains(netip.MustParseAddrPort("192.0.2.1:35713")))
	assert.False(t, got.Contains(netip.MustParseAddrPort("192.0.2.1:40001")))
	assert.False(t, got.Contains(netip.MustParseAddrPort("192.0.2.2:35713")))
	assert.Equal(t, "192.0.2.1:30000-40000", got.String())

	// cached round trip
	got2, err := resolver.Get("router.example.com:30000-40000")
	require.NoError(t, err)
	assert.Equal(t, got, got2)

	// literal range endpoint does not touch DNS at all
	lit, err := resolver.Resolve("198.51.100.7:1-10", time.Hour)
	require.NoError(t, err)
	assert.Equal(t, "198.51.100.7:1-10", lit.String())
	assert.Equal(t, 1, dns.NameCalls())
}

func TestAddrPortRangeStringIPv6(t *testing.T) {
	a := AddrPortRange{Addr: netip.MustParseAddr("2001:db8::1"), Ports: PortRange{First: 30000, Last: 40000}}
	assert.Equal(t, "[2001:db8::1]:30000-40000", a.String())
	single := AddrPortRange{Addr: netip.MustParseAddr("2001:db8::1"), Ports: PortRange{First: 57175, Last: 57175}}
	assert.Equal(t, "[2001:db8::1]:57175", single.String())
}

// srvDNSResolver records SRV lookups.
type srvDNSResolver struct {
	countingDNSResolver
	srvCalls int
}

func (r *srvDNSResolver) ResolveSRV(_ context.Context, _, _, _ string) (string, uint16, error) {
	r.srvCalls++
	return "", 0, errors.New("no SRV record")
}

func TestEndpointResolverSkipsSRVForRanges(t *testing.T) {
	dns := &srvDNSResolver{}
	resolver := newEndpointResolver(dns)

	_, err := resolver.Resolve("router.example.com:30000-40000", time.Hour)
	require.NoError(t, err)
	assert.Zero(t, dns.srvCalls, "SRV must not be consulted for range endpoints")

	_, err = resolver.Resolve("router.example.com:57175", time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, dns.srvCalls, "single-port endpoints still consult SRV")
}
