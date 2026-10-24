package state

import (
	"net/netip"
	"testing"
	"time"
)

func testGroup(addr string, first, last uint16) PortGroup {
	return PortGroup{
		Addr:  netip.MustParseAddr(addr),
		Ports: PortRange{First: first, Last: last},
	}
}

func TestPortPoolDrawsFromAllGroups(t *testing.T) {
	pool := NewPortPool([]PortGroup{
		testGroup("10.0.0.1", 30000, 30009),
		testGroup("10.0.1.1", 30000, 30009),
	}, PortPoolConfig{Recent: 8, Cooldown: time.Minute, Samples: 16})

	seen := make(map[netip.Addr]int)
	for i := 0; i < 200; i++ {
		ap, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		seen[ap.Addr()]++
	}
	if len(seen) != 2 {
		t.Fatalf("expected draws from both groups, saw %d distinct addrs", len(seen))
	}
	for addr, n := range seen {
		if n < 10 {
			t.Errorf("group %s drew only %d/200 times; distribution too skewed", addr, n)
		}
	}
}

func TestPortPoolDrawsWithinRange(t *testing.T) {
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", 30000, 30099)},
		PortPoolConfig{Recent: 1, Cooldown: time.Minute, Samples: 4})
	for i := 0; i < 100; i++ {
		ap, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if ap.Port() < 30000 || ap.Port() > 30099 {
			t.Fatalf("drew port %d outside the range", ap.Port())
		}
	}
}

func TestPortPoolCooldownQuarantine(t *testing.T) {
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", 30000, 30000)},
		PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 4})

	ap, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	// the single port is now in the recent ring; the fallback must ignore the
	// ring but the cooldown still applies — so the pool is exhausted
	pool.Retire(ap)
	if _, err := pool.Select(nil); err != ErrPoolExhausted {
		t.Fatalf("expected ErrPoolExhausted during cooldown, got %v", err)
	}

	// after the cooldown elapses the port becomes selectable again
	base := time.Now()
	pool.nowFn = func() time.Time { return base.Add(2 * time.Hour) }
	if _, err := pool.Select(nil); err != nil {
		t.Fatalf("Select after cooldown: %v", err)
	}
}

// TestPortPoolIsCooling pins the quarantine query the port factory relies on
// to detect ports retired between their draw and their link materialisation.
func TestPortPoolIsCooling(t *testing.T) {
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", 30000, 30009)},
		PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 4})

	ap, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if pool.IsCooling(ap) {
		t.Fatal("a freshly drawn port must not be cooling")
	}
	other := netip.MustParseAddrPort("10.0.0.1:30009")
	if pool.IsCooling(other) {
		t.Fatal("a never-retired port must not be cooling")
	}

	pool.Retire(ap)
	if !pool.IsCooling(ap) {
		t.Fatal("a retired port must report cooling inside its cooldown window")
	}

	// past the cooldown the quarantine lifts (lazily pruned, like Select)
	base := time.Now()
	pool.nowFn = func() time.Time { return base.Add(2 * time.Hour) }
	if pool.IsCooling(ap) {
		t.Fatal("a port past its cooldown must no longer report cooling")
	}
}

func TestPortPoolRecentRingAvoidsRepeats(t *testing.T) {
	// one group, small range, ring covering half of it
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", 30000, 30007)},
		PortPoolConfig{Recent: 4, Cooldown: time.Hour, Samples: 4})

	last, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	for i := 0; i < 50; i++ {
		ap, err := pool.Select([]netip.AddrPort{last})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if ap == last {
			t.Fatalf("drew the immediately avoided endpoint %v again", ap)
		}
		last = ap
	}
}

func TestPortPoolDiversityPrefersDifferentIP(t *testing.T) {
	// three groups: different subnet, same subnet, same IP
	pool := NewPortPool([]PortGroup{
		testGroup("10.0.0.1", 30000, 30099), // same IP as active
		testGroup("10.0.0.2", 30000, 30099), // same /24 subnet
		testGroup("10.9.9.9", 30000, 30099), // different subnet
	}, PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 64})

	active := netip.MustParseAddrPort("10.0.0.1:30123")
	diffSubnet, diffIP, sameIP := 0, 0, 0
	for i := 0; i < 300; i++ {
		ap, err := pool.Select([]netip.AddrPort{active})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		switch {
		case ap.Addr().String() == "10.9.9.9":
			diffSubnet++
		case ap.Addr().String() == "10.0.0.2":
			diffIP++
		case ap.Addr().String() == "10.0.0.1":
			sameIP++
		}
	}
	// the diversity scoring samples every group, so a different-subnet
	// candidate should dominate; a same-IP draw is possible only through tie
	// breakers and must be rare
	if diffSubnet < 250 {
		t.Errorf("different-subnet candidates won only %d/300 draws", diffSubnet)
	}
	if sameIP > 20 {
		t.Errorf("same-IP draws happened %d/300 times; diversity scoring is not working", sameIP)
	}
	_ = diffIP
}

func TestPortPoolDiversityPrefersDifferentSubnetOverSameSubnet(t *testing.T) {
	pool := NewPortPool([]PortGroup{
		testGroup("10.0.0.1", 30000, 30099), // same /24 as active
		testGroup("10.0.0.2", 30000, 30099),
		testGroup("10.1.0.1", 30000, 30099), // different subnet
	}, PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 64})

	active := netip.MustParseAddrPort("10.0.0.5:30123")
	otherSubnet, sameSubnet := 0, 0
	for i := 0; i < 200; i++ {
		ap, err := pool.Select([]netip.AddrPort{active})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if ap.Addr().String() == "10.1.0.1" {
			otherSubnet++
		} else {
			sameSubnet++
		}
	}
	if otherSubnet < 160 {
		t.Errorf("different-subnet candidate won only %d/200 draws", otherSubnet)
	}
	_ = sameSubnet
}

func TestPortPoolIPv6SubnetComparison(t *testing.T) {
	pool := NewPortPool([]PortGroup{
		testGroup("2001:db8:1::1", 30000, 30099),
		testGroup("2001:db8:2::1", 30000, 30099),
	}, PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 32})

	active := netip.MustParseAddrPort("[2001:db8:1::5]:30123")
	otherSubnet := 0
	for i := 0; i < 100; i++ {
		ap, err := pool.Select([]netip.AddrPort{active})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if ap.Addr().String() == "2001:db8:2::1" {
			otherSubnet++
		}
	}
	if otherSubnet < 70 {
		t.Errorf("different-subnet IPv6 candidate won only %d/100 draws", otherSubnet)
	}
}

func TestPortPoolStatsAndSetGroups(t *testing.T) {
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", 30000, 30009)},
		PortPoolConfig{Recent: 2, Cooldown: time.Hour, Samples: 4})

	if _, err := pool.Select(nil); err != nil {
		t.Fatalf("Select: %v", err)
	}
	ap, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	pool.Retire(ap)

	groups, recent, cooling, retired := pool.Stats()
	if groups != 1 || recent != 2 || cooling != 1 || retired != 1 {
		t.Errorf("Stats() = (%d groups, %d recent, %d cooling, %d retired), want (1, 2, 1, 1)",
			groups, recent, cooling, retired)
	}

	// swapping groups keeps cooldown state but draws only from the new group
	pool.SetGroups([]PortGroup{testGroup("10.9.9.9", 40000, 40009)})
	ap, err = pool.Select(nil)
	if err != nil {
		t.Fatalf("Select after SetGroups: %v", err)
	}
	if ap.Addr().String() != "10.9.9.9" {
		t.Errorf("drew %v from a removed group", ap)
	}
}

func TestPortPoolEmptyIsExhausted(t *testing.T) {
	pool := NewPortPool(nil, PortPoolConfig{Recent: 1, Cooldown: time.Second, Samples: 1})
	if _, err := pool.Select(nil); err != ErrPoolExhausted {
		t.Fatalf("expected ErrPoolExhausted for empty pool, got %v", err)
	}
}
