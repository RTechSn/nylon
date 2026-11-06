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

// TestPortPoolRecycle pins the auto_recycle primitive: Recycle releases every
// quarantined port and empties the recent ring (a clean-slate restart when
// the pool has run dry), reporting how many ports it freed. Groups are
// untouched, so the next Select draws immediately.
func TestPortPoolRecycle(t *testing.T) {
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", 30000, 30003)},
		PortPoolConfig{Recent: 8, Cooldown: time.Hour, Samples: 4})

	retired := []netip.AddrPort{}
	for i := 0; i < 4; i++ {
		ap, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		pool.Retire(ap)
		retired = append(retired, ap)
	}
	if _, err := pool.Select(nil); err != ErrPoolExhausted {
		t.Fatalf("expected ErrPoolExhausted with all ports quarantined, got %v", err)
	}

	if cleared := pool.Recycle(); cleared != 4 {
		t.Fatalf("Recycle reported %d cleared ports, want 4", cleared)
	}
	for _, ap := range retired {
		if pool.IsCooling(ap) {
			t.Fatalf("port %v must not be cooling after Recycle", ap)
		}
	}
	if _, err := pool.Select(nil); err != nil {
		t.Fatalf("Select after Recycle: %v", err)
	}
	// a second Recycle on an empty quarantine is a no-op reporting zero
	if cleared := pool.Recycle(); cleared != 0 {
		t.Fatalf("Recycle on an empty quarantine reported %d, want 0", cleared)
	}
}

// TestPortPoolSetCooldown pins the live re-tune of the quarantine duration
// (a config change of port_hopping.cooldown_seconds applies without a
// restart).
func TestPortPoolSetCooldown(t *testing.T) {
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", 30000, 30000)},
		PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 4})

	ap, err := pool.Select(nil)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	pool.Retire(ap)
	if !pool.IsCooling(ap) {
		t.Fatal("control: the port must be cooling before SetCooldown")
	}

	// shorten the quarantine: the entry clamps to now+10s, so it must lift
	// within the new window (a lengthening never extends existing entries)
	pool.SetCooldown(10 * time.Second)
	base := time.Now()
	pool.nowFn = func() time.Time { return base }
	if !pool.IsCooling(ap) {
		t.Fatal("the port must still be cooling right after the clamp")
	}
	pool.nowFn = func() time.Time { return base.Add(11 * time.Second) }
	if pool.IsCooling(ap) {
		t.Fatal("the port must not be cooling after the shortened cooldown elapsed")
	}
}

// TestPortPoolSweepExhaustsExactly pins the exactness of Select's exhaustion:
// a sweep over a range (production defaults: Recent=512, Samples=32, cooldown
// long enough that nothing expires mid-sweep) must draw EVERY port of the
// range exactly once — retiring the carrying endpoint before each draw, as
// the send path does — and only then report ErrPoolExhausted. Random sampling
// alone gave up while a handful of ports remained eligible (field report:
// sweeps over a 501-port range ended 1-13 ports early, so every auto_recycle
// clean-slate restart fired prematurely and the recycle journal filled with
// back-to-back clears while good ports were still available); the
// deterministic scan backstop must close that gap completely.
func TestPortPoolSweepExhaustsExactly(t *testing.T) {
	const first, last = 30000, 30500
	const size = int(last - first + 1)
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", first, last)},
		PortPoolConfig{Recent: 512, Cooldown: time.Hour, Samples: 32})
	frozen := time.Now()
	pool.nowFn = func() time.Time { return frozen }

	for sweep := 0; sweep < 5; sweep++ {
		drawn := make(map[netip.AddrPort]struct{}, size)
		var carrier netip.AddrPort
		for {
			// production order: a rotation retires the carrying endpoint
			// first, then draws with it as the active window to avoid
			// (NextHopEndpoint); the bootstrap draw has nothing to retire
			avoid := []netip.AddrPort{}
			if carrier.IsValid() {
				pool.Retire(carrier)
				avoid = append(avoid, carrier)
			}
			ap, err := pool.Select(avoid)
			if err != nil {
				break
			}
			if _, dup := drawn[ap]; dup {
				t.Fatalf("sweep %d: drew %v twice before exhausting the range", sweep+1, ap)
			}
			drawn[ap] = struct{}{}
			carrier = ap
		}
		if len(drawn) != size {
			t.Fatalf("sweep %d: drew %d of %d ports before reporting exhaustion", sweep+1, len(drawn), size)
		}
		if _, _, cooling, _ := pool.Stats(); cooling != size {
			t.Fatalf("sweep %d: %d ports cooling at exhaustion, want %d", sweep+1, cooling, size)
		}
		if cleared := pool.Recycle(); cleared != size {
			t.Fatalf("sweep %d: recycle released %d ports, want %d", sweep+1, cleared, size)
		}
	}
}

// TestPortPoolSelectFindsLastEligiblePort pins the deterministic backstop
// directly: with every port of the range retired into cooldown except one,
// Select must return that port — not report exhaustion. Under the random
// sampling alone each call missed the survivor with probability
// (1-1/501)^288 ≈ 56%, which is exactly how near-exhaustion sweeps ended
// early. The survivor must also be returned when it is a member of the
// active window (avoid): a rotation onto the carrying port is only forced
// when it is the sole port left anywhere.
func TestPortPoolSelectFindsLastEligiblePort(t *testing.T) {
	const first, last = 30000, 30500
	pool := NewPortPool([]PortGroup{testGroup("10.0.0.1", first, last)},
		PortPoolConfig{Recent: 512, Cooldown: time.Hour, Samples: 32})
	frozen := time.Now()
	pool.nowFn = func() time.Time { return frozen }

	addr := netip.MustParseAddr("10.0.0.1")
	survivor := netip.MustParseAddrPort("10.0.0.1:30437")
	for p := int(first); p <= int(last); p++ {
		if ap := netip.AddrPortFrom(addr, uint16(p)); ap != survivor {
			pool.Retire(ap)
		}
	}

	for range 16 {
		ap, err := pool.Select(nil)
		if err != nil {
			t.Fatalf("Select must find the sole eligible port, got %v", err)
		}
		if ap != survivor {
			t.Fatalf("Select returned %v, want the sole eligible port %v", ap, survivor)
		}
		// the survivor is now in the recent ring as well: the ring must not
		// mask it either, including when it is the active window to avoid
		ap, err = pool.Select([]netip.AddrPort{survivor})
		if err != nil {
			t.Fatalf("Select with the survivor as the active window: %v", err)
		}
		if ap != survivor {
			t.Fatalf("Select returned %v with the survivor avoided, want %v (sole port left)", ap, survivor)
		}
	}
}

// TestPortPoolSelectFromRestrictsToGroups pins the strategy-restricted draw:
// SelectFrom draws only from the GIVEN group subset (one obf strategy's
// resolved groups), never from the pool's wider group set.
func TestPortPoolSelectFromRestrictsToGroups(t *testing.T) {
	stratA := []PortGroup{testGroup("10.0.0.1", 40000, 40009)}
	stratB := []PortGroup{testGroup("10.0.1.1", 50000, 50009)}
	pool := NewPortPool(append(append([]PortGroup{}, stratA...), stratB...),
		PortPoolConfig{Recent: 8, Cooldown: time.Minute, Samples: 16})

	for i := 0; i < 100; i++ {
		ap, err := pool.SelectFrom(stratA, nil)
		if err != nil {
			t.Fatalf("SelectFrom: %v", err)
		}
		if ap.Addr() != netip.MustParseAddr("10.0.0.1") || ap.Port() < 40000 || ap.Port() > 40009 {
			t.Fatalf("draw %d outside strategy A's groups: %v", i, ap)
		}
	}
}

// TestPortPoolSelectFromExhaustionIsSubsetScoped pins that exhaustion is
// scoped to the GIVEN groups: a strategy whose ports are all cooling fails
// the draw while other strategies' ports stay selectable — and the shared
// cooldown retires a port for every strategy that reaches it.
func TestPortPoolSelectFromExhaustionIsSubsetScoped(t *testing.T) {
	stratA := []PortGroup{testGroup("10.0.0.1", 40000, 40000)} // sole port
	stratB := []PortGroup{testGroup("10.0.1.1", 50000, 50009)}
	pool := NewPortPool(append(append([]PortGroup{}, stratA...), stratB...),
		PortPoolConfig{Recent: 1, Cooldown: time.Hour, Samples: 4})

	// burn strategy A's sole port: drawn, then retired (the exhaustion path —
	// NextHopEndpoint retires the exhausted endpoint), so it cools down
	if ap, err := pool.SelectFrom(stratA, nil); err != nil {
		t.Fatalf("first SelectFrom: %v", err)
	} else {
		pool.Retire(ap)
	}
	if _, err := pool.SelectFrom(stratA, nil); err == nil {
		t.Fatalf("exhausted strategy A must fail its own draws")
	}
	// ...while strategy B still serves, from the SAME pool
	if _, err := pool.SelectFrom(stratB, nil); err != nil {
		t.Fatalf("strategy B must stay selectable: %v", err)
	}

	// the shared cooldown: strategy B cannot reach A's burned port either
	burned := netip.MustParseAddrPort("10.0.0.1:40000")
	if !pool.IsCooling(burned) {
		t.Fatalf("the burned port must be cooling pool-wide")
	}
	poolBwithA := append([]PortGroup{}, stratB...)
	poolBwithA = append(poolBwithA, stratA...)
	if ap, err := pool.SelectFrom(poolBwithA, nil); err != nil {
		t.Fatalf("combined draw must fall back to B's ports: %v", err)
	} else if ap == burned {
		t.Fatalf("combined draw must not select the cooling port")
	}
}
