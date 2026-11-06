package state

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"
)

// ErrPoolExhausted is returned when every port of every group is currently
// unavailable (recently used or cooling down after retirement).
var ErrPoolExhausted = errors.New("port pool exhausted: all candidate ports are cooling down")

// PortGroup is one reachable address with the inclusive range of UDP ports it
// accepts traffic on.
type PortGroup struct {
	Addr  netip.Addr
	Ports PortRange
}

// PortPool draws carrying endpoints for port hopping. It keeps:
//   - an exclusion ring of recently selected endpoints (short-term),
//   - a cooldown map of retired endpoints (quarantine after a port has been
//     burned through its packet budget),
//
// and selects new candidates to be maximally DISSIMILAR to the endpoints it
// is told to avoid (the currently active window). The preference order is:
// different IP subnet > different IP in the same subnet > same IP, different
// port. Ties are broken randomly so port usage stays unpredictable.
//
// All methods are safe for concurrent use.
type PortPool struct {
	mu       sync.Mutex
	groups   []PortGroup
	recent   []netip.AddrPort // ring, oldest first
	recSet   map[netip.AddrPort]struct{}
	cooldown map[netip.AddrPort]time.Time
	nextExp  time.Time // earliest cooldown expiry seen
	retired  uint64
	cfg      PortPoolConfig
	nowFn    func() time.Time
}

// PortPoolConfig tunes the selection policy.
type PortPoolConfig struct {
	// Recent is the size of the exclusion ring (endpoints never re-selected
	// while still in the ring).
	Recent int
	// Cooldown quarantines a retired endpoint (budget exhausted / banned)
	// for this long before it may be selected again.
	Cooldown time.Duration
	// Samples is how many candidates are drawn per selection to score for
	// diversity. Every group receives a proportional share of the samples,
	// so multi-IP configs always consider every IP.
	Samples int
}

// NewPortPool creates a pool over the given groups.
func NewPortPool(groups []PortGroup, cfg PortPoolConfig) *PortPool {
	if cfg.Recent <= 0 {
		cfg.Recent = 1
	}
	if cfg.Samples <= 0 {
		cfg.Samples = 1
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = time.Second
	}
	return &PortPool{
		groups:   append([]PortGroup(nil), groups...),
		recent:   make([]netip.AddrPort, 0, cfg.Recent),
		recSet:   make(map[netip.AddrPort]struct{}),
		cooldown: make(map[netip.AddrPort]time.Time),
		cfg:      cfg,
		nowFn:    time.Now,
	}
}

// SetGroups replaces the group set (e.g. after a DNS refresh). Groups that
// no longer exist keep their cooldown entries; they are simply never drawn.
func (p *PortPool) SetGroups(groups []PortGroup) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.groups = append([]PortGroup(nil), groups...)
}

// Groups returns a copy of the current groups.
func (p *PortPool) Groups() []PortGroup {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]PortGroup(nil), p.groups...)
}

// Retire quarantines an endpoint whose packet budget was exhausted (or which
// was otherwise given up on), so it will not be selected again until the
// cooldown elapses.
func (p *PortPool) Retire(ap netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retired++
	exp := p.nowFn().Add(p.cfg.Cooldown)
	p.cooldown[ap] = exp
	if p.nextExp.IsZero() || exp.Before(p.nextExp) {
		p.nextExp = exp
	}
}

// IsCooling reports whether the endpoint is still quarantined: retired and
// inside its cooldown window. It answers "would Select refuse this endpoint
// right now", which the port factory uses to detect ports that were retired
// after being drawn but before their link was materialised.
func (p *PortPool) IsCooling(ap netip.AddrPort) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneExpiredLocked(p.nowFn())
	_, cooling := p.cooldown[ap]
	return cooling
}

// Stats reports the number of groups, endpoints in the recent ring, endpoints
// cooling down, and total retirements (for observability).
func (p *PortPool) Stats() (groups, recent, cooling, retired int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.groups), len(p.recent), len(p.cooldown), int(p.retired)
}

// subnetPrefix returns the prefix that two addresses must share to be
// considered "the same subnet" for diversity purposes: /24 for IPv4 and
// /64 for IPv6 (4-in-6 addresses are treated as IPv4). The prefix is masked
// so two different addresses inside the same subnet compare equal.
func subnetPrefix(a netip.Addr) netip.Prefix {
	if a.Is4() || a.Is4In6() {
		return netip.PrefixFrom(netip.AddrFrom4(a.As4()), 24).Masked()
	}
	return netip.PrefixFrom(a, 64).Masked()
}

// diversityDistance scores how dissimilar candidate is from ref:
//
//	3: different IP subnet
//	2: different IP, same subnet
//	1: same IP (different port)
func diversityDistance(candidate, ref netip.AddrPort) int {
	if candidate.Addr() != ref.Addr() {
		if subnetPrefix(candidate.Addr()) != subnetPrefix(ref.Addr()) {
			return 3
		}
		return 2
	}
	return 1
}

// pruneExpiredLocked drops cooldown entries whose quarantine has elapsed.
func (p *PortPool) pruneExpiredLocked(now time.Time) {
	if p.nextExp.IsZero() || now.Before(p.nextExp) || len(p.cooldown) == 0 {
		return
	}
	next := time.Time{}
	for ap, exp := range p.cooldown {
		if !exp.After(now) {
			delete(p.cooldown, ap)
			continue
		}
		if next.IsZero() || exp.Before(next) {
			next = exp
		}
	}
	p.nextExp = next
}

// drawFromGroupLocked draws one random endpoint from a single group,
// skipping endpoints in the recent ring or cooldown.
func (p *PortPool) drawFromGroupLocked(g PortGroup, ignoreRecent bool) (netip.AddrPort, bool) {
	n := g.Ports.Size()
	if n <= 0 {
		return netip.AddrPort{}, false
	}
	ap := netip.AddrPortFrom(g.Addr, g.Ports.First+uint16(rand.IntN(n)))
	if _, cool := p.cooldown[ap]; cool {
		return netip.AddrPort{}, false
	}
	if !ignoreRecent {
		if _, rec := p.recSet[ap]; rec {
			return netip.AddrPort{}, false
		}
	}
	return ap, true
}

// Select draws the next carrying endpoint from the pool's full group set,
// preferring candidates maximally dissimilar from `avoid` (the currently
// active window members). See selectFromLocked for the selection contract.
func (p *PortPool) Select(avoid []netip.AddrPort) (netip.AddrPort, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.selectFromLocked(p.groups, avoid)
}

// SelectFrom draws the next carrying endpoint from the GIVEN group subset
// (the obf strategy selection: the factory restricts each draw to the chosen
// strategy's resolved groups), with the same selection semantics as Select.
// The pool's recent-ring and cooldown bookkeeping stays shared: a port
// retired through one strategy's draw is quarantined for every strategy that
// reaches it (strategies may carry overlapping ranges).
func (p *PortPool) SelectFrom(groups []PortGroup, avoid []netip.AddrPort) (netip.AddrPort, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.selectFromLocked(groups, avoid)
}

// selectFromLocked draws the next carrying endpoint over the given groups,
// preferring candidates maximally dissimilar from `avoid` (the currently
// active window members). It returns ErrPoolExhausted when nothing is
// selectable — over the GIVEN groups only.
//
// Selection is random-sampled for diversity, but exhaustion is EXACT: when
// the sampling finds nothing, the ranges are walked deterministically before
// ErrPoolExhausted is reported. A bounded random sampler alone cannot prove
// the pool empty — near the end of a sweep, when only a handful of ports
// remain eligible, every attempt can miss them and the miss reads as
// exhaustion (field report: sweeps over a 501-port range ended 1-13 ports
// early, and with auto_recycle every premature miss fired a clean-slate
// restart, so the recycle journal showed back-to-back clears while good
// ports were still available).
func (p *PortPool) selectFromLocked(groups []PortGroup, avoid []netip.AddrPort) (netip.AddrPort, error) {
	now := p.nowFn()
	p.pruneExpiredLocked(now)
	if len(groups) == 0 {
		return netip.AddrPort{}, ErrPoolExhausted
	}

	// Sample candidates for diversity scoring. Each group receives a
	// proportional share of the sample budget so every IP is considered.
	type cand struct {
		ap    netip.AddrPort
		score int
	}
	var cands []cand
	seen := make(map[netip.AddrPort]struct{})
	avoidSet := make(map[netip.AddrPort]struct{}, len(avoid))
	for _, a := range avoid {
		avoidSet[a] = struct{}{}
	}

	totalPorts := 0
	for _, g := range groups {
		totalPorts += g.Ports.Size()
	}
	if totalPorts == 0 {
		return netip.AddrPort{}, ErrPoolExhausted
	}

	scoreOf := func(ap netip.AddrPort) int {
		score := 1 << 30 // +inf: wins when there is nothing to avoid
		for _, a := range avoid {
			if d := diversityDistance(ap, a); d < score {
				score = d
			}
		}
		return score
	}

	remaining := p.cfg.Samples
	shares := make([]int, len(groups))
	for gi, g := range groups {
		share := p.cfg.Samples * g.Ports.Size() / totalPorts
		if share > remaining {
			share = remaining
		}
		shares[gi] = share
		remaining -= share
	}
	for remaining > 0 {
		shares[rand.IntN(len(shares))]++
		remaining--
	}

	for gi, g := range groups {
		for i := 0; i < shares[gi]; i++ {
			// a few attempts per sample to step over ring/cooldown collisions
			for attempt := 0; attempt < 8; attempt++ {
				ap, ok := p.drawFromGroupLocked(g, false)
				if !ok {
					continue
				}
				if _, dup := seen[ap]; dup {
					continue
				}
				seen[ap] = struct{}{}
				cands = append(cands, cand{ap: ap, score: scoreOf(ap)})
				break
			}
		}
	}

	// Fallback: the recent ring covers the whole group space; retry ignoring
	// it (cooldown still applies). Members of the active window are skipped
	// here: rotating the carrying port onto itself would silently reset its
	// budget and defeat the hop while any alternative port exists (the
	// deterministic scan below keeps the sole-port case working).
	if len(cands) == 0 {
		for i := 0; i < 32 && len(cands) < 4; i++ {
			ap, ok := p.drawFromGroupLocked(groups[rand.IntN(len(groups))], true)
			if !ok {
				continue
			}
			if _, dup := seen[ap]; dup {
				continue
			}
			if _, active := avoidSet[ap]; active {
				continue
			}
			seen[ap] = struct{}{}
			cands = append(cands, cand{ap: ap, score: scoreOf(ap)})
		}
	}
	// Last resort: the random sampling found nothing. Walk the ranges
	// deterministically so exhaustion is exact — ErrPoolExhausted must mean
	// that every port of the GIVEN groups is cooling down, nothing weaker.
	if len(cands) == 0 {
		if ap, ok := p.scanEligibleLocked(groups, avoidSet); ok {
			cands = append(cands, cand{ap: ap, score: scoreOf(ap)})
		}
	}
	if len(cands) == 0 {
		return netip.AddrPort{}, ErrPoolExhausted
	}

	// pick the best score; break ties randomly
	best := cands[0].score
	for _, c := range cands[1:] {
		if c.score > best {
			best = c.score
		}
	}
	var winners []netip.AddrPort
	for _, c := range cands {
		if c.score == best {
			winners = append(winners, c.ap)
		}
	}
	chosen := winners[rand.IntN(len(winners))]

	// record in the recent ring
	if len(p.recent) >= p.cfg.Recent {
		oldest := p.recent[0]
		p.recent = p.recent[1:]
		delete(p.recSet, oldest)
	}
	p.recent = append(p.recent, chosen)
	p.recSet[chosen] = struct{}{}
	return chosen, nil
}

// scanEligibleLocked deterministically walks every port of the GIVEN groups
// and returns the first eligible endpoint, in three passes of decreasing
// strictness: (1) not cooling, outside the recent ring and outside the active
// window; (2) recent ring relaxed; (3) active window relaxed — a rotation
// onto the current carrying port is only ever forced when it is the sole
// port left anywhere. Each group is entered at a random offset so the walk
// carries no positional bias. This is Select's exactness backstop: it is
// reached only when the random sampling found nothing, which near the end of
// a sweep happens while a handful of eligible ports remain.
func (p *PortPool) scanEligibleLocked(groups []PortGroup, avoidSet map[netip.AddrPort]struct{}) (netip.AddrPort, bool) {
	for pass := 0; pass < 3; pass++ {
		for _, g := range groups {
			n := g.Ports.Size()
			if n <= 0 {
				continue
			}
			start := rand.IntN(n)
			for i := 0; i < n; i++ {
				ap := netip.AddrPortFrom(g.Addr, g.Ports.First+uint16((start+i)%n))
				if _, cool := p.cooldown[ap]; cool {
					continue
				}
				if pass < 2 {
					if _, active := avoidSet[ap]; active {
						continue
					}
				}
				if pass == 0 {
					if _, rec := p.recSet[ap]; rec {
						continue
					}
				}
				return ap, true
			}
		}
	}
	return netip.AddrPort{}, false
}

// SetCooldown adjusts the retirement quarantine duration — a live config
// change of port_hopping.cooldown_seconds applies without a restart. A
// shortened window clamps already-quarantined ports so everything lifts
// within the new duration; a lengthened window never extends entries that
// were retired under the old policy.
func (p *PortPool) SetCooldown(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d <= 0 {
		return
	}
	old := p.cfg.Cooldown
	p.cfg.Cooldown = d
	if d >= old || len(p.cooldown) == 0 {
		return
	}
	now := p.nowFn()
	next := time.Time{}
	for ap, exp := range p.cooldown {
		if ne := now.Add(d); ne.Before(exp) {
			exp = ne
			p.cooldown[ap] = exp
		}
		if next.IsZero() || exp.Before(next) {
			next = exp
		}
	}
	p.nextExp = next
}

// Recycle empties the retirement quarantine and the recent-selection ring —
// a clean-slate restart for the auto_recycle policy: once every port is
// cooling down and the pool would stall, the operator opted into releasing
// all retired ports and starting a fresh sweep. Groups are untouched. It
// returns how many quarantined ports were released (for the journal line).
func (p *PortPool) Recycle() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	cleared := len(p.cooldown)
	p.cooldown = make(map[netip.AddrPort]time.Time)
	p.nextExp = time.Time{}
	p.recent = p.recent[:0]
	p.recSet = make(map[netip.AddrPort]struct{})
	return cleared
}
