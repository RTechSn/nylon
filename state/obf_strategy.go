package state

import (
	"fmt"
	"slices"
	"strings"

	"github.com/encodeous/nylon/polyamide/device"
)

// The obf strategy model (config reform):
//
//      obf:                      # the global obf block — network-wide (upstream naming:
//        s1: 32                  #   central obf = whole-mesh params, node obf = per-node)
//        s2: 28
//        s3: 20
//        s4: 16
//        h1: {min: 100, max: 5000000}     # mesh-wide AWG 2.0 S/H handshake
//        h2: ...                          # dialect, uniform by construction
//        strategy:                 # the named strategy map
//          awg_main:
//            ports: "40000"      # required: one port or an inclusive range "40000-50000"
//            jc: 5                # sender-local junk: jc datagrams of size [jmin, jmax)
//            jmin: 250            #   ahead of every handshake initiation (per strategy)
//            jmax: 800
//            i1: ... i5: ...       # optional sender junk packets (see the note below)
//          hopping:
//            ports: "40000-50000"
//            port_hopping_mode: timed     # rotation policy lives IN the strategy
//            port_hopping:
//              period_seconds: 30
//          vanilla:
//            ports: "51820"
//
//      routers:
//        - id: hub
//          endpoints:
//            - hub.example.com[hopping,vanilla]   # per-endpoint strategy selection
//            - 203.0.113.7[awg_main]
//            - 198.51.100.9:51820                # raw fixed-port endpoint (no strategy)
//
// Ports therefore live in strategies; the listen half of a node binds the
// union of ports over the strategies its OWN advertised endpoints name
// (untagged / "[*]" = all strategies), and the connect half expands every
// tagged peer endpoint into one candidate set per named strategy.
//
// WIRE REALITY (documented, not negotiable by config): the AWG 2.0 device
// speaks exactly ONE handshake dialect (the S/H profile is mesh-wide,
// inline in the global obf block) but its junk EMISSION is per CONNECTION,
// not per device: the jc/jmin/jmax junk stream and the I-packets are
// properties of the obf strategy carrying the connection. The nylon core
// feeds them to the device through a per-peer in-process junk hook
// (device.JunkSource, the same pattern device.HopSource established for
// port hopping); the device's own UAPI knobs (jc/jmin/jmax, i1..i5) degrade
// to the FALLBACK for peers no strategy carries (raw host:port endpoints,
// the bootstrap window; see EffectiveStrategyJunk). Receivers discard junk
// unclassified, so two nodes (and two connections of one node) may draw
// their junk from different strategies without breaking interop.

// ObfStrategy is one named entry of the central `obf.strategy` map: a
// wire-reachability definition (ports) plus, optionally, the client-side
// rotation policy for those ports and the sender-local junk emission (the
// AWG J trio and the I-packets). The strategy NAME is its identity.
type ObfStrategy struct {
	// Ports is the strategy's port spec: a single port ("40000") or an
	// inclusive range ("40000-50000"). Required.
	Ports string `yaml:"ports"`

	// Client-side rotation policy for the strategy's ports (when the mode
	// governs rotation of the carrying endpoint drawn from this strategy).
	PortHoppingMode string          `yaml:"port_hopping_mode,omitempty"` // static (default) | reactive | proactive | timed
	PortHopping     *PortHoppingCfg `yaml:"port_hopping,omitempty"`

	// Sender-local junk datagrams (AWG Jc/Jmin/Jmax): `jc` datagrams of
	// sizes drawn from [jmin, jmax) go out ahead of every handshake
	// initiation this strategy carries (see StrategyJunkOf). `jc` requires
	// the size range (ValidateStrategyJunk); every i-spec must parse as an
	// obfuscation chain (device.ValidateObfSpec, wired into
	// ValidateObfStrategies).
	Jc   *uint32 `yaml:"jc,omitempty"`
	Jmin *uint32 `yaml:"jmin,omitempty"`
	Jmax *uint32 `yaml:"jmax,omitempty"`

	// Sender-local junk packets (AWG I1-I5), prepended to every handshake
	// initiation this strategy carries (StrategyJunkOf resolves the
	// per-strategy set, with the obf-level defaults inherited per slot).
	I1 string `yaml:"i1,omitempty"`
	I2 string `yaml:"i2,omitempty"`
	I3 string `yaml:"i3,omitempty"`
	I4 string `yaml:"i4,omitempty"`
	I5 string `yaml:"i5,omitempty"`
}

// iParams returns the strategy's I-packet specs in wire order.
func (s *ObfStrategy) iParams() [5]string {
	if s == nil {
		return [5]string{}
	}
	return [5]string{s.I1, s.I2, s.I3, s.I4, s.I5}
}

// ipParamsSet reports whether the strategy defines any I-packet.
func (s *ObfStrategy) iParamsSet() bool {
	for _, v := range s.iParams() {
		if v != "" {
			return true
		}
	}
	return false
}

// hopPolicySignature renders a strategy's rotation policy for change
// detection (journal + wire-up comparisons).
func (s *ObfStrategy) HopPolicySignature() string {
	p := s.PortHopping.Resolve()
	p.Mode = s.PortHoppingMode
	if p.Mode == "" {
		p.Mode = HopModeStatic
	}
	return fmt.Sprintf("%s|%d|%s|%d|%s|%s", p.Mode, p.Budget, p.Period, p.JitterPct, p.RecycleMinInterval, p.Cooldown)
}

// StrategyNames returns the strategy map's names in stable (sorted) order.
func StrategyNames(m map[string]*ObfStrategy) []string {
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// ParseStrategyPorts parses a strategy's ports spec into a PortRange.
func ParseStrategyPorts(s *ObfStrategy, name string) (PortRange, error) {
	if s == nil || strings.TrimSpace(s.Ports) == "" {
		return PortRange{}, fmt.Errorf("obf strategy %s: ports is required (a single port or an inclusive range, e.g. \"40000\" or \"40000-50000\")", name)
	}
	pr, err := ParsePortRange(strings.TrimSpace(s.Ports))
	if err != nil {
		return PortRange{}, fmt.Errorf("obf strategy %s: ports: %w", name, err)
	}
	return pr, nil
}

// ResolveStrategyHopPolicy resolves one strategy's rotation policy with the
// built-in defaults. The mode defaults to static.
func ResolveStrategyHopPolicy(s *ObfStrategy) PortHoppingPolicy {
	p := DefaultPortHoppingPolicy()
	if s == nil {
		return p
	}
	p = s.PortHopping.Resolve()
	p.Mode = s.PortHoppingMode
	if p.Mode == "" {
		p.Mode = HopModeStatic
	}
	return p
}

// StrategyPortRangeOf returns the parsed ports of a named strategy.
func StrategyPortRangeOf(m map[string]*ObfStrategy, name string) (PortRange, error) {
	s, ok := m[name]
	if !ok {
		return PortRange{}, fmt.Errorf("unknown obf strategy %q", name)
	}
	return ParseStrategyPorts(s, name)
}

// EndpointStrategyTags expands an endpoint's strategy tag list into concrete
// strategy names. An untagged endpoint (or the "*" wildcard) means "all
// strategies defined in the mesh" — the default is everything available, in
// sorted (map) order. Explicit tags expand in the operator's WRITTEN order:
// the tag list is the preference order, and the strategy selection modes
// read it (fixed uses the first, the random/trial draws follow it). A
// concrete tag that names no defined strategy is a config error.
func EndpointStrategyTags(spec EndpointSpec, m map[string]*ObfStrategy) ([]string, error) {
	all := StrategyNames(m)
	for _, tag := range spec.Strategies {
		if tag == "*" {
			return all, nil
		}
	}
	if len(spec.Strategies) == 0 {
		return all, nil
	}
	out := make([]string, 0, len(spec.Strategies))
	for _, tag := range spec.Strategies {
		if _, ok := m[tag]; !ok {
			return nil, fmt.Errorf("endpoint %s references undefined obf strategy %q (defined: %v)", spec.String(), tag, all)
		}
		out = append(out, tag)
	}
	return out, nil
}

// ListenUnionRanges derives a node's listen half from its advertised
// endpoints: the union of ports over every strategy the node's own endpoints
// name (untagged = all strategies), merged into a minimal set of disjoint
// inclusive ranges. The primary port (node.yaml port) is always bound by the
// device itself and is NOT part of this union.
//
// A node with no advertised endpoints serves no strategies (clients accept
// no inbound connections); an empty strategy map yields no ranges.
func ListenUnionRanges(router *RouterCfg, m map[string]*ObfStrategy) ([]PortRange, error) {
	var names []string
	seen := map[string]struct{}{}
	add := func(list []string) {
		for _, n := range list {
			if _, ok := seen[n]; !ok {
				seen[n] = struct{}{}
				names = append(names, n)
			}
		}
	}
	if router != nil {
		for _, addr := range router.Endpoints {
			spec, err := ParseEndpointSpec(addr)
			if err != nil {
				// unreachable via validation (CentralConfigValidator parses
				// every endpoint); a broken spec simply contributes nothing
				continue
			}
			// tagged and bare-host endpoints contribute (untagged = all
			// strategies); raw host:port endpoints never do
			if !spec.HasStrategies() && (spec.Ports.Valid() || len(m) == 0) {
				continue
			}
			tags, err := EndpointStrategyTags(spec, m)
			if err != nil {
				return nil, err
			}
			add(tags)
		}
	}
	var prs []PortRange
	for _, name := range names {
		pr, err := StrategyPortRangeOf(m, name)
		if err != nil {
			return nil, err
		}
		prs = append(prs, pr)
	}
	return MergePortRanges(prs...), nil
}

// MergePortRanges folds a list of inclusive port ranges into a minimal set
// of disjoint ranges (sorted, overlapping/adjacent ranges coalesced). Used
// both for the listen union and for rendering the device UAPI form.
func MergePortRanges(prs ...PortRange) []PortRange {
	var valid []PortRange
	for _, pr := range prs {
		if pr.Valid() {
			valid = append(valid, pr)
		}
	}
	if len(valid) == 0 {
		return nil
	}
	slices.SortFunc(valid, func(a, b PortRange) int {
		if a.First != b.First {
			return int(a.First) - int(b.First)
		}
		return int(a.Last) - int(b.Last)
	})
	out := []PortRange{valid[0]}
	for _, pr := range valid[1:] {
		last := &out[len(out)-1]
		if pr.First <= last.Last || pr.First == last.Last+1 {
			if pr.Last > last.Last {
				last.Last = pr.Last
			}
			continue
		}
		out = append(out, pr)
	}
	return out
}

// StrategyJunk is the resolved sender junk configuration of one connection
// (the connection the carrying obf strategy owns): `jc` junk datagrams of
// sizes drawn from [jmin, jmax) ahead of every handshake initiation, plus
// the I-packet set prepended to it. Zero values emit no junk of that kind.
type StrategyJunk struct {
	Jc   uint32
	Jmin uint32
	Jmax uint32
	I    [5]string
}

// set reports whether the junk configuration carries anything (a junk
// datagram trio or an i-packet).
func (j StrategyJunk) set() bool {
	if j.Jc > 0 {
		return true
	}
	for _, v := range j.I {
		if v != "" {
			return true
		}
	}
	return false
}

// StrategyJunkOf resolves ONE strategy's effective junk: its own trio and
// i-set with the obf-level defaults inherited per field (CentralObf.
// applyDefaults performs the fold; the fold is idempotent, so an
// already-resolved map — CentralCfg.ObfStrategies() — is accepted unchanged).
// This is the source of truth for connections the strategy carries (the
// per-peer junk hook serves it; see core's portFactory.JunkFor).
//
// ok is false when the strategy is absent from the map (or name is empty) —
// the caller falls back to the device knobs. A present strategy resolves to
// its spec EVEN WHEN ZERO: a junkless strategy must not leak the device
// fallback onto the connections it carries.
func StrategyJunkOf(m map[string]*ObfStrategy, obf *CentralObf, name string) (StrategyJunk, bool) {
	if name == "" {
		return StrategyJunk{}, false
	}
	s, ok := m[name]
	if !ok {
		return StrategyJunk{}, false
	}
	if obf != nil {
		s = obf.applyDefaults(s)
	}
	var out StrategyJunk
	if s.Jc != nil {
		out.Jc = *s.Jc
	}
	if s.Jmin != nil {
		out.Jmin = *s.Jmin
	}
	if s.Jmax != nil {
		out.Jmax = *s.Jmax
	}
	out.I = s.iParams()
	return out, true
}

// EffectiveStrategyJunk resolves the DEVICE FALLBACK junk — what the
// polyamide device's UAPI knobs (jc/jmin/jmax, i1..i5) are rendered to and
// what UAPI `get` reports. Per-strategy junk made the wire junk a property
// of the connection's carrying strategy (StrategyJunkOf, served through the
// per-peer junk hook), so the knobs only serve connections no strategy
// carries — raw host:port peers and the bootstrap window:
//
//   - the AGREED junk when every used strategy concurs (each of
//     jc/jmin/jmax identical across every used strategy that sets the knob
//     after the obf-default fold, and one shared i-set): exactly the
//     configurations that sealed before per-strategy junk, byte-identical
//     behaviour;
//   - else the obf-level DEFAULT junk (the neutral choice when strategies
//     disagree — it favours no strategy over another);
//   - else none.
//
// The returned source names the provider for the journal: the first
// contributing strategy, "defaults", or "" (no junk).
func EffectiveStrategyJunk(m map[string]*ObfStrategy, obf *CentralObf, used []string) (StrategyJunk, string) {
	var out StrategyJunk
	// the first setter of each J knob fixes the candidate agreed value; a
	// later disagreement abandons the agreement (the fallback takes over)
	var knobVal [3]uint32
	var knobSeen [3]bool
	var iSet [5]string
	var iSeen bool
	source := ""
	agree := true
	for _, name := range used {
		s, ok := m[name]
		if !ok {
			continue
		}
		if obf != nil {
			s = obf.applyDefaults(s)
		}
		contributes := s.iParamsSet() || s.Jc != nil || s.Jmin != nil || s.Jmax != nil
		if contributes && source == "" {
			source = name
		}
		for i, p := range [3]*uint32{s.Jc, s.Jmin, s.Jmax} {
			if p == nil {
				continue
			}
			if !knobSeen[i] {
				knobSeen[i], knobVal[i] = true, *p
				continue
			}
			if knobVal[i] != *p {
				agree = false
			}
		}
		if s.iParamsSet() {
			set := s.iParams()
			if !iSeen {
				iSet, iSeen = set, true
				continue
			}
			if set != iSet {
				agree = false
			}
		}
	}
	if agree {
		out.Jc, out.Jmin, out.Jmax = knobVal[0], knobVal[1], knobVal[2]
		out.I = iSet
		return out, source
	}
	// the strategies disagree: the obf-level default junk is the neutral
	// fallback (it favours no strategy over another)
	if obf != nil {
		var d StrategyJunk
		if obf.Jc != nil && *obf.Jc > 0 {
			d.Jc = *obf.Jc
			if obf.Jmin != nil {
				d.Jmin = *obf.Jmin
			}
			if obf.Jmax != nil {
				d.Jmax = *obf.Jmax
			}
		}
		d.I = [5]string{obf.I1, obf.I2, obf.I3, obf.I4, obf.I5}
		if d.set() {
			return d, "defaults"
		}
	}
	return StrategyJunk{}, ""
}

// ValidateStrategyJunk checks one strategy's sender-junk trio for internal
// consistency: the size range travels with the count — `jc` requires
// `jmin`/`jmax`, and a size range without a positive `jc` emits nothing, so
// it is rejected rather than carried as dead config.
func ValidateStrategyJunk(s *ObfStrategy, name string) error {
	if s == nil {
		return nil
	}
	jcSet := s.Jc != nil && *s.Jc > 0
	if jcSet && (s.Jmin == nil || s.Jmax == nil) {
		return fmt.Errorf("obf strategy %s: jc requires the jmin/jmax junk size range (datagram sizes are drawn from [jmin, jmax))", name)
	}
	if !jcSet && (s.Jmin != nil || s.Jmax != nil) {
		return fmt.Errorf("obf strategy %s: jmin/jmax are set but jc is not positive — no junk datagrams are emitted without a count; set jc, or drop the size range", name)
	}
	if s.Jmin != nil && s.Jmax != nil && *s.Jmin > *s.Jmax {
		return fmt.Errorf("obf strategy %s: jmin (%d) must not exceed jmax (%d)", name, *s.Jmin, *s.Jmax)
	}
	return nil
}

// validateDefaultJunk checks the obf-level default junk trio for internal
// coherence — the same contract ValidateStrategyJunk holds each strategy to,
// applied to the obf defaults (per-field inheritance can only produce a
// complete trio from a coherent default; an incomplete default is dead config
// wherever it ends up).
func validateDefaultJunk(o *CentralObf) error {
	jcSet := o.Jc != nil && *o.Jc > 0
	if jcSet && (o.Jmin == nil || o.Jmax == nil) {
		return fmt.Errorf("obf defaults: jc requires the jmin/jmax junk size range (datagram sizes are drawn from [jmin, jmax))")
	}
	if !jcSet && (o.Jmin != nil || o.Jmax != nil) {
		return fmt.Errorf("obf defaults: jmin/jmax are set but jc is not positive — no junk datagrams are emitted without a count; set jc, or drop the size range")
	}
	if o.Jmin != nil && o.Jmax != nil && *o.Jmin > *o.Jmax {
		return fmt.Errorf("obf defaults: jmin (%d) must not exceed jmax (%d)", *o.Jmin, *o.Jmax)
	}
	return nil
}

// NodeUsedStrategies computes the strategies a node may speak, in stable
// order: every strategy named by its own advertised endpoints (the listen
// half) or by any router's advertised endpoints (the connect half — a
// conservative superset of the node's actual neighbours, so a graph change
// can never make a previously-valid config start failing at runtime without
// having been re-sealed). Untagged endpoints expand to all strategies.
func NodeUsedStrategies(central *CentralCfg, node NodeId) []string {
	if central == nil {
		return nil
	}
	m := central.ObfStrategies()
	if len(m) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(list []string) {
		for _, n := range list {
			if _, ok := seen[n]; !ok {
				seen[n] = struct{}{}
				out = append(out, n)
			}
		}
	}
	for i := range central.Routers {
		r := &central.Routers[i]
		for _, addr := range r.Endpoints {
			spec, err := ParseEndpointSpec(addr)
			if err != nil {
				continue
			}
			// tagged and bare-host endpoints contribute (untagged expands
			// to all strategies via EndpointStrategyTags); raw
			// host:port endpoints never do
			if !spec.HasStrategies() && (spec.Ports.Valid() || len(m) == 0) {
				continue
			}
			tags, err := EndpointStrategyTags(spec, m)
			if err != nil {
				continue
			}
			add(tags)
		}
	}
	slices.Sort(out)
	return out
}

// ValidateObfStrategies checks the central strategy map and the strategy
// selection mode: names, ports, per-strategy rotation policy, the per-strategy
// junk trio and every i-spec's syntax, and the obf.strategy_mode value
// (required when the mesh defines more than one strategy, rejected when the
// mesh defines none). Per-strategy junk needs no cross-strategy coherence:
// the junk a connection speaks is its carrying strategy's own (the device
// knobs degrade to the fallback, see EffectiveStrategyJunk).
func ValidateObfStrategies(cfg *CentralCfg) error {
	m := cfg.ObfStrategies()
	// the strategy selection mode governs every node's connect half; it is
	// dead config without strategies and an ambiguous choice with more than
	// one (this build replaced the former implicit behaviour — rotations drew
	// across all strategies uniformly — with an explicit mode, like
	// port_hopping_mode before it)
	if cfg.Obf != nil && cfg.Obf.StrategyMode != "" {
		if err := ValidateStrategyMode(cfg.Obf.StrategyMode); err != nil {
			return fmt.Errorf("obf: %w", err)
		}
		if len(m) == 0 {
			return fmt.Errorf("obf: strategy_mode is set but no obf strategies are defined — the mode selects among obf.strategy entries; define at least one, or drop the key")
		}
	}
	if len(m) > 1 && (cfg.Obf == nil || cfg.Obf.StrategyMode == "") {
		return fmt.Errorf("obf: strategy_mode is required when the mesh defines more than one obf strategy (this build no longer rotates implicitly across all strategies): fixed (every connection uses the first strategy of the endpoint's list) | random (a random strategy per connection) | trial (iterate randomly until a connection establishes, then prefer the confirmed strategy; re-search on failure)")
	}
	if len(m) == 0 {
		return nil
	}
	// The obf-level defaults (ObfDefaults) are validated as a virtual
	// strategy: they materialize into every strategy that leaves a
	// parameter unset, so a bogus default must fail loudly even when
	// every defined strategy overrides it (dead config is dead config,
	// wherever it sits).
	if o := cfg.Obf; o.DefaultsSet() {
		if strings.TrimSpace(o.Ports) != "" {
			if _, err := ParsePortRange(strings.TrimSpace(o.Ports)); err != nil {
				return fmt.Errorf("obf: default ports: %w", err)
			}
		}
		if err := ValidateHopPolicyCfg(o.PortHoppingMode, o.PortHopping, "obf defaults"); err != nil {
			return err
		}
		if err := validateDefaultJunk(o); err != nil {
			return err
		}
	}
	for _, name := range StrategyNames(m) {
		s := m[name]
		if err := NameValidator(name); err != nil {
			return fmt.Errorf("obf strategy name: %w", err)
		}
		if _, err := ParseStrategyPorts(s, name); err != nil {
			return err
		}
		if err := ValidateHopPolicyCfg(s.PortHoppingMode, s.PortHopping, fmt.Sprintf("obf strategy %s", name)); err != nil {
			return err
		}
		if err := ValidateStrategyJunk(s, name); err != nil {
			return err
		}
		// every i-spec must parse as an obfuscation chain: each
		// strategy's set now reaches the wire through the per-peer
		// junk hook (not only the one agreed set the device knobs
		// used to render), and the send path cannot fail loudly —
		// validation owns the loud error, exactly where the UAPI
		// i1..i5 parse used to surface it
		for i, ispec := range s.iParams() {
			if ispec == "" {
				continue
			}
			if err := device.ValidateObfSpec(ispec); err != nil {
				return fmt.Errorf("obf strategy %s: i%d: %w", name, i+1, err)
			}
		}
	}
	// Every strategy-tagged endpoint must name defined strategies — the
	// connect half expands the tags into candidates at runtime, so a
	// dangling tag is a config error (the endpoint is otherwise silently
	// strategyless).
	for i := range cfg.Routers {
		for _, addr := range cfg.Routers[i].Endpoints {
			spec, err := ParseEndpointSpec(addr)
			if err != nil || !spec.HasStrategies() {
				// unparseable endpoints are reported by the router loop with
				// node context; here they contribute no strategies
				continue
			}
			if _, err := EndpointStrategyTags(spec, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// formatRanges renders a range list for messages and journals:
// "40000-50000,51820".
func formatRanges(prs []PortRange) string {
	parts := make([]string, 0, len(prs))
	for _, pr := range prs {
		parts = append(parts, pr.String())
	}
	return strings.Join(parts, ",")
}

// RangesString is the exported form of formatRanges (device UAPI rendering,
// journal lines).
func RangesString(prs []PortRange) string {
	return formatRanges(prs)
}
