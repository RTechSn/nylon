package state

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"go4.org/netipx"
)

// ObfHeaderRange is an inclusive uint32 range mapping to the UAPI "min-max" form.
type ObfHeaderRange struct {
	Min uint32
	Max uint32
}

// ObfProfile is the mesh-wide shared AWG 2.0 handshake dialect (S/H) — the
// wire contract every pair of nodes must speak identically, so it cannot
// vary from node to node. It lives inline in the global `obf` block of the
// central config (CentralObf), which keeps S/H uniform across the full mesh
// by construction, as wire compatibility requires (design §2.4) — and matches
// the upstream naming, where the central `obf` block is network-wide and the
// per-node `obf` block (node.yaml) is per-node. The sender-local junk
// emission (jc/jmin/jmax and the I-packets) is per-strategy — see ObfStrategy
// and EffectiveStrategyJunk.
type ObfProfile struct {
	S1 uint32         `yaml:",omitempty"`
	S2 uint32         `yaml:",omitempty"`
	S3 uint32         `yaml:",omitempty"`
	S4 uint32         `yaml:",omitempty"`
	H1 ObfHeaderRange `yaml:",omitempty"`
	H2 ObfHeaderRange `yaml:",omitempty"`
	H3 ObfHeaderRange `yaml:",omitempty"`
	H4 ObfHeaderRange `yaml:",omitempty"`
}

// Validate performs structural load-time checks. Deep parameter validation
// (padding collisions, header-range viability) belongs to the genesis tool;
// the per-strategy junk trio carries its own checks (ValidateStrategyJunk).
func (p *ObfProfile) Validate() error {
	for i, h := range [4]ObfHeaderRange{p.H1, p.H2, p.H3, p.H4} {
		if h.Min > h.Max {
			return fmt.Errorf("h%d min (%d) must not exceed max (%d)", i+1, h.Min, h.Max)
		}
	}
	return nil
}

// ObfPeerParams is the RETIRED per-node obf block (protocol label + I1-I5).
// Parse-only: a config that still carries it fails validation with a
// migration error (the i-params moved into central obf strategies).
type ObfPeerParams struct {
	Protocol string `yaml:",omitempty"` // amnezigo template name, informational
	I1       string `yaml:",omitempty"`
	I2       string `yaml:",omitempty"`
	I3       string `yaml:",omitempty"`
	I4       string `yaml:",omitempty"`
	I5       string `yaml:",omitempty"`
}

// ObfDefaults is the defaultable subset of the obf strategy parameters, set
// inline at the `obf:` level (sibling of the mesh-wide S/H dialect and the
// named strategy map). Every parameter a strategy may set can also be set
// here as a mesh-wide default: a strategy that leaves the parameter unset
// inherits the obf-level value, a strategy that sets it wins (per parameter —
// a strategy that sets only `i1` inherits the obf default `i2`..`i5` slot by
// slot). The defaults resolve where the strategy VALUES are consumed —
// CentralCfg.ObfStrategies() returns the resolved (materialized) map — while
// serialization keeps the operator's shape: the defaults stay at the obf
// level and the strategies stay as written, in the seal, in the distributed
// bundle and in the daemon's local cache alike.
// (The fields live directly on CentralObf rather than in a second inline
// embed: goccy/go-yaml v1.19.1 silently drops the whole section when a
// struct carries TWO inline embeds and the second marshals to nothing —
// the single ObfProfile inline plus direct fields marshal correctly.)

// CentralObf is the global `obf` block of the central config — the
// network-wide obfuscation half (upstream keeps the same naming: a `obf`
// block on a node holds per-node parameters, the central `obf` block holds
// the parameters for the whole network). It carries the mesh-wide S/H
// handshake dialect inline (the wire contract, uniform by construction), the
// named strategy map under `strategy:` — ports, rotation policy and the
// sender-local junk emission, selected per endpoint (host[<strategy>,...]) —
// and the obf-level DEFAULTS for the strategy parameters (ObfDefaults): a
// strategy inherits every parameter it does not set of its own.
// A nil CentralObf (no `obf:` key at all) is the vanilla-compat default.
type CentralObf struct {
	ObfProfile `yaml:",inline"`

	// The obf-level DEFAULTS for the strategy parameters (see the
	// ObfDefaults comment above): inherited per field by every strategy
	// that leaves the parameter unset.
	Ports           string          `yaml:"ports,omitempty"`             // default port spec: "40000" or "40000-50000"
	PortHoppingMode string          `yaml:"port_hopping_mode,omitempty"` // static (default) | reactive | proactive | timed
	PortHopping     *PortHoppingCfg `yaml:"port_hopping,omitempty"`      // default rotation policy block
	Jc              *uint32         `yaml:"jc,omitempty"`                // default junk datagram count
	Jmin            *uint32         `yaml:"jmin,omitempty"`              // default junk size range low
	Jmax            *uint32         `yaml:"jmax,omitempty"`              // default junk size range high
	I1              string          `yaml:"i1,omitempty"`
	I2              string          `yaml:"i2,omitempty"`
	I3              string          `yaml:"i3,omitempty"`
	I4              string          `yaml:"i4,omitempty"`
	I5              string          `yaml:"i5,omitempty"`

	// Strategy is the named obf strategy map; referenced per endpoint as
	// host[strategy1,strategy2] (untagged / "[*]" = all strategies).
	Strategy map[string]*ObfStrategy `yaml:"strategy,omitempty"`
	// StrategyMode is the strategy selection principle for new connections
	// (obf.strategy_mode): fixed (default) | random | trial; `rated` is
	// reserved. Required when the mesh defines more than one strategy —
	// see ValidateObfStrategies.
	StrategyMode string `yaml:"strategy_mode,omitempty"`
}

// DefaultsSet reports whether the obf block carries any strategy default.
func (o *CentralObf) DefaultsSet() bool {
	if o == nil {
		return false
	}
	return o.Ports != "" ||
		o.PortHoppingMode != "" || o.PortHopping != nil ||
		o.Jc != nil || o.Jmin != nil || o.Jmax != nil ||
		o.I1 != "" || o.I2 != "" || o.I3 != "" || o.I4 != "" || o.I5 != ""
}

// applyDefaults returns a copy of the strategy with every unset parameter
// inherited from the obf-level defaults (per field — the strategy's own
// value always wins). The receiver is never mutated; s is returned as-is
// when nothing is inherited.
func (o *CentralObf) applyDefaults(s *ObfStrategy) *ObfStrategy {
	if !o.DefaultsSet() || s == nil {
		return s
	}
	out := *s
	if out.Ports == "" {
		out.Ports = o.Ports
	}
	if out.PortHoppingMode == "" {
		out.PortHoppingMode = o.PortHoppingMode
	}
	if out.PortHopping == nil {
		out.PortHopping = o.PortHopping
	}
	if out.Jc == nil {
		out.Jc = o.Jc
	}
	if out.Jmin == nil {
		out.Jmin = o.Jmin
	}
	if out.Jmax == nil {
		out.Jmax = o.Jmax
	}
	if out.I1 == "" {
		out.I1 = o.I1
	}
	if out.I2 == "" {
		out.I2 = o.I2
	}
	if out.I3 == "" {
		out.I3 = o.I3
	}
	if out.I4 == "" {
		out.I4 = o.I4
	}
	if out.I5 == "" {
		out.I5 = o.I5
	}
	return &out
}

// ObfStrategies returns the RESOLVED named obf strategy map of the global
// `obf` block: every strategy with each unset parameter inherited from the
// obf-level defaults (see ObfDefaults). The returned entries are fresh
// copies whenever defaults are set (the raw map is never handed out then);
// with no defaults configured the raw map is returned unchanged. Consumers
// reading strategy VALUES (validation, the listen union, the junk
// resolution, the connect-half candidates, the policy journal) must go
// through this accessor — direct `Obf.Strategy` access reads the RAW
// operator shape and misses the defaults. Serialization (seal, the local
// config cache) deliberately uses the raw shape.
// Nil when the block or the map is absent.
func (c *CentralCfg) ObfStrategies() map[string]*ObfStrategy {
	if c == nil || c.Obf == nil {
		return nil
	}
	m := c.Obf.Strategy
	if len(m) == 0 {
		return nil
	}
	if !c.Obf.DefaultsSet() {
		return m
	}
	out := make(map[string]*ObfStrategy, len(m))
	for name, s := range m {
		out[name] = c.Obf.applyDefaults(s)
	}
	return out
}

// ObfStrategyMode returns the resolved strategy selection mode of the global
// `obf` block: an absent block or value resolves to fixed. Unknown values
// (a live-swapped config that slipped past validation) also resolve to fixed —
// validation owns the loud error; the runtime never wedges on a bad value.
func (c *CentralCfg) ObfStrategyMode() string {
	if c == nil || c.Obf == nil {
		return StrategyModeFixed
	}
	switch c.Obf.StrategyMode {
	case StrategyModeRandom, StrategyModeTrial:
		return c.Obf.StrategyMode
	default:
		return StrategyModeFixed
	}
}

// Profile returns the mesh-wide AWG 2.0 S/H handshake dialect from the global
// `obf` block, or nil when the block is absent or carries no dialect — nil
// means vanilla-compat (the device pins H1..H4 to the WireGuard message
// types; see core.obfDeviceIPC). The returned pointer aliases the embedded
// profile inside the active config, so it stays stable for one config
// generation and changes identity across a config swap.
func (c *CentralCfg) Profile() *ObfProfile {
	if c == nil || c.Obf == nil {
		return nil
	}
	p := c.Obf.ObfProfile
	if p == (ObfProfile{}) {
		return nil
	}
	return &c.Obf.ObfProfile
}

type NodeCfg struct {
	Id        NodeId
	PubKey    NyPublicKey
	Addresses []netip.Addr          `yaml:",omitempty"`
	Prefixes  []PrefixHealthWrapper `yaml:",omitempty"`
	// Obf is the retired per-node obf block; parse-only, rejected by
	// validation (i1..i5 moved into central obf strategies).
	Obf *ObfPeerParams `yaml:"obf,omitempty"`
}

// RouterCfg represents a central representation of a node that can route
type RouterCfg struct {
	NodeCfg   `yaml:",inline"`
	Endpoints []string
	// PortHoppingMode/PortHopping are the RETIRED router-level rotation
	// policy fields; parse-only, rejected by validation (the rotation
	// policy moved into obf strategies — see ObfStrategy).
	PortHoppingMode string          `yaml:"port_hopping_mode,omitempty"`
	PortHopping     *PortHoppingCfg `yaml:"port_hopping,omitempty"`
	PriorityRules   []PriorityRule  `yaml:"priority_rules,omitempty"` // in-tunnel QoS: inner protocol/port rules -> in-device priority + outer DSCP marking; wins wholesale over node.yaml (an empty list clears)
}
type ClientCfg struct {
	NodeCfg `yaml:",inline"`
}

type DistributionCfg struct {
	Key   NyPublicKey // also used as shared secret, so, although its "public", it's not a good idea to share it.
	Repos []string
	// Interval is how often the repos are polled for config updates.
	// nil = fall back to LocalDistributionCfg.Interval, then the built-in
	// default (RouterTunables.CentralUpdateDelay).
	Interval *time.Duration `yaml:"interval,omitempty"`
}

type LocalDistributionCfg struct {
	Key NyPublicKey
	Url string
	// Interval is the fallback polling cadence used while the active
	// central config's dist block sets no interval of its own. The url/key
	// above are bootstrap-only; the interval outlives bootstrap.
	Interval *time.Duration `yaml:"interval,omitempty"`
}

// ResolveUpdateDelay returns the effective cadence for polling the
// distribution repos: the central dist interval takes precedence, then the
// node.yaml dist interval, then the tunables default.
func ResolveUpdateDelay(central *DistributionCfg, local *LocalDistributionCfg, def time.Duration) time.Duration {
	delay, _ := ResolveUpdateDelaySource(central, local, def)
	return delay
}

// ResolveUpdateDelaySource additionally reports where the effective cadence
// came from: "central" (dist.interval of the active central config), "node"
// (dist.interval in node.yaml) or "default" (RouterTunables). The source is
// logged with every poll attempt so that a silently ignored interval - for
// example one sealed into a bundle by an older binary - is diagnosable from
// the journal alone.
func ResolveUpdateDelaySource(central *DistributionCfg, local *LocalDistributionCfg, def time.Duration) (time.Duration, string) {
	if central != nil && central.Interval != nil && *central.Interval > 0 {
		return *central.Interval, "central"
	}
	if local != nil && local.Interval != nil && *local.Interval > 0 {
		return *local.Interval, "node"
	}
	return def, "default"
}

type CentralCfg struct {
	Dist                *DistributionCfg `yaml:",omitempty"`
	Routers             []RouterCfg
	Clients             []ClientCfg
	Graph               []string
	Timestamp           int64
	ExcludeIPs          []netip.Prefix `yaml:"exclude_ips,omitempty"`           // split tunnel, default excluded ip ranges for the whole network, if empty, all advertised prefixes will be included
	DynamicPrefixRanges []netip.Prefix `yaml:"dynamic_prefix_ranges,omitempty"` // ranges dynamic prefixes may be announced from (design §4.6); receivers drop announcements for prefixes outside their central prefixes and these ranges
	Obf                 *CentralObf    `yaml:"obf,omitempty"`                   // the global obf block: the mesh-wide AWG 2.0 S/H handshake dialect (inline s1-s4/h1-h4) plus the named strategy map under `strategy:` (ports, rotation policy, sender-local junk); nil = vanilla-compat; referenced per endpoint as host[strategy1,strategy2]
	PriorityRules       []PriorityRule `yaml:"priority_rules,omitempty"`        // in-tunnel QoS: mesh-wide default rule set — a node's own routers[] entry wins wholesale over this list, which wins wholesale over node.yaml (empty == absent at every level)
}

// TunablesOverrides carries optional router tunable overrides from the local
// node config; nil fields keep the DefaultRouterTunables value.
type TunablesOverrides struct {
	ProbeDelay                 *time.Duration `yaml:"probe_delay,omitempty"`
	ProbeRecoveryDelay         *time.Duration `yaml:"probe_recovery_delay,omitempty"`
	ProbeDiscoveryDelay        *time.Duration `yaml:"probe_discovery_delay,omitempty"`
	GcDelay                    *time.Duration `yaml:"gc_delay,omitempty"`
	LinkDeadThreshold          *time.Duration `yaml:"link_dead_threshold,omitempty"`
	ProbeTimeout               *time.Duration `yaml:"probe_timeout,omitempty"`
	RouteExpiryTime            *time.Duration `yaml:"route_expiry_time,omitempty"`
	RouteSwitchHold            *time.Duration `yaml:"route_switch_hold,omitempty"`
	NoEndpointWarnInterval     *time.Duration `yaml:"no_endpoint_warn_interval,omitempty"`
	HandshakeStaleWarn         *time.Duration `yaml:"handshake_stale_warn,omitempty"`
	HandshakeStaleDemote       *time.Duration `yaml:"handshake_stale_demote,omitempty"`
	HandshakeStaleDebounce     *time.Duration `yaml:"handshake_stale_debounce,omitempty"`
	HandshakeStaleWarnInterval *time.Duration `yaml:"handshake_stale_warn_interval,omitempty"`
	LossPenaltyGain            *float64       `yaml:"loss_penalty_gain,omitempty"`
	LossDemotionThreshold      *float64       `yaml:"loss_demotion_threshold,omitempty"`
	LinkSwitchDeadband         *float64       `yaml:"link_switch_deadband,omitempty"`
	HopCost                    *uint32        `yaml:"hop_cost,omitempty"`
}

// Port rotation modes (port_hopping_mode) decide WHEN the carrying endpoint of a
// range-configured peer changes. The mode governs the node's OUTGOING
// connections (the client half of port hopping); the listen half
// (listen_ports/listen_mode) is orthogonal and serves other nodes' rotation
// into our range, so a hub may serve a wide range while itself running any
// mode.
const (
	// HopModeStatic never rotates: the carrying endpoint stays pinned to
	// the first port of the first resolvable range spec. Default; the flow
	// behaves like a pre-hopping single-port connection.
	HopModeStatic = "static"
	// HopModeReactive rotates only when the carrying link is considered
	// dead: no traffic heard back for link_dead_threshold, or loss-dead
	// probe statistics. Minimal port churn; reacts only after a drop.
	HopModeReactive = "reactive"
	// HopModeProactive rotates after the carrying port has carried the
	// configured packet budget (budget_packets, required) — the worst-case
	// per-flow volume strategy against middleboxes that ban flows by packet
	// count.
	HopModeProactive = "proactive"
	// HopModeTimed rotates on a wall-clock schedule: every period_seconds
	// (required), with a random jitter so rotations do not synchronise.
	HopModeTimed = "timed"

	// Reserved mode names, parseable but rejected by validation until their
	// implementing branch lands.
	HopModeDynamic = "dynamic" // proactive with an automatically sized budget
	HopModeAuto    = "auto"    // automatic mode switching by connection conditions
)

// HopModes lists the implemented port_hopping_mode values.
func HopModes() []string {
	return []string{HopModeStatic, HopModeReactive, HopModeProactive, HopModeTimed}
}

// ReservedHopModes lists the port_hopping_mode values reserved for future branches.
func ReservedHopModes() []string {
	return []string{HopModeDynamic, HopModeAuto}
}

// ValidateHopMode checks a port_hopping_mode value: implemented modes pass,
// reserved names get a dedicated not-yet-implemented error, anything else
// is unknown.
func ValidateHopMode(mode string) error {
	if slices.Contains(HopModes(), mode) {
		return nil
	}
	if slices.Contains(ReservedHopModes(), mode) {
		return fmt.Errorf("port_hopping_mode %q is reserved for a future release and not implemented yet (this build implements %v)", mode, HopModes())
	}
	return fmt.Errorf("unknown port_hopping_mode %q (want one of %v)", mode, HopModes())
}

// Strategy selection modes (obf.strategy_mode) decide WHICH obf strategy a
// new connection uses — the connect half of the strategy model. Where
// port_hopping_mode governs WHEN the carrying endpoint rotates (within the
// strategy's ports), strategy_mode governs the strategy choice per
// connection: every drawn carrying endpoint is one connection (one UDP flow
// through the middleboxes), so the mode applies on every draw.
const (
	// StrategyModeFixed uses the FIRST strategy of the endpoint's list
	// (config order: endpoints first, then the tag order as written) for
	// every connection. Default; the deterministic, predictable pin.
	StrategyModeFixed = "fixed"
	// StrategyModeRandom draws a random strategy for every connection,
	// preferring one other than the outgoing connection's when the peer
	// names more than one.
	StrategyModeRandom = "random"
	// StrategyModeTrial iterates randomly until a connection establishes
	// (the carrying endpoint is heard back on — the handshake completed);
	// the confirmed strategy is remembered, and every later connection
	// (reconnects and rotations alike) first uses it. When an attempt on the
	// remembered strategy exhausts without confirmation, the memory is
	// demoted and the random iteration resumes.
	StrategyModeTrial = "trial"

	// StrategyModeRated is a reserved mode name: strategy rating by measured
	// connection performance. Parseable, but rejected by validation until
	// the implementing branch lands (same contract as the reserved hop
	// modes).
	StrategyModeRated = "rated" // rating by measured performance — not implemented yet
)

// StrategyModes lists the implemented obf.strategy_mode values.
func StrategyModes() []string {
	return []string{StrategyModeFixed, StrategyModeRandom, StrategyModeTrial}
}

// ReservedStrategyModes lists the obf.strategy_mode values reserved for
// future branches.
func ReservedStrategyModes() []string {
	return []string{StrategyModeRated}
}

// ValidateStrategyMode checks an obf.strategy_mode value: implemented modes
// pass, reserved names get a dedicated not-yet-implemented error, anything
// else is unknown.
func ValidateStrategyMode(mode string) error {
	if slices.Contains(StrategyModes(), mode) {
		return nil
	}
	if slices.Contains(ReservedStrategyModes(), mode) {
		return fmt.Errorf("strategy_mode %q is reserved for a future release and not implemented yet (this build implements %v)", mode, StrategyModes())
	}
	return fmt.Errorf("unknown strategy_mode %q (want one of %v)", mode, StrategyModes())
}

// PortHoppingCfg is the client-side port rotation policy for peers whose
// endpoints are configured with port ranges. Nil values keep the built-in
// defaults (see DefaultPortHoppingPolicy). Which knobs are meaningful
// depends on the configured port_hopping_mode; knobs the mode does not use are
// ignored.
type PortHoppingCfg struct {
	BudgetPackets    *uint32 `yaml:"budget_packets,omitempty"`    // proactive: rotate the carrying port after N wire packets (worst-case per-flow budget)
	PeriodSeconds    *uint32 `yaml:"period_seconds,omitempty"`    // timed: rotate every N seconds (required in timed mode)
	PeriodJitterPct  *uint32 `yaml:"period_jitter_pct,omitempty"` // timed: random jitter around the period, as a percentage of it (default 10, at most 50)
	RecentPorts      *uint32 `yaml:"recent_ports,omitempty"`      // avoid reusing the last N selected endpoints
	CooldownSeconds  *uint32 `yaml:"cooldown_seconds,omitempty"`  // quarantine a retired port for this long
	CandidateSamples *uint32 `yaml:"candidate_samples,omitempty"` // candidates sampled per selection for diversity scoring
	RecycleSeconds   *uint32 `yaml:"recycle_seconds,omitempty"`   // opt-in auto-recycle: when the pool exhausts, clear the retirement quarantine so rotation resumes immediately, at most once per this many seconds (0/absent = stock behaviour: stall until a cooldown elapses and warn)
	AutoRecycle      *bool   `yaml:"auto_recycle,omitempty"`      // Deprecated: interim-PR knob replaced by recycle_seconds; parse-only, so a leftover key fails validation with an actionable error instead of being silently ignored
}

// PortHoppingPolicy is the resolved, always-set form of PortHoppingCfg.
// Mode is filled by ResolveHopPolicy (the knob block does not carry it).
type PortHoppingPolicy struct {
	Mode             string
	Budget           uint32
	Period           time.Duration
	JitterPct        uint32 // percentage of Period; the effective interval is Period ± Period*JitterPct/100
	Recent           uint32
	Cooldown         time.Duration
	CandidateSamples uint32
	// RecycleMinInterval is the resolved port_hopping.recycle_seconds:
	// when the pool exhausts, the retired-port quarantine is cleared so
	// rotation resumes immediately, rate-limited to once per this
	// interval. Zero keeps the stock behaviour (rotation stalls until a
	// cooldown elapses). See PortHoppingCfg.RecycleSeconds.
	RecycleMinInterval time.Duration
}

// DefaultPortHoppingPolicy returns the worst-case defaults: the budget stays
// under empirically observed per-flow volume bans (16-20 packets), retired
// ports are quarantined for several minutes (typical middlebox recovery),
// and selection samples enough candidates to express the diversity
// preference across IPs and subnets.
func DefaultPortHoppingPolicy() PortHoppingPolicy {
	return PortHoppingPolicy{
		Mode:             HopModeStatic,
		Budget:           12,
		Period:           0,
		JitterPct:        10,
		Recent:           512,
		Cooldown:         3 * time.Minute,
		CandidateSamples: 32,
	}
}

// Resolve fills unset fields with the defaults. The mode is the static
// default; ResolveHopPolicy overrides it with the winning source's port_hopping_mode.
func (c *PortHoppingCfg) Resolve() PortHoppingPolicy {
	p := DefaultPortHoppingPolicy()
	if c == nil {
		return p
	}
	if c.BudgetPackets != nil && *c.BudgetPackets > 0 {
		p.Budget = *c.BudgetPackets
	}
	if c.PeriodSeconds != nil && *c.PeriodSeconds > 0 {
		p.Period = time.Duration(*c.PeriodSeconds) * time.Second
	}
	if c.PeriodJitterPct != nil {
		p.JitterPct = *c.PeriodJitterPct
	}
	if c.RecentPorts != nil && *c.RecentPorts > 0 {
		p.Recent = *c.RecentPorts
	}
	if c.CooldownSeconds != nil && *c.CooldownSeconds > 0 {
		p.Cooldown = time.Duration(*c.CooldownSeconds) * time.Second
	}
	if c.CandidateSamples != nil && *c.CandidateSamples > 0 {
		p.CandidateSamples = *c.CandidateSamples
	}
	if c.RecycleSeconds != nil && *c.RecycleSeconds > 0 {
		p.RecycleMinInterval = time.Duration(*c.RecycleSeconds) * time.Second
	}
	return p
}

// RetiredHopPolicyError is the shared migration error for the retired
// port_hopping_mode / port_hopping / listen_ports fields (node-level,
// router-level): the rotation policy and the served ports moved into central
// obf strategies.
func retiredHopPolicyError(where string) error {
	return fmt.Errorf("%s: port_hopping_mode / port_hopping moved into obf strategies — define the rotation policy on the obf strategy that carries the ports (central `obf:` block, e.g. obf.strategy.hopping.port_hopping_mode: timed), then tag the endpoints that use it: host[hopping]", where)
}

func retiredListenPortsError(where string) error {
	return fmt.Errorf("%s: listen_ports moved into obf strategies — the listen half now derives from the strategies this node's own advertised endpoints name; define the ports on a central obf strategy (obf.strategy.<name>.ports) and advertise the strategy on an endpoint: host[<name>]", where)
}

func retiredNodeObfError(where string) error {
	return fmt.Errorf("%s: the per-node obf block moved into central obf strategies — carry the jc/jmin/jmax and i1..i5 junk-packet params on the obf strategy that uses them (the `obf.strategy` map of the central `obf:` block)", where)
}

// ValidateHopPolicyCfg checks one file's hop policy for internal
// consistency: the mode must be implemented (or clearly reserved), and the
// parameters the configured mode requires must be co-located in the same
// block — a mode may not rely on knobs from the other config file. Knobs
// the configured mode does not use are not an error (they are ignored).
// where names the config location for error messages.
func ValidateHopPolicyCfg(mode string, cfg *PortHoppingCfg, where string) error {
	if mode == "" {
		if cfg != nil {
			return fmt.Errorf("%s: port_hopping is configured but port_hopping_mode is not set; this build requires an explicit mode (earlier builds rotated by packet budget implicitly — set port_hopping_mode: proactive to keep that behaviour, or reactive|timed|static; the knob was renamed from port_mode)", where)
		}
		return nil
	}
	if err := ValidateHopMode(mode); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	switch mode {
	case HopModeProactive:
		if cfg == nil || cfg.BudgetPackets == nil {
			return fmt.Errorf("%s: port_hopping_mode proactive requires port_hopping.budget_packets in the same config file", where)
		}
	case HopModeTimed:
		if cfg == nil || cfg.PeriodSeconds == nil {
			return fmt.Errorf("%s: port_hopping_mode timed requires port_hopping.period_seconds in the same config file", where)
		}
	}
	if cfg != nil {
		if cfg.AutoRecycle != nil {
			return fmt.Errorf("%s: port_hopping.auto_recycle was replaced by recycle_seconds — it restarted the sweep unconditionally on every pool exhaustion; set recycle_seconds: N to restart at most once per N seconds, or drop the key for the stock stall-until-cooldown behaviour", where)
		}
		if cfg.PeriodSeconds != nil && *cfg.PeriodSeconds == 0 {
			return fmt.Errorf("%s: port_hopping.period_seconds must be greater than 0 (or omitted)", where)
		}
		if cfg.PeriodJitterPct != nil && *cfg.PeriodJitterPct > 50 {
			return fmt.Errorf("%s: port_hopping.period_jitter_pct must be at most 50, got %d", where, *cfg.PeriodJitterPct)
		}
	}
	return nil
}

// Listen modes for the port-hopping server half (see LocalCfg.ListenPorts).
const (
	// ListenModeSockets binds one extra UDP socket per port of the listen
	// range (the MultiBind range listener). It is the default and works
	// everywhere, but every port costs file descriptors and receive buffers,
	// hence the MaxInDaemonListenPorts ceiling.
	ListenModeSockets = "sockets"
	// ListenModeNftables keeps the single primary-port bind and installs a
	// netfilter redirect for the listen range instead: the kernel rewrites
	// inbound packets addressed to any port of the range to the primary
	// port, and conntrack mirrors the reverse direction so replies still
	// originate from the port the peer targeted. Sockets and memory stay
	// O(1) for arbitrarily wide ranges. Linux only, requires CAP_NET_ADMIN.
	ListenModeNftables = "nftables"
)

// EffectiveListenMode returns the configured listen mode, defaulting to
// ListenModeSockets.
func (c *LocalCfg) EffectiveListenMode() string {
	if c.ListenMode == "" || c.ListenMode == ListenModeSockets {
		return ListenModeSockets
	}
	return c.ListenMode
}

// UsesNftListenMode reports whether the listen range is served by the
// daemon-managed netfilter redirect instead of per-port sockets.
func (c *LocalCfg) UsesNftListenMode() bool {
	return c.EffectiveListenMode() == ListenModeNftables
}

// LocalCfg represents local node-level configuration
type LocalCfg struct {
	// Node Private Key
	Key  NyPrivateKey
	Id   NodeId // unique id for this node
	Port uint16 // Address that the data plane can be accessed by (primary listen port; always bound)
	// ListenPorts is the RETIRED node-level listen range; parse-only,
	// rejected by validation (ports moved into central obf strategies —
	// the listen half now derives from the strategies this node's own
	// advertised endpoints name).
	ListenPorts string `yaml:"listen_ports,omitempty"`
	ListenMode  string `yaml:"listen_mode,omitempty"` // how the strategy-derived listen ranges are served: "sockets" (default, one socket per port) or "nftables" (daemon-managed DNAT redirect; Linux, CAP_NET_ADMIN)
	// PortHoppingMode/PortHopping are the RETIRED node-level rotation
	// policy fields; parse-only, rejected by validation (the rotation
	// policy moved into obf strategies — see ObfStrategy).
	PortHoppingMode    string                `yaml:"port_hopping_mode,omitempty"`
	PortHopping        *PortHoppingCfg       `yaml:"port_hopping,omitempty"`
	PriorityRules      []PriorityRule        `yaml:"priority_rules,omitempty"`       // in-tunnel QoS: inner protocol/port rules -> in-device priority + outer DSCP marking
	Dist               *LocalDistributionCfg `yaml:",omitempty"`                     // distribution configuration
	UseSystemRouting   bool                  `yaml:"use_system_routing,omitempty"`   // all packets from peers will come out of the TUN interface
	NoTun              bool                  `yaml:"no_tun,omitempty"`               // relay-only mode; requires no advertised addresses or prefixes
	NoNetConfigure     bool                  `yaml:"no_net_configure,omitempty"`     // do not configure system networking at all
	DnsResolvers       []string              `yaml:"dns_resolvers,omitempty"`        // DNS resolvers used for endpoints and config repositories
	InterfaceName      string                `yaml:"interface_name,omitempty"`       // the name of the nylon interface
	LogPath            string                `yaml:"log_path,omitempty"`             // if not empty, nylon will write to this file
	ObservabilityAddr  string                `yaml:"observability_addr,omitempty"`   // HTTP address for metrics, health, readiness, and service discovery
	UnexcludeIPs       []netip.Prefix        `yaml:"unexclude_ips,omitempty"`        // split tunnel, subtracts from centrally excluded ip ranges
	ExcludeIPs         []netip.Prefix        `yaml:"exclude_ips,omitempty"`          // split tunnel, adds to the centrally excluded ip ranges
	PreUp              []string              `yaml:"pre_up,omitempty"`               // a list of commands executed in order before the nylon interface is brought up
	PreDown            []string              `yaml:"pre_down,omitempty"`             // a list of commands executed in order before the nylon interface is brought down
	PostUp             []string              `yaml:"post_up,omitempty"`              // a list of commands executed in order after the nylon interface is brought up
	PostDown           []string              `yaml:"post_down,omitempty"`            // a list of commands executed in order after the nylon interface is brought down
	MTU                *uint16               `yaml:"mtu,omitempty"`                  // TUN MTU; nil = device default (1420)
	TunQueues          *int                  `yaml:"tun_queues,omitempty"`           // TUN queue count; nil = min(NumCPU, 4); Linux only
	TunTxQueueLen      *int                  `yaml:"tun_txqueuelen,omitempty"`       // TUN tx queue length; nil = 10000; 0 = keep the kernel default
	TunBackpressure    *bool                 `yaml:"tun_backpressure,omitempty"`     // request IFF_BACKPRESSURE; nil = false (kernel support required)
	DynamicPrefixesDir string                `yaml:"dynamic_prefixes_dir,omitempty"` // directory of dynamic prefix JSON files (design §4); empty = disabled
	Tunables           *TunablesOverrides    `yaml:"router_tunables,omitempty"`      // router tunables overrides; nil = defaults
}

func (c *CentralCfg) Clone() (*CentralCfg, error) {
	data, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	var dst CentralCfg
	if err = yaml.Unmarshal(data, &dst); err != nil {
		return nil, err
	}
	return &dst, nil
}

// GetPrefixes returns all unique prefixes from all nodes
func (c *CentralCfg) GetPrefixes() []netip.Prefix {
	prefixMap := make(map[netip.Prefix]bool)

	// Collect from routers
	for _, router := range c.Routers {
		for _, prefix := range router.Prefixes {
			prefixMap[prefix.GetPrefix()] = true
		}
	}

	// Collect from clients
	for _, client := range c.Clients {
		for _, prefix := range client.Prefixes {
			prefixMap[prefix.GetPrefix()] = true
		}
	}

	// Convert to slice
	prefixes := make([]netip.Prefix, 0, len(prefixMap))
	for prefix := range prefixMap {
		prefixes = append(prefixes, prefix)
	}

	return prefixes
}

func (c *CentralCfg) GetNodes() []NodeCfg {
	nodes := make([]NodeCfg, 0)
	for _, n := range c.Routers {
		nodes = append(nodes, n.NodeCfg)
	}
	for _, n := range c.Clients {
		nodes = append(nodes, n.NodeCfg)
	}
	return nodes
}

func parseSymbolList(s string, validSymbols []string) ([]string, error) {
	spl := strings.Split(strings.TrimSpace(s), ",")
	line := make([]string, 0)
	for _, s := range spl {
		x := strings.TrimSpace(s)
		if x == "" {
			continue
		}
		if !slices.Contains(validSymbols, x) {
			return nil, fmt.Errorf(`invalid graph: %s is not a valid node/group`, x)
		}
		line = append(line, x)
	}
	if len(line) == 0 {
		return nil, fmt.Errorf(`invalid graph: node/group list must not be empty`)
	}
	slices.Sort(line)
	return line, nil
}

func MakeSet(prefix []netip.Prefix) *netipx.IPSet {
	builder := netipx.IPSetBuilder{}
	for _, pfx := range prefix {
		builder.AddPrefix(pfx)
	}
	res, err := builder.IPSet()
	if err != nil {
		panic(err)
	}
	return res
}

/*
ParseGraph Graph syntax is something like this:

Group1 = node1, node2, node3

Group2 = node4, node5

Group1, Group2, OtherNode // Group1, Group2, OtherNode will all be interconnected, but not within Group1 or Group2

Group1, Group1 // every node is connected to every other node

node8, node9 // node8 and node9 will be connected

graph represents the above graph
nodes represents a set of unique terminal nodes that the graph will evaluate down to
*/
func ParseGraph(graph []string, nodes []string) ([]Pair[NodeId, NodeId], error) {
	// why can't we just have unordered_set<Pair<NodeId, NodeId>> :(

	parsedPairings := make([]Pair[string, string], 0)

	groups := make(map[string][]string)

	symbols := slices.Clone(nodes)

	// pass 0, collect all symbols

	for _, line := range graph {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(line, "=") {
			// group definition
			spl := strings.Split(line, "=")
			if len(spl) != 2 {
				return nil, fmt.Errorf("invalid graph: %s. group definition must contain one '='", line)
			}
			grp := strings.TrimSpace(spl[0])
			if slices.Contains(nodes, grp) {
				return nil, fmt.Errorf("invalid graph: group name must not be a node name: %s", grp)
			}
			symbols = append(symbols, grp)
		}
	}
	slices.Sort(symbols)
	symbols = slices.Compact(symbols)

	// used for topological sorting
	// map: group -> []<groups that the node depends on>
	topo := make(map[string][]string)
	expansion := make(map[string][]string)

	// pass 1, parse graph
	for _, line := range graph {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(line, "=") {
			spl := strings.Split(line, "=")
			grp := strings.TrimSpace(spl[0])
			if _, ok := groups[grp]; ok {
				return nil, fmt.Errorf("invalid graph: duplicate group name: %s", grp)
			}
			lst, err := parseSymbolList(spl[1], symbols)
			if err != nil {
				return nil, err
			}
			// track dependencies
			deps := make([]string, 0)
			for _, l := range lst {
				if !slices.Contains(nodes, l) {
					// depends on a group
					deps = append(deps, l)
				} else {
					expansion[grp] = append(expansion[grp], l)
				}
			}
			slices.Sort(deps)
			deps = slices.Compact(deps)

			topo[grp] = deps
			groups[grp] = lst
		} else {
			names, err := parseSymbolList(line, symbols)
			if err != nil {
				return nil, err
			}
			if len(names) < 2 {
				return nil, fmt.Errorf("invalid graph: invalid pairing, %v", names)
			}
			interconnectNodes := make([]NodeId, 0)
			for _, name := range names {
				for _, node := range interconnectNodes {
					parsedPairings = append(parsedPairings, MakeSortedPair(string(node), name))
				}
				interconnectNodes = append(interconnectNodes, NodeId(name))
			}
			SortPairs(parsedPairings)
			parsedPairings = slices.Compact(parsedPairings)
		}
	}

	// pass 2, expand group names
	// just topological sorting
	for len(topo) > 0 {
		// find free group
		var group string
		for k, v := range topo {
			if len(v) == 0 {
				group = k
				break
			}
		}
		if group == "" {
			cycleNodes := make([]string, 0)
			for node := range topo {
				cycleNodes = append(cycleNodes, node)
			}
			slices.Sort(cycleNodes)
			return nil, fmt.Errorf("invalid graph: cycle detected in graph: %v", cycleNodes)
		}
		delete(topo, group)

		// remove and expand the group for every dependent
		for k, deps := range topo {
			if slices.Contains(deps, group) {
				// remove it from the group and copy the value to the expansion
				expansion[k] = append(expansion[k], expansion[group]...)
				slices.Sort(expansion[k])
				expansion[k] = slices.Compact(expansion[k])

				// remove group from deps
				x := 0
				for _, dep := range deps {
					if dep == group {
						// remove
					} else {
						deps[x] = dep
						x++
					}
				}
				deps = deps[:x]
				topo[k] = deps
			}
		}
	}

	// pass 3, rewrite pairings
	pairings := make([]Pair[NodeId, NodeId], 0)
	for _, pair := range parsedPairings {
		x := make([]NodeId, 0)
		if slices.Contains(nodes, pair.V1) {
			x = append(x, NodeId(pair.V1))
		} else {
			for _, exp := range expansion[pair.V1] {
				x = append(x, NodeId(exp))
			}
		}
		y := make([]NodeId, 0)
		if slices.Contains(nodes, pair.V2) {
			y = append(y, NodeId(pair.V2))
		} else {
			for _, exp := range expansion[pair.V2] {
				y = append(y, NodeId(exp))
			}
		}
		for _, x1 := range x {
			for _, y1 := range y {
				if x1 != y1 {
					pairings = append(pairings, MakeSortedPair(x1, y1))
				}
			}
		}
		SortPairs(pairings)
		pairings = slices.Compact(pairings)
	}
	return pairings, nil
}

func MakeSortedPair[T cmp.Ordered](a, b T) Pair[T, T] {
	if a < b {
		return Pair[T, T]{a, b}
	} else {
		return Pair[T, T]{b, a}
	}
}

func (e *CentralCfg) GetPeers(curId NodeId) []NodeId {
	allNodes := make([]string, 0)
	for _, node := range e.Routers {
		allNodes = append(allNodes, string(node.Id))
	}
	for _, node := range e.Clients {
		allNodes = append(allNodes, string(node.Id))
	}
	graph, err := ParseGraph(e.Graph, allNodes)
	if err != nil {
		panic(err)
	}
	nodes := make([]NodeId, 0)
	for _, edge := range graph {
		var neighNode NodeId
		if edge.V1 == curId {
			neighNode = edge.V2
		}
		if edge.V2 == curId {
			neighNode = edge.V1
		}
		if neighNode != curId && neighNode != "" {
			nodes = append(nodes, neighNode)
		}
	}
	return nodes
}

func (e *CentralCfg) FindNodeBy(pkey NyPublicKey) *NodeId {
	for _, n := range e.Routers {
		if n.PubKey == pkey {
			return &n.Id
		}
	}
	for _, n := range e.Clients {
		if n.PubKey == pkey {
			return &n.Id
		}
	}
	return nil
}

func ExpandCentralConfig(cfg *CentralCfg) {
	// compatibility & convenience: advertise address as a host address (/32 or /128)
	for idx, node := range cfg.Routers {
		expandNodeAddresses(&node.NodeCfg)
		cfg.Routers[idx] = node
	}
	for idx, node := range cfg.Clients {
		expandNodeAddresses(&node.NodeCfg)
		cfg.Clients[idx] = node
	}
}

func expandNodeAddresses(node *NodeCfg) {
	prefixes := make(map[netip.Prefix]struct{}, len(node.Prefixes))
	for _, prefix := range node.Prefixes {
		prefixes[prefix.GetPrefix()] = struct{}{}
	}
	for _, addr := range node.Addresses {
		prefix := AddrToPrefix(addr)
		if _, ok := prefixes[prefix]; ok {
			continue
		}
		advAddress := StaticPrefixHealth{
			Prefix: prefix,
			Metric: 0,
		}
		node.Prefixes = append([]PrefixHealthWrapper{{&advAddress}}, node.Prefixes...)
		prefixes[prefix] = struct{}{}
	}
}

func (e *CentralCfg) IsRouter(node NodeId) bool {
	idx := slices.IndexFunc(e.Routers, func(cfg RouterCfg) bool {
		return cfg.Id == node
	})
	return idx != -1
}

func (e *CentralCfg) IsClient(node NodeId) bool {
	idx := slices.IndexFunc(e.Clients, func(cfg ClientCfg) bool {
		return cfg.Id == node
	})
	return idx != -1
}

func (e *CentralCfg) IsNode(node NodeId) bool {
	return e.IsRouter(node) || e.IsClient(node)
}

func (e *CentralCfg) GetNode(node NodeId) NodeCfg {
	val := e.TryGetNode(node)
	if val == nil {
		panic("node " + string(node) + " not found")
	}
	return *val
}

func (e *CentralCfg) TryGetNode(node NodeId) *NodeCfg {
	idx := slices.IndexFunc(e.Routers, func(cfg RouterCfg) bool {
		return cfg.Id == node
	})
	if idx == -1 {
		idx = slices.IndexFunc(e.Clients, func(cfg ClientCfg) bool {
			return cfg.Id == node
		})
		if idx == -1 {
			return nil
		}
		return &e.Clients[idx].NodeCfg
	}
	return &e.Routers[idx].NodeCfg
}

func (e *CentralCfg) GetRouter(node NodeId) RouterCfg {
	idx := slices.IndexFunc(e.Routers, func(cfg RouterCfg) bool {
		return cfg.Id == node
	})
	if idx == -1 {
		panic("router " + string(node) + " not found")
	}

	return e.Routers[idx]
}

func (e *CentralCfg) GetClient(node NodeId) ClientCfg {
	idx := slices.IndexFunc(e.Clients, func(cfg ClientCfg) bool {
		return cfg.Id == node
	})
	if idx == -1 {
		panic("client " + string(node) + " not found")
	}

	return e.Clients[idx]
}
