package state

import (
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

func hopStr(v uint32) *uint32 { return &v }

func hopBool(v bool) *bool { return &v }

// TestHopModeStrategyParsingRoundtrip pins the YAML surface of the per-strategy
// rotation policy in the central `obf:` block, and its marshal/unmarshal
// roundtrip through CentralCfg.
func TestHopModeStrategyParsingRoundtrip(t *testing.T) {
	const centralYaml = `
obf:
  hopping:
    ports: 40000-50000
    port_hopping_mode: timed
    port_hopping:
      period_seconds: 300
      period_jitter_pct: 15
      cooldown_seconds: 60
  awg_main:
    ports: "40000"
    protocol: quic
    i1: "aabbcc"
`
	var central CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(centralYaml), &central, yaml.Strict()); err != nil {
		t.Fatalf("central yaml: %v", err)
	}
	if len(central.ObfStrategies) != 2 {
		t.Fatalf("strategies = %d, want 2", len(central.ObfStrategies))
	}
	h := central.ObfStrategies["hopping"]
	if h.PortHoppingMode != HopModeTimed {
		t.Errorf("hopping port_hopping_mode = %q, want %q", h.PortHoppingMode, HopModeTimed)
	}
	if h.PortHopping == nil || h.PortHopping.PeriodSeconds == nil || *h.PortHopping.PeriodSeconds != 300 {
		t.Fatalf("period_seconds not parsed: %+v", h.PortHopping)
	}
	if h.PortHopping.PeriodJitterPct == nil || *h.PortHopping.PeriodJitterPct != 15 {
		t.Fatalf("period_jitter_pct not parsed: %+v", h.PortHopping)
	}
	a := central.ObfStrategies["awg_main"]
	if a.Ports != "40000" || a.Protocol != "quic" || a.I1 != "aabbcc" {
		t.Errorf("awg_main not parsed: %+v", a)
	}

	// the strategy block must survive a marshal/unmarshal roundtrip
	out, err := yaml.Marshal(&central)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var central2 CentralCfg
	if err := yaml.UnmarshalWithOptions(out, &central2, yaml.Strict()); err != nil {
		t.Fatalf("re-unmarshal: %v (yaml: %s)", err, out)
	}
	h2 := central2.ObfStrategies["hopping"]
	if h2.PortHoppingMode != HopModeTimed || h2.PortHopping == nil || h2.PortHopping.PeriodSeconds == nil || *h2.PortHopping.PeriodSeconds != 300 {
		t.Errorf("hop policy lost in roundtrip: %+v", h2)
	}
	a2 := central2.ObfStrategies["awg_main"]
	if a2.Ports != "40000" || a2.I1 != "aabbcc" || a2.Protocol != "quic" {
		t.Errorf("strategy fields lost in roundtrip: %+v", a2)
	}
}

// TestValidateHopPolicyCfgMatrix walks the full validation matrix of one
// strategy's hop policy block (unchanged semantics, new location).
func TestValidateHopPolicyCfgMatrix(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		cfg     *PortHoppingCfg
		wantErr string // "" = expect success
	}{
		{"no policy at all", "", nil, ""},
		{"static without block", HopModeStatic, nil, ""},
		{"static with ignored budget", HopModeStatic, &PortHoppingCfg{BudgetPackets: hopStr(12)}, ""},
		{"reactive without block", HopModeReactive, nil, ""},
		{"reactive with ignored budget", HopModeReactive, &PortHoppingCfg{BudgetPackets: hopStr(12)}, ""},
		{"proactive without block", HopModeProactive, nil, "requires port_hopping.budget_packets"},
		{"proactive without budget", HopModeProactive, &PortHoppingCfg{CooldownSeconds: hopStr(5)}, "requires port_hopping.budget_packets"},
		{"proactive with budget", HopModeProactive, &PortHoppingCfg{BudgetPackets: hopStr(12)}, ""},
		{"proactive with legacy auto_recycle", HopModeProactive, &PortHoppingCfg{BudgetPackets: hopStr(12), AutoRecycle: hopBool(true)}, "auto_recycle was replaced by recycle_seconds"},
		{"timed without block", HopModeTimed, nil, "requires port_hopping.period_seconds"},
		{"timed without period", HopModeTimed, &PortHoppingCfg{BudgetPackets: hopStr(12)}, "requires port_hopping.period_seconds"},
		{"timed with period", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(300)}, ""},
		{"timed with period and jitter", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(300), PeriodJitterPct: hopStr(25)}, ""},
		{"timed with zero period", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(0)}, "period_seconds must be greater than 0"},
		{"timed with excess jitter", HopModeTimed, &PortHoppingCfg{PeriodSeconds: hopStr(300), PeriodJitterPct: hopStr(51)}, "period_jitter_pct must be at most 50"},
		{"knobs without mode (migration guard)", "", &PortHoppingCfg{BudgetPackets: hopStr(12)}, "port_hopping_mode is not set"},
		{"unknown mode", "surprise", nil, "unknown port_hopping_mode"},
		{"reserved dynamic", HopModeDynamic, nil, "reserved for a future release"},
		{"reserved auto", HopModeAuto, nil, "reserved for a future release"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHopPolicyCfg(tc.mode, tc.cfg, "obf strategy hop_test")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestRetiredHopFieldsRejected pins the retired node- and router-level hop
// fields: they still parse (so a pre-reform config is detected, not silently
// reinterpreted) but fail validation with the migration pointer.
func TestRetiredHopFieldsRejected(t *testing.T) {
	base := func() *LocalCfg {
		return &LocalCfg{Id: "node1", Port: 30000, Key: [32]byte{1}}
	}

	node := base()
	node.PortHopping = &PortHoppingCfg{BudgetPackets: hopStr(12)}
	if err := NodeConfigValidator(nil, node); err == nil || !strings.Contains(err.Error(), "moved into obf strategies") {
		t.Errorf("retired node port_hopping: err = %v, want migration error", err)
	}

	node = base()
	node.PortHoppingMode = HopModeTimed
	if err := NodeConfigValidator(nil, node); err == nil || !strings.Contains(err.Error(), "moved into obf strategies") {
		t.Errorf("retired node port_hopping_mode: err = %v, want migration error", err)
	}

	node = base()
	node.ListenPorts = "30000-40000"
	if err := NodeConfigValidator(nil, node); err == nil || !strings.Contains(err.Error(), "listen_ports moved into obf strategies") {
		t.Errorf("retired node listen_ports: err = %v, want migration error", err)
	}

	central := &CentralCfg{
		Routers: []RouterCfg{{
			NodeCfg:         NodeCfg{Id: "node1"},
			PortHoppingMode: HopModeProactive,
			PortHopping:     &PortHoppingCfg{BudgetPackets: hopStr(12)},
		}},
	}
	if err := CentralConfigValidator(central); err == nil || !strings.Contains(err.Error(), "moved into obf strategies") {
		t.Errorf("retired router hop fields: err = %v, want migration error", err)
	}

	central = &CentralCfg{
		Routers: []RouterCfg{{
			NodeCfg: NodeCfg{Id: "node1", Obf: &ObfPeerParams{I1: "aabb"}},
		}},
	}
	if err := CentralConfigValidator(central); err == nil || !strings.Contains(err.Error(), "per-node obf block moved into central obf strategies") {
		t.Errorf("retired per-node obf: err = %v, want migration error", err)
	}
}

// TestResolveStrategyHopPolicy pins the per-strategy resolution: defaults,
// knob resolution, and the static default for a knobless strategy.
func TestResolveStrategyHopPolicy(t *testing.T) {
	p := ResolveStrategyHopPolicy(nil)
	if p.Mode != HopModeStatic || p.Budget != 12 || p.JitterPct != 10 {
		t.Errorf("nil strategy policy: %+v", p)
	}

	p = ResolveStrategyHopPolicy(&ObfStrategy{})
	if p.Mode != HopModeStatic {
		t.Errorf("knobless strategy must resolve static: %+v", p)
	}

	p = ResolveStrategyHopPolicy(&ObfStrategy{
		PortHoppingMode: HopModeTimed,
		PortHopping:     &PortHoppingCfg{PeriodSeconds: hopStr(60), PeriodJitterPct: hopStr(20)},
	})
	if p.Mode != HopModeTimed || p.Period != 60*time.Second || p.JitterPct != 20 {
		t.Errorf("timed strategy policy: %+v", p)
	}

	p = ResolveStrategyHopPolicy(&ObfStrategy{
		PortHoppingMode: HopModeTimed,
		PortHopping:     &PortHoppingCfg{PeriodSeconds: hopStr(5)},
	})
	if p.Period != 5*time.Second || p.JitterPct != 10 {
		t.Errorf("timed knob resolution (default jitter): %+v", p)
	}

	p = ResolveStrategyHopPolicy(&ObfStrategy{
		PortHoppingMode: HopModeProactive,
		PortHopping:     &PortHoppingCfg{BudgetPackets: hopStr(40)},
	})
	if p.Mode != HopModeProactive || p.Budget != 40 {
		t.Errorf("proactive strategy policy: %+v", p)
	}
}

// TestValidateHopMode covers the mode-name classifier directly.
func TestValidateHopMode(t *testing.T) {
	for _, m := range HopModes() {
		if err := ValidateHopMode(m); err != nil {
			t.Errorf("implemented mode %q rejected: %v", m, err)
		}
	}
	for _, m := range ReservedHopModes() {
		err := ValidateHopMode(m)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("reserved mode %q: err = %v, want reserved error", m, err)
		}
	}
	if err := ValidateHopMode("fast"); err == nil || !strings.Contains(err.Error(), "unknown port_hopping_mode") {
		t.Errorf("unknown mode: err = %v, want unknown error", err)
	}
}

// TestStrategyRecycleSeconds pins the recycle_seconds knob inside a strategy:
// parsed there, defaulted off, resolved into the policy's rate limit, and the
// interim auto_recycle key still rejected with an actionable error.
func TestStrategyRecycleSeconds(t *testing.T) {
	const centralYaml = `
obf:
  hop:
    ports: 30000-30010
    port_hopping_mode: proactive
    port_hopping:
      budget_packets: 24
      recycle_seconds: 7
`
	var central CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(centralYaml), &central, yaml.Strict()); err != nil {
		t.Fatalf("central yaml: %v", err)
	}
	hop := central.ObfStrategies["hop"]
	if hop.PortHopping == nil || hop.PortHopping.RecycleSeconds == nil || *hop.PortHopping.RecycleSeconds != 7 {
		t.Fatalf("recycle_seconds not parsed: %+v", hop.PortHopping)
	}
	p := ResolveStrategyHopPolicy(hop)
	if p.RecycleMinInterval != 7*time.Second {
		t.Fatalf("recycle_seconds not resolved: %+v", p)
	}
	if p.Cooldown != 3*time.Minute {
		t.Fatalf("default cooldown drifted: %v", p.Cooldown)
	}

	// default and explicit zero: off
	if p := (&PortHoppingCfg{}).Resolve(); p.RecycleMinInterval != 0 {
		t.Fatal("recycle_seconds must default to off")
	}
	if p := (&PortHoppingCfg{RecycleSeconds: hopStr(0)}).Resolve(); p.RecycleMinInterval != 0 {
		t.Fatal("recycle_seconds: 0 must resolve to off")
	}
	if p := DefaultPortHoppingPolicy(); p.RecycleMinInterval != 0 {
		t.Fatal("the default policy must not auto-recycle")
	}

	// the interim auto_recycle key still fails with the replacement named
	err := ValidateHopPolicyCfg(HopModeProactive, &PortHoppingCfg{BudgetPackets: hopStr(12), AutoRecycle: hopBool(true)}, "obf strategy hop")
	if err == nil || !strings.Contains(err.Error(), "auto_recycle was replaced by recycle_seconds") {
		t.Fatalf("legacy auto_recycle must fail validation with the replacement named, got: %v", err)
	}
}

// TestStrategyIPacketsCoherence pins the i-set rule: the strategies a node
// uses must agree on one non-empty i-set (the AWG 2.0 device prepends one
// junk set to every handshake toward every peer).
func TestStrategyIPacketsCoherence(t *testing.T) {
	strats := func(a, b string) map[string]*ObfStrategy {
		return map[string]*ObfStrategy{
			"awg":     {Ports: "40000", I1: a, I2: b},
			"hopping": {Ports: "40000-50000"},
			"vanilla": {Ports: "51820"},
		}
	}

	// one i-set among the used strategies: fine
	_, src, err := EffectiveStrategyIPackets(strats("aabb", "ccdd"), []string{"awg", "hopping"})
	if err != nil || src != "awg" {
		t.Fatalf("single i-set: src=%q err=%v", src, err)
	}

	// two different i-sets both used: rejected
	_, _, err = EffectiveStrategyIPackets(map[string]*ObfStrategy{
		"awg":  {Ports: "40000", I1: "aabb"},
		"awg2": {Ports: "40001", I1: "ccdd"},
	}, []string{"awg", "awg2"})
	if err == nil || !strings.Contains(err.Error(), "define different i1..i5") {
		t.Fatalf("conflicting i-sets must be rejected, got: %v", err)
	}

	// identical i-sets across strategies: fine
	_, src, err = EffectiveStrategyIPackets(map[string]*ObfStrategy{
		"awg":  {Ports: "40000", I1: "aabb", I5: "ff00"},
		"awg2": {Ports: "40001", I1: "aabb", I5: "ff00"},
	}, []string{"awg", "awg2"})
	if err != nil || src != "awg" {
		t.Fatalf("identical i-sets: src=%q err=%v", src, err)
	}

	// unused strategies never restrict the used set
	_, _, err = EffectiveStrategyIPackets(map[string]*ObfStrategy{
		"awg":  {Ports: "40000", I1: "aabb"},
		"awg2": {Ports: "40001", I1: "ccdd"},
	}, []string{"awg"})
	if err != nil {
		t.Fatalf("unused strategy must not restrict: %v", err)
	}

	// the central validator catches it across every router endpoint
	central := &CentralCfg{
		ObfStrategies: map[string]*ObfStrategy{
			"awg":  {Ports: "40000", I1: "aabb"},
			"awg2": {Ports: "40001", I1: "ccdd"},
		},
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "r1"}, Endpoints: []string{"1.2.3.4[awg]"}},
			{NodeCfg: NodeCfg{Id: "r2"}, Endpoints: []string{"1.2.3.5[awg2]"}},
		},
	}
	if err := CentralConfigValidator(central); err == nil || !strings.Contains(err.Error(), "define different i1..i5") {
		t.Errorf("mesh-wide i-set conflict: err = %v, want coherence error", err)
	}
}

// TestNodeUsedStrategies pins the used-set derivation: tags of every router
// endpoint (own + peers'), untagged endpoints expanding to all strategies.
func TestNodeUsedStrategies(t *testing.T) {
	central := &CentralCfg{
		ObfStrategies: map[string]*ObfStrategy{
			"awg":     {Ports: "40000"},
			"hopping": {Ports: "40000-50000"},
			"vanilla": {Ports: "51820"},
		},
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "hub"}, Endpoints: []string{"hub.example.com[hopping,vanilla]"}},
			{NodeCfg: NodeCfg{Id: "r2"}, Endpoints: []string{"r2.example.com"}},
		},
	}
	used := NodeUsedStrategies(central, "hub")
	want := "awg,hopping,vanilla" // own tagged {hopping,vanilla} + r2's untagged = all
	if strings.Join(used, ",") != want {
		t.Errorf("used = %v, want %s", used, want)
	}

	// no strategies defined: no used set
	used = NodeUsedStrategies(&CentralCfg{Routers: []RouterCfg{{NodeCfg: NodeCfg{Id: "hub"}, Endpoints: []string{"hub.example.com"}}}}, "hub")
	if len(used) != 0 {
		t.Errorf("strategyless mesh must yield no used set, got %v", used)
	}
}
