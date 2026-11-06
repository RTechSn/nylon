package state

import (
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

func hopStr(v uint32) *uint32 { return &v }

func hopBool(v bool) *bool { return &v }

// TestHopModeStrategyParsingRoundtrip pins the YAML surface of the global
// `obf:` block — the named strategy map nested under `obf.strategy` — and
// its marshal/unmarshal roundtrip through CentralCfg.
func TestHopModeStrategyParsingRoundtrip(t *testing.T) {
	const centralYaml = `
obf:
  strategy:
    hopping:
      ports: 40000-50000
      port_hopping_mode: timed
      port_hopping:
        period_seconds: 300
        period_jitter_pct: 15
        cooldown_seconds: 60
    awg_main:
      ports: "40000"
      jc: 5
      jmin: 250
      jmax: 800
      i1: "aabbcc"
`
	var central CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(centralYaml), &central, yaml.Strict()); err != nil {
		t.Fatalf("central yaml: %v", err)
	}
	if len(central.ObfStrategies()) != 2 {
		t.Fatalf("strategies = %d, want 2", len(central.ObfStrategies()))
	}
	h := central.ObfStrategies()["hopping"]
	if h.PortHoppingMode != HopModeTimed {
		t.Errorf("hopping port_hopping_mode = %q, want %q", h.PortHoppingMode, HopModeTimed)
	}
	if h.PortHopping == nil || h.PortHopping.PeriodSeconds == nil || *h.PortHopping.PeriodSeconds != 300 {
		t.Fatalf("period_seconds not parsed: %+v", h.PortHopping)
	}
	if h.PortHopping.PeriodJitterPct == nil || *h.PortHopping.PeriodJitterPct != 15 {
		t.Fatalf("period_jitter_pct not parsed: %+v", h.PortHopping)
	}
	a := central.ObfStrategies()["awg_main"]
	if a.Ports != "40000" || a.I1 != "aabbcc" {
		t.Errorf("awg_main not parsed: %+v", a)
	}
	if a.Jc == nil || *a.Jc != 5 || a.Jmin == nil || *a.Jmin != 250 || a.Jmax == nil || *a.Jmax != 800 {
		t.Errorf("awg_main junk trio not parsed: %+v", a)
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
	h2 := central2.ObfStrategies()["hopping"]
	if h2.PortHoppingMode != HopModeTimed || h2.PortHopping == nil || h2.PortHopping.PeriodSeconds == nil || *h2.PortHopping.PeriodSeconds != 300 {
		t.Errorf("hop policy lost in roundtrip: %+v", h2)
	}
	a2 := central2.ObfStrategies()["awg_main"]
	if a2.Ports != "40000" || a2.I1 != "aabbcc" || a2.Jc == nil || *a2.Jc != 5 || a2.Jmin == nil || *a2.Jmin != 250 || a2.Jmax == nil || *a2.Jmax != 800 {
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
  strategy:
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
	hop := central.ObfStrategies()["hop"]
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

// TestObfBlockRejectsLegacyShapes pins the migration contract at the YAML
// surface: the first reform draft's top-level `awg_profile:` key, and strategy
// entries placed directly under `obf:` (without the `strategy:` nesting), fail
// strict central decoding loudly instead of silently dropping.
func TestObfBlockRejectsLegacyShapes(t *testing.T) {
	for name, src := range map[string]string{
		"round-1 top-level awg_profile key": `
awg_profile:
  s1: 32
  h1:
    min: 100
    max: 5000000
`,
		"strategy directly under obf": `
obf:
  hopping:
    ports: "40000"
`,
	} {
		t.Run(name, func(t *testing.T) {
			var cfg CentralCfg
			err := yaml.UnmarshalWithOptions([]byte(src), &cfg, yaml.Strict())
			if err == nil {
				t.Fatalf("legacy shape must fail strict decoding, got nil (cfg=%+v)", cfg)
			}
		})
	}
}

// TestStrategyJunkCoherence pins the junk rule: the strategies a node uses
// must agree on one junk configuration — the AWG 2.0 device emits one junk
// stream (jc/jmin/jmax) and prepends one I-packet set to every handshake
// toward every peer.
func TestStrategyJunkCoherence(t *testing.T) {
	strats := func(a, b string) map[string]*ObfStrategy {
		return map[string]*ObfStrategy{
			"awg":     {Ports: "40000", Jc: hopStr(5), Jmin: hopStr(250), Jmax: hopStr(800), I1: a, I2: b},
			"hopping": {Ports: "40000-50000"},
			"vanilla": {Ports: "51820"},
		}
	}

	// one junk set among the used strategies: fine
	junk, src, err := EffectiveStrategyJunk(strats("aabb", "ccdd"), []string{"awg", "hopping"})
	if err != nil || src != "awg" {
		t.Fatalf("single junk set: src=%q err=%v", src, err)
	}
	if junk.Jc != 5 || junk.Jmin != 250 || junk.Jmax != 800 || junk.I[0] != "aabb" || junk.I[1] != "ccdd" {
		t.Fatalf("resolved junk wrong: %+v", junk)
	}

	// two different i-sets both used: rejected
	_, _, err = EffectiveStrategyJunk(map[string]*ObfStrategy{
		"awg":  {Ports: "40000", I1: "aabb"},
		"awg2": {Ports: "40001", I1: "ccdd"},
	}, []string{"awg", "awg2"})
	if err == nil || !strings.Contains(err.Error(), "define different i1..i5") {
		t.Fatalf("conflicting i-sets must be rejected, got: %v", err)
	}

	// two different junk trios both used: rejected
	_, _, err = EffectiveStrategyJunk(map[string]*ObfStrategy{
		"awg":  {Ports: "40000", Jc: hopStr(5), Jmin: hopStr(250), Jmax: hopStr(800)},
		"awg2": {Ports: "40001", Jc: hopStr(7), Jmin: hopStr(250), Jmax: hopStr(800)},
	}, []string{"awg", "awg2"})
	if err == nil || !strings.Contains(err.Error(), "define different jc (5 vs 7)") {
		t.Fatalf("conflicting junk trios must be rejected, got: %v", err)
	}

	// identical junk across strategies: fine (the second strategy inherits)
	junk, src, err = EffectiveStrategyJunk(map[string]*ObfStrategy{
		"awg":  {Ports: "40000", Jc: hopStr(5), Jmin: hopStr(250), Jmax: hopStr(800), I1: "aabb"},
		"awg2": {Ports: "40001", Jc: hopStr(5), Jmin: hopStr(250), Jmax: hopStr(800)},
	}, []string{"awg", "awg2"})
	if err != nil || src != "awg" || junk.Jc != 5 || junk.I[0] != "aabb" {
		t.Fatalf("identical junk trios: src=%q junk=%+v err=%v", src, junk, err)
	}

	// unused strategies never restrict the used set
	_, _, err = EffectiveStrategyJunk(map[string]*ObfStrategy{
		"awg":  {Ports: "40000", I1: "aabb"},
		"awg2": {Ports: "40001", I1: "ccdd"},
	}, []string{"awg"})
	if err != nil {
		t.Fatalf("unused strategy must not restrict: %v", err)
	}

	// the central validator catches it across every router endpoint
	central := &CentralCfg{
		Obf: &CentralObf{StrategyMode: StrategyModeFixed, Strategy: map[string]*ObfStrategy{
			"awg":  {Ports: "40000", I1: "aabb"},
			"awg2": {Ports: "40001", I1: "ccdd"},
		}},
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "r1"}, Endpoints: []string{"1.2.3.4[awg]"}},
			{NodeCfg: NodeCfg{Id: "r2"}, Endpoints: []string{"1.2.3.5[awg2]"}},
		},
	}
	if err := CentralConfigValidator(central); err == nil || !strings.Contains(err.Error(), "define different i1..i5") {
		t.Errorf("mesh-wide i-set conflict: err = %v, want coherence error", err)
	}

	central = &CentralCfg{
		Obf: &CentralObf{StrategyMode: StrategyModeFixed, Strategy: map[string]*ObfStrategy{
			"awg":  {Ports: "40000", Jc: hopStr(5), Jmin: hopStr(250), Jmax: hopStr(800)},
			"awg2": {Ports: "40001", Jc: hopStr(6), Jmin: hopStr(250), Jmax: hopStr(800)},
		}},
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "r1"}, Endpoints: []string{"1.2.3.4[awg]"}},
			{NodeCfg: NodeCfg{Id: "r2"}, Endpoints: []string{"1.2.3.5[awg2]"}},
		},
	}
	if err := CentralConfigValidator(central); err == nil || !strings.Contains(err.Error(), "define different jc") {
		t.Errorf("mesh-wide jc conflict: err = %v, want coherence error", err)
	}
}

// TestValidateStrategyJunkMatrix walks the per-strategy junk trio checks:
// the size range travels with the count, and the range must be ordered.
func TestValidateStrategyJunkMatrix(t *testing.T) {
	viaValidator := func(s *ObfStrategy) error {
		return ValidateObfStrategies(&CentralCfg{Obf: &CentralObf{Strategy: map[string]*ObfStrategy{"hop": s}}})
	}
	cases := []struct {
		name    string
		s       *ObfStrategy
		wantErr string // "" = expect success
	}{
		{"no junk at all", &ObfStrategy{Ports: "40000"}, ""},
		{"valid trio", &ObfStrategy{Ports: "40000", Jc: hopStr(5), Jmin: hopStr(250), Jmax: hopStr(800)}, ""},
		{"equal bounds (fixed-length junk)", &ObfStrategy{Ports: "40000", Jc: hopStr(5), Jmin: hopStr(250), Jmax: hopStr(250)}, ""},
		{"jc without range", &ObfStrategy{Ports: "40000", Jc: hopStr(5)}, "jc requires the jmin/jmax junk size range"},
		{"jmin only", &ObfStrategy{Ports: "40000", Jc: hopStr(5), Jmin: hopStr(250)}, "jc requires the jmin/jmax junk size range"},
		{"jmax only", &ObfStrategy{Ports: "40000", Jc: hopStr(5), Jmax: hopStr(800)}, "jc requires the jmin/jmax junk size range"},
		{"range without jc", &ObfStrategy{Ports: "40000", Jmin: hopStr(250), Jmax: hopStr(800)}, "jmin/jmax are set but jc is not positive"},
		{"range with explicit zero jc", &ObfStrategy{Ports: "40000", Jc: hopStr(0), Jmin: hopStr(250), Jmax: hopStr(800)}, "jmin/jmax are set but jc is not positive"},
		{"inverted range", &ObfStrategy{Ports: "40000", Jc: hopStr(5), Jmin: hopStr(800), Jmax: hopStr(250)}, "must not exceed jmax"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := viaValidator(tc.s)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestNodeUsedStrategies pins the used-set derivation: tags of every router
// endpoint (own + peers'), untagged endpoints expanding to all strategies.
func TestNodeUsedStrategies(t *testing.T) {
	central := &CentralCfg{
		Obf: &CentralObf{Strategy: map[string]*ObfStrategy{
			"awg":     {Ports: "40000"},
			"hopping": {Ports: "40000-50000"},
			"vanilla": {Ports: "51820"},
		}},
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

// TestValidateStrategyModeMatrix walks the obf.strategy_mode validation:
// implemented modes pass, the reserved `rated` gets the not-implemented
// error, unknown values are rejected, and the mode is REQUIRED when the mesh
// defines more than one strategy and dead config when it defines none.
func TestValidateStrategyModeMatrix(t *testing.T) {
	// the value validator itself
	for _, mode := range StrategyModes() {
		if err := ValidateStrategyMode(mode); err != nil {
			t.Errorf("mode %q must validate: %v", mode, err)
		}
	}
	if err := ValidateStrategyMode(StrategyModeRated); err == nil || !strings.Contains(err.Error(), "reserved for a future release") {
		t.Errorf("rated must carry the reserved error, got: %v", err)
	}
	if err := ValidateStrategyMode("round-robin"); err == nil || !strings.Contains(err.Error(), "unknown strategy_mode") {
		t.Errorf("unknown mode must be rejected, got: %v", err)
	}

	twoStrats := func(mode string) *CentralCfg {
		return &CentralCfg{
			Obf: &CentralObf{StrategyMode: mode, Strategy: map[string]*ObfStrategy{
				"awg":  {Ports: "40000"},
				"awg2": {Ports: "40001"},
			}},
		}
	}

	// required when the mesh defines more than one strategy
	if err := ValidateObfStrategies(twoStrats("")); err == nil || !strings.Contains(err.Error(), "strategy_mode is required") {
		t.Errorf("two strategies without a mode must be rejected, got: %v", err)
	}
	for _, mode := range StrategyModes() {
		if err := ValidateObfStrategies(twoStrats(mode)); err != nil {
			t.Errorf("two strategies with mode %q must validate: %v", mode, err)
		}
	}
	if err := ValidateObfStrategies(twoStrats(StrategyModeRated)); err == nil || !strings.Contains(err.Error(), "reserved for a future release") {
		t.Errorf("rated must be rejected even with two strategies, got: %v", err)
	}

	// one strategy: the mode is optional (every mode reduces to the one)
	oneStrat := func(mode string) *CentralCfg {
		return &CentralCfg{
			Obf: &CentralObf{StrategyMode: mode, Strategy: map[string]*ObfStrategy{
				"awg": {Ports: "40000"},
			}},
		}
	}
	if err := ValidateObfStrategies(oneStrat("")); err != nil {
		t.Errorf("one strategy without a mode must validate: %v", err)
	}
	for _, mode := range StrategyModes() {
		if err := ValidateObfStrategies(oneStrat(mode)); err != nil {
			t.Errorf("one strategy with mode %q must validate: %v", mode, err)
		}
	}

	// dead config: a mode without any strategies
	noStrats := &CentralCfg{Obf: &CentralObf{StrategyMode: StrategyModeRandom}}
	if err := ValidateObfStrategies(noStrats); err == nil || !strings.Contains(err.Error(), "strategy_mode is set but no obf strategies") {
		t.Errorf("mode without strategies must be rejected, got: %v", err)
	}
}

// TestObfStrategyModeResolution pins the runtime resolution: absent → fixed,
// and unknown/reserved values (a live-swapped config that slipped past
// validation) also resolve to fixed — the runtime never wedges on a bad
// value; validation owns the loud error.
func TestObfStrategyModeResolution(t *testing.T) {
	var nilCfg *CentralCfg
	if mode := nilCfg.ObfStrategyMode(); mode != StrategyModeFixed {
		t.Errorf("nil central config: mode = %q, want fixed", mode)
	}
	cases := []struct {
		set  string
		want string
	}{
		{"", StrategyModeFixed},
		{StrategyModeFixed, StrategyModeFixed},
		{StrategyModeRandom, StrategyModeRandom},
		{StrategyModeTrial, StrategyModeTrial},
		{StrategyModeRated, StrategyModeFixed},
		{"nonsense", StrategyModeFixed},
	}
	for _, tc := range cases {
		cfg := &CentralCfg{Obf: &CentralObf{StrategyMode: tc.set, Strategy: map[string]*ObfStrategy{
			"awg": {Ports: "40000"}, "awg2": {Ports: "40001"},
		}}}
		if mode := cfg.ObfStrategyMode(); mode != tc.want {
			t.Errorf("set %q: mode = %q, want %q", tc.set, mode, tc.want)
		}
	}
}

// TestStrategyModeRoundtrip pins the YAML surface: strategy_mode nests under
// the global obf block next to the strategy map and survives the
// marshal/unmarshal roundtrip.
func TestStrategyModeRoundtrip(t *testing.T) {
	const in = `
obf:
  s1: 32
  strategy_mode: trial
  strategy:
    awg:
      ports: "40000"
    awg2:
      ports: 50000-50100
`
	var central CentralCfg
	if err := yaml.UnmarshalWithOptions([]byte(in), &central, yaml.Strict()); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if central.Obf == nil || central.Obf.StrategyMode != StrategyModeTrial {
		t.Fatalf("strategy_mode not parsed: %+v", central.Obf)
	}
	if err := CentralConfigValidator(&central); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if mode := central.ObfStrategyMode(); mode != StrategyModeTrial {
		t.Fatalf("resolved mode = %q, want trial", mode)
	}
	out, err := yaml.Marshal(&central)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var central2 CentralCfg
	if err := yaml.UnmarshalWithOptions(out, &central2, yaml.Strict()); err != nil {
		t.Fatalf("re-unmarshal: %v (yaml: %s)", err, out)
	}
	if central2.Obf == nil || central2.Obf.StrategyMode != StrategyModeTrial {
		t.Fatalf("strategy_mode lost in roundtrip (yaml: %s): %+v", out, central2.Obf)
	}
}

// TestEndpointStrategyTagOrder pins the tag list as the operator's preference
// order: explicit tags expand in the WRITTEN order (the fixed mode pins the
// first as written), while untagged and wildcard endpoints expand to every
// defined strategy in sorted (map) order.
func TestEndpointStrategyTagOrder(t *testing.T) {
	m := map[string]*ObfStrategy{
		"alpha": {Ports: "40000"},
		"beta":  {Ports: "41000"},
		"gamma": {Ports: "42000"},
	}

	// written order preserved, not sorted
	spec, err := ParseEndpointSpec("hub.example.com[gamma,alpha,beta]")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tags, err := EndpointStrategyTags(spec, m)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	if len(tags) != 3 || tags[0] != "gamma" || tags[1] != "alpha" || tags[2] != "beta" {
		t.Fatalf("written order must be preserved, got %v", tags)
	}

	// untagged: every strategy, sorted
	spec, err = ParseEndpointSpec("hub.example.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tags, err = EndpointStrategyTags(spec, m)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	if len(tags) != 3 || tags[0] != "alpha" || tags[1] != "beta" || tags[2] != "gamma" {
		t.Fatalf("untagged must expand sorted, got %v", tags)
	}

	// wildcard: same as untagged
	spec, err = ParseEndpointSpec("hub.example.com[*]")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tags, err = EndpointStrategyTags(spec, m)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	if len(tags) != 3 || tags[0] != "alpha" || tags[1] != "beta" || tags[2] != "gamma" {
		t.Fatalf("wildcard must expand sorted, got %v", tags)
	}

	// unknown tag: rejected with the defined names
	spec, err = ParseEndpointSpec("hub.example.com[alpha,nope]")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := EndpointStrategyTags(spec, m); err == nil || !strings.Contains(err.Error(), "undefined obf strategy \"nope\"") {
		t.Fatalf("unknown tag must be rejected, got: %v", err)
	}
}
