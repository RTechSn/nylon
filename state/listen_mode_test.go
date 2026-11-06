package state

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// strategyFixture builds a central config whose node `a` advertises endpoints
// over the given strategies, plus the node config.
func strategyFixture(strategyPorts map[string]string, endpoints []string, mode string) (*CentralCfg, *LocalCfg) {
	strats := make(map[string]*ObfStrategy, len(strategyPorts))
	for name, ports := range strategyPorts {
		strats[name] = &ObfStrategy{Ports: ports}
	}
	key := GenerateKey()
	central := &CentralCfg{
		ObfStrategies: strats,
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "a", PubKey: key.Pubkey()}, Endpoints: endpoints},
		},
	}
	node := &LocalCfg{
		Port:       30000,
		ListenMode: mode,
		Key:        key,
		Id:         "a",
	}
	return central, node
}

func TestListenModeParsing(t *testing.T) {
	src := `
port: 30000
listen_mode: nftables
id: a
`
	var cfg LocalCfg
	if err := yaml.UnmarshalWithOptions([]byte(src), &cfg, yaml.Strict()); err != nil {
		t.Fatalf("node yaml: %v", err)
	}
	if cfg.ListenMode != "nftables" {
		t.Fatalf("listen_mode = %q, want nftables", cfg.ListenMode)
	}
	if !cfg.UsesNftListenMode() {
		t.Fatal("listen_mode: nftables must select the nftables mode")
	}
}

func TestListenModeDefaultsToSockets(t *testing.T) {
	if (&LocalCfg{}).EffectiveListenMode() != ListenModeSockets {
		t.Error("empty listen_mode defaults to sockets")
	}
	if (&LocalCfg{ListenMode: "sockets"}).EffectiveListenMode() != ListenModeSockets {
		t.Error("explicit sockets mode not effective")
	}
	if (&LocalCfg{}).UsesNftListenMode() {
		t.Error("default mode must not be nftables")
	}
}

func TestListenModeValidationMatrix(t *testing.T) {
	// unknown mode values are rejected
	central, node := strategyFixture(nil, nil, "iptables")
	if err := NodeConfigValidator(central, node); err == nil || !strings.Contains(err.Error(), "listen_mode") {
		t.Errorf("unknown listen_mode: err = %v, want listen_mode error", err)
	}

	// nftables without serving any strategy ports is meaningless
	central, node = strategyFixture(map[string]string{"hopping": "30000-31000"}, []string{"1.2.3.4:30001"}, "nftables")
	if err := NodeConfigValidator(central, node); err == nil || !strings.Contains(err.Error(), "requires the node to serve") {
		t.Errorf("nftables without strategy ports: err = %v, want meaningless-mode error", err)
	}

	// explicit sockets with nothing to serve is fine (it is the default)
	central, node = strategyFixture(map[string]string{"hopping": "30000-31000"}, []string{"1.2.3.4:30001"}, "sockets")
	if err := NodeConfigValidator(central, node); err != nil {
		t.Errorf("explicit sockets mode without strategy ports rejected: %v", err)
	}
}

// TestListenUnionCeiling walks the derived-listen-union ceiling: the union of
// ports over the strategies the node's own advertised endpoints name, with
// the in-daemon (N-socket) ceiling enforced on the DERIVED set in sockets mode
// and lifted in nftables mode.
func TestListenUnionCeiling(t *testing.T) {
	overCeiling := map[string]string{"hopping": "10000-60000"}
	underCeiling := map[string]string{"hopping": "30000-31000"}

	// sockets mode keeps the ceiling on the derived union
	central, node := strategyFixture(overCeiling, []string{"a.example.com[hopping]"}, "")
	if err := NodeConfigValidator(central, node); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("over-ceiling strategy union with default sockets mode: err = %v, want ceiling error", err)
	}
	central, node = strategyFixture(overCeiling, []string{"a.example.com[hopping]"}, "sockets")
	if err := NodeConfigValidator(central, node); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Errorf("over-ceiling strategy union with explicit sockets mode: err = %v, want ceiling error", err)
	}

	// nftables mode lifts the ceiling (arbitrarily wide unions)
	central, node = strategyFixture(overCeiling, []string{"a.example.com[hopping]"}, "nftables")
	if err := NodeConfigValidator(central, node); err != nil {
		t.Errorf("over-ceiling union rejected under nftables mode: %v", err)
	}

	// a node that does not advertise the wide strategy is not bound by it
	central, node = strategyFixture(overCeiling, []string{"a.example.com:30000"}, "")
	if err := NodeConfigValidator(central, node); err != nil {
		t.Errorf("wide strategy not advertised by the node must not restrict it: %v", err)
	}

	// under-ceiling unions pass in both modes
	central, node = strategyFixture(underCeiling, []string{"a.example.com[hopping]"}, "")
	if err := NodeConfigValidator(central, node); err != nil {
		t.Errorf("under-ceiling union rejected with sockets mode: %v", err)
	}
	central, node = strategyFixture(underCeiling, []string{"a.example.com[hopping]"}, "nftables")
	if err := NodeConfigValidator(central, node); err != nil {
		t.Errorf("under-ceiling union rejected with nftables mode: %v", err)
	}
}

// TestListenUnionDerivation pins which strategies a node's listen half binds:
// the union over the strategies its OWN advertised endpoints name (untagged =
// all), never strategies only other nodes advertise.
func TestListenUnionDerivation(t *testing.T) {
	strats := map[string]*ObfStrategy{
		"awg":     {Ports: "40000"},
		"hopping": {Ports: "40000-50000"},
		"vanilla": {Ports: "51820"},
	}

	// untagged advertised endpoint: every strategy's ports (merged; the
	// 50001-51819 gap keeps the vanilla strategy a separate range)
	union, err := ListenUnionRanges(&RouterCfg{Endpoints: []string{"hub.example.com"}}, strats)
	if err != nil {
		t.Fatal(err)
	}
	if got := RangesString(union); got != "40000-50000,51820" {
		t.Errorf("untagged union = %q, want merged 40000-50000,51820", got)
	}

	// wildcard endpoint: same union
	union, err = ListenUnionRanges(&RouterCfg{Endpoints: []string{"hub.example.com[*]"}}, strats)
	if err != nil {
		t.Fatal(err)
	}
	if got := RangesString(union); got != "40000-50000,51820" {
		t.Errorf("wildcard union = %q, want merged 40000-50000,51820", got)
	}

	// tagged: only the named strategies, merged
	union, err = ListenUnionRanges(&RouterCfg{Endpoints: []string{"hub.example.com[hopping,awg]"}}, strats)
	if err != nil {
		t.Fatal(err)
	}
	if got := RangesString(union); got != "40000-50000" {
		t.Errorf("tagged union = %q, want 40000-50000", got)
	}

	// disjoint strategies stay disjoint ranges
	union, err = ListenUnionRanges(&RouterCfg{Endpoints: []string{"hub.example.com[vanilla]"}}, strats)
	if err != nil {
		t.Fatal(err)
	}
	if got := RangesString(union); got != "51820" {
		t.Errorf("vanilla union = %q, want 51820", got)
	}

	// raw endpoints contribute nothing; a client (no endpoints) binds nothing
	union, err = ListenUnionRanges(&RouterCfg{Endpoints: []string{"hub.example.com:51820"}}, strats)
	if err != nil || len(union) != 0 {
		t.Errorf("raw endpoint must contribute no listen ports: %v %v", union, err)
	}
	union, err = ListenUnionRanges(nil, strats)
	if err != nil || len(union) != 0 {
		t.Errorf("no advertised endpoints must yield no listen ports: %v %v", union, err)
	}

	// unknown strategy tag on an advertised endpoint is an error
	union, err = ListenUnionRanges(&RouterCfg{Endpoints: []string{"hub.example.com[nope]"}}, strats)
	if err == nil || !strings.Contains(err.Error(), "undefined obf strategy") {
		t.Errorf("unknown tag: err = %v, want undefined-strategy error", err)
	}
}
