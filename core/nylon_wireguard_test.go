package core

import (
	"strings"
	"testing"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

func testObfProfile() *state.ObfProfile {
	return &state.ObfProfile{
		S1: 30,
		S2: 25,
		S3: 15,
		S4: 10,
		H1: state.ObfHeaderRange{Min: 100, Max: 200},
		H2: state.ObfHeaderRange{Min: 300, Max: 400},
		H3: state.ObfHeaderRange{Min: 500, Max: 600},
		H4: state.ObfHeaderRange{Min: 700, Max: 800},
	}
}

func TestObfDeviceIPCNilProfileEmitsCompatDefaults(t *testing.T) {
	want := "h1=1-1\nh2=2-2\nh3=3-3\nh4=4-4\n"
	if got := obfDeviceIPC(nil, state.StrategyJunk{}); got != want {
		t.Errorf("obfDeviceIPC(nil, empty) = %q, want %q", got, want)
	}
}

func TestObfDeviceIPCFullProfile(t *testing.T) {
	want := "s1=30\ns2=25\ns3=15\ns4=10\n" +
		"h1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\n"
	if got := obfDeviceIPC(testObfProfile(), state.StrategyJunk{}); got != want {
		t.Errorf("obfDeviceIPC(profile, empty junk) = %q, want %q", got, want)
	}
}

func TestObfDeviceIPCJunkParams(t *testing.T) {
	// the junk configuration now arrives as the device-global StrategyJunk
	// resolved from the node's used obf strategies (see strategyJunkSet)
	junk := state.StrategyJunk{
		Jc:   2,
		Jmin: 50,
		Jmax: 90,
		I:    [5]string{"16-28-100-4", "", "150-3-1", "", ""},
	}

	t.Run("junk lines precede the dialect lines on a compat profile", func(t *testing.T) {
		want := "jc=2\njmin=50\njmax=90\n" +
			"h1=1-1\nh2=2-2\nh3=3-3\nh4=4-4\n" +
			"i1=16-28-100-4\ni3=150-3-1\n"
		if got := obfDeviceIPC(nil, junk); got != want {
			t.Errorf("obfDeviceIPC(nil, junk) = %q, want %q", got, want)
		}
	})

	t.Run("junk lines precede the dialect lines on a full profile", func(t *testing.T) {
		want := "jc=2\njmin=50\njmax=90\n" +
			"s1=30\ns2=25\ns3=15\ns4=10\n" +
			"h1=100-200\nh2=300-400\nh3=500-600\nh4=700-800\n" +
			"i1=16-28-100-4\ni3=150-3-1\n"
		if got := obfDeviceIPC(testObfProfile(), junk); got != want {
			t.Errorf("obfDeviceIPC(profile, junk) = %q, want %q", got, want)
		}
	})

	t.Run("only non-empty specs emit i lines", func(t *testing.T) {
		got := obfDeviceIPC(nil, junk)
		for _, forbidden := range []string{"i2=", "i4=", "i5="} {
			if strings.Contains(got, forbidden) {
				t.Errorf("obfDeviceIPC emitted %q line for an empty spec: %q", forbidden, got)
			}
		}
	})

	t.Run("an empty junk configuration emits no junk lines", func(t *testing.T) {
		want := "h1=1-1\nh2=2-2\nh3=3-3\nh4=4-4\n"
		if got := obfDeviceIPC(nil, state.StrategyJunk{}); got != want {
			t.Errorf("obfDeviceIPC(nil, empty junk) = %q, want %q", got, want)
		}
	})

	t.Run("a zero-count junk configuration emits no jc lines", func(t *testing.T) {
		// jc resolves to 0 (explicit no-junk): a size range without a
		// count would be dead knobs on the device
		got := obfDeviceIPC(nil, state.StrategyJunk{Jmin: 50, Jmax: 90})
		if strings.Contains(got, "jc=") {
			t.Errorf("obfDeviceIPC emitted jc lines for a zero-count junk: %q", got)
		}
	})
}

func TestResolveMTU(t *testing.T) {
	cfg := &state.LocalCfg{}
	if got := resolveMTU(cfg); got != device.DefaultMTU {
		t.Errorf("resolveMTU(nil MTU) = %d, want device.DefaultMTU (%d)", got, device.DefaultMTU)
	}

	mtu := uint16(1280)
	cfg.MTU = &mtu
	if got := resolveMTU(cfg); got != 1280 {
		t.Errorf("resolveMTU(MTU=1280) = %d, want 1280", got)
	}
}

func TestCentralCfgObfYAMLShape(t *testing.T) {
	prof := testObfProfile()
	cfg := state.CentralCfg{Obf: &state.CentralObf{ObfProfile: *prof}}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal CentralCfg: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal marshaled CentralCfg into map: %v", err)
	}
	obf, ok := doc["obf"].(map[string]any)
	if !ok {
		t.Fatalf("marshaled YAML lacks the global obf mapping:\n%s", data)
	}

	wantKeys := []string{"s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"}
	for _, k := range []string{"jc", "jmin", "jmax"} {
		if _, ok := obf[k]; ok {
			t.Errorf("the obf mapping must not carry %q (the junk trio moved onto obf strategies)", k)
		}
	}
	if len(obf) != len(wantKeys) {
		t.Errorf("obf mapping has %d keys, want %d: %v", len(obf), len(wantKeys), obf)
	}
	for _, k := range wantKeys {
		if _, ok := obf[k]; !ok {
			t.Errorf("obf mapping missing key %q", k)
		}
	}
	for _, k := range []string{"h1", "h2", "h3", "h4"} {
		h, ok := obf[k].(map[string]any)
		if !ok {
			t.Fatalf("obf.%s is not a mapping: %v", k, obf[k])
		}
		if len(h) != 2 {
			t.Errorf("obf.%s has %d keys, want exactly min and max: %v", k, len(h), h)
		}
		if _, ok := h["min"]; !ok {
			t.Errorf("obf.%s missing key %q", k, "min")
		}
		if _, ok := h["max"]; !ok {
			t.Errorf("obf.%s missing key %q", k, "max")
		}
	}

	var round state.CentralCfg
	if err := yaml.Unmarshal(data, &round); err != nil {
		t.Fatalf("unmarshal marshaled CentralCfg: %v", err)
	}
	if round.Profile() == nil {
		t.Fatalf("round-trip lost the obf profile:\n%s", data)
	}
	if *round.Profile() != *cfg.Profile() {
		t.Errorf("round-trip mismatch: got %+v, want %+v", *round.Profile(), *cfg.Profile())
	}
}
