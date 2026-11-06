package state

import (
	"strings"
	"testing"
)

func TestParsePortRangeForms(t *testing.T) {
	cases := []struct {
		in            string
		first, last   uint16
		size          int
		single, valid bool
		wantErr       bool
	}{
		{"80", 80, 80, 1, true, true, false},
		{"30000-40000", 30000, 40000, 10001, false, true, false},
		{"40000-30000", 0, 0, 0, false, false, true},
		{"0", 0, 0, 0, false, false, true},
		{"0-100", 0, 0, 0, false, false, true},
		{"65536", 0, 0, 0, false, false, true},
	}
	for _, c := range cases {
		pr, err := ParsePortRange(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePortRange(%q): expected error, got %v", c.in, pr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortRange(%q): unexpected error %v", c.in, err)
			continue
		}
		if pr.First != c.first || pr.Last != c.last || pr.Size() != c.size || pr.IsSingle() != c.single || pr.Valid() != c.valid {
			t.Errorf("ParsePortRange(%q) = %v (size %d), want %d-%d size %d single=%v", c.in, pr, pr.Size(), c.first, c.last, c.size, c.single)
		}
	}
}

func TestPortRangeContains(t *testing.T) {
	pr, err := ParsePortRange("30000-30009")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []uint16{30000, 30005, 30009} {
		if !pr.Contains(p) {
			t.Errorf("Contains(%d) = false, want true", p)
		}
	}
	for _, p := range []uint16{29999, 30010, 0, 65535} {
		if pr.Contains(p) {
			t.Errorf("Contains(%d) = true, want false", p)
		}
	}
}

func TestParseEndpointSpecForms(t *testing.T) {
	cases := []struct {
		in          string
		host        string
		first, last uint16
		isRange     bool
		strategies  []string
		wantErr     string // "" = expect success
	}{
		// concrete endpoints (raw forms); a bare host keeps Ports invalid
		// so "explicit port" stays distinguishable from "bare host"
		{"1.2.3.4", "1.2.3.4", 0, 0, false, nil, ""},
		{"1.2.3.4:57175", "1.2.3.4", 57175, 57175, false, nil, ""},
		{"example.com", "example.com", 0, 0, false, nil, ""},
		{"example.com:9000", "example.com", 9000, 9000, false, nil, ""},
		{"[2001:db8::1]:9000", "2001:db8::1", 9000, 9000, false, nil, ""},
		{"2001:db8::1", "2001:db8::1", 0, 0, false, nil, ""},
		// strategy-tagged endpoints: the strategy carries the ports
		{"1.2.3.4[awg_main]", "1.2.3.4", 0, 0, false, []string{"awg_main"}, ""},
		{"example.com[hopping,vanilla]", "example.com", 0, 0, false, []string{"hopping", "vanilla"}, ""},
		{"1.2.3.4[*]", "1.2.3.4", 0, 0, false, []string{"*"}, ""},
		{"[2001:db8::1][awg_main]", "2001:db8::1", 0, 0, false, []string{"awg_main"}, ""},
		// inline ranges moved into strategies: migration errors
		{"1.2.3.4:30000-40000", "", 0, 0, false, nil, "inline port ranges moved into obf strategies"},
		{"example.com:30000-40000", "", 0, 0, false, nil, "inline port ranges moved into obf strategies"},
		{"1.2.3.4:30000-30000", "", 0, 0, false, nil, "inline port ranges moved into obf strategies"},
		// port + tags is a contradiction: the strategy names the ports
		{"1.2.3.4:9000[awg_main]", "", 0, 0, false, nil, "cannot be combined with obf strategy tags"},
		// tag list hygiene
		{"1.2.3.4[]", "", 0, 0, false, nil, "empty obf strategy name"},
		{"1.2.3.4[* ,awg]", "", 0, 0, false, nil, "must stand alone"},
		{"1.2.3.4[awg,]", "", 0, 0, false, nil, "empty obf strategy name"},
		{"1.2.3.4[Awg]", "", 0, 0, false, nil, "invalid obf strategy tag"},
		{"[awg_main]", "", 0, 0, false, nil, "without a host"},
		// generic errors
		{"", "", 0, 0, false, nil, "endpoint is empty"},
		{"http://example.com", "", 0, 0, false, nil, "invalid endpoint"},
		{"1.2.3.4:40000-30000", "", 0, 0, false, nil, "inline port ranges moved into obf strategies"},
		{":30000", "", 0, 0, false, nil, "empty host"},
	}
	for _, c := range cases {
		spec, err := ParseEndpointSpec(c.in)
		if c.wantErr != "" {
			if err == nil {
				t.Errorf("ParseEndpointSpec(%q): expected error %q, got %+v", c.in, c.wantErr, spec)
			} else if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("ParseEndpointSpec(%q): error %q does not contain %q", c.in, err.Error(), c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEndpointSpec(%q): unexpected error %v", c.in, err)
			continue
		}
		if spec.Host != c.host {
			t.Errorf("ParseEndpointSpec(%q).Host = %q, want %q", c.in, spec.Host, c.host)
		}
		if spec.Ports.First != c.first || spec.Ports.Last != c.last {
			t.Errorf("ParseEndpointSpec(%q).Ports = %v, want %d-%d", c.in, spec.Ports, c.first, c.last)
		}
		if spec.IsRange() != c.isRange {
			t.Errorf("ParseEndpointSpec(%q).IsRange() = %v, want %v", c.in, spec.IsRange(), c.isRange)
		}
		if strings.Join(spec.Strategies, ",") != strings.Join(c.strategies, ",") {
			t.Errorf("ParseEndpointSpec(%q).Strategies = %v, want %v", c.in, spec.Strategies, c.strategies)
		}
		if spec.HasStrategies() != (len(c.strategies) > 0) {
			t.Errorf("ParseEndpointSpec(%q).HasStrategies() drift", c.in)
		}
	}
}

func TestEndpointSpecStringRoundTrip(t *testing.T) {
	cases := []string{
		"1.2.3.4:57175",
		"1.2.3.4[awg_main]",
		"1.2.3.4[hopping,vanilla]",
		"[2001:db8::1][awg_main]",
		"[2001:db8::1]:30000",
	}
	for _, c := range cases {
		spec, err := ParseEndpointSpec(c)
		if err != nil {
			t.Fatalf("ParseEndpointSpec(%q): %v", c, err)
		}
		if got := spec.String(); got != c {
			t.Errorf("spec.String() = %q, want %q", got, c)
		}
	}
}

func TestEndpointSpecValidationCentral(t *testing.T) {
	// tagged endpoints must reference defined strategies
	cfg := &CentralCfg{
		Obf: &CentralObf{Strategy: map[string]*ObfStrategy{
			"hopping": {Ports: "30000-40000"},
		}},
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "a"}, Endpoints: []string{"1.2.3.4[hopping]"}},
		},
	}
	if err := CentralConfigValidator(cfg); err != nil {
		t.Errorf("CentralConfigValidator rejected a tagged endpoint: %v", err)
	}
	// unknown strategy names are rejected
	cfg.Routers[0].Endpoints = []string{"1.2.3.4[nope]"}
	if err := CentralConfigValidator(cfg); err == nil || !strings.Contains(err.Error(), "undefined obf strategy") {
		t.Errorf("unknown strategy tag: err = %v, want undefined-strategy error", err)
	}
	// inline ranges are rejected with the migration pointer
	cfg.Routers[0].Endpoints = []string{"1.2.3.4:30000-40000"}
	if err := CentralConfigValidator(cfg); err == nil || !strings.Contains(err.Error(), "inline port ranges moved into obf strategies") {
		t.Errorf("inline range endpoint: err = %v, want migration error", err)
	}
	// raw single-port endpoints stay valid without any strategies
	cfg.Routers[0].Endpoints = []string{"1.2.3.4:30000"}
	if err := CentralConfigValidator(cfg); err != nil {
		t.Errorf("raw single-port endpoint rejected: %v", err)
	}
}
