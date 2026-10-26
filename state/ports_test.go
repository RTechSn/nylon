package state

import (
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
		{"", 0, 0, 0, false, false, true},
		{"abc", 0, 0, 0, false, false, true},
		{"100-abc", 0, 0, 0, false, false, true},
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
		if pr.First != c.first || pr.Last != c.last {
			t.Errorf("ParsePortRange(%q) = %v, want %d-%d", c.in, pr, c.first, c.last)
		}
		if pr.Size() != c.size {
			t.Errorf("PortRange(%q).Size() = %d, want %d", c.in, pr.Size(), c.size)
		}
		if pr.IsSingle() != c.single {
			t.Errorf("PortRange(%q).IsSingle() = %v, want %v", c.in, pr.IsSingle(), c.single)
		}
		if pr.Valid() != c.valid {
			t.Errorf("PortRange(%q).Valid() = %v, want %v", c.in, pr.Valid(), c.valid)
		}
	}
}

func TestPortRangeContains(t *testing.T) {
	pr := PortRange{First: 30000, Last: 30009}
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
		wantErr     bool
	}{
		// concrete endpoints
		{"1.2.3.4", "1.2.3.4", DefaultPort, DefaultPort, false, false},
		{"1.2.3.4:57175", "1.2.3.4", 57175, 57175, false, false},
		{"example.com", "example.com", DefaultPort, DefaultPort, false, false},
		{"example.com:9000", "example.com", 9000, 9000, false, false},
		{"[2001:db8::1]:9000", "2001:db8::1", 9000, 9000, false, false},
		{"2001:db8::1", "2001:db8::1", DefaultPort, DefaultPort, false, false},
		// ranges
		{"1.2.3.4:30000-40000", "1.2.3.4", 30000, 40000, true, false},
		{"example.com:30000-40000", "example.com", 30000, 40000, true, false},
		{"[2001:db8::1]:30000-40000", "2001:db8::1", 30000, 40000, true, false},
		{"1.2.3.4:30000-30000", "1.2.3.4", 30000, 30000, false, false},
		// errors
		{"", "", 0, 0, false, true},
		{"http://example.com", "", 0, 0, false, true},
		{"1.2.3.4:40000-30000", "", 0, 0, false, true},
		{"1.2.3.4:0-100", "", 0, 0, false, true},
		{":30000", "", 0, 0, false, true},
	}
	for _, c := range cases {
		spec, err := ParseEndpointSpec(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseEndpointSpec(%q): expected error, got %+v", c.in, spec)
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
	}
}

func TestEndpointSpecStringRoundTrip(t *testing.T) {
	cases := []string{
		"1.2.3.4:57175",
		"1.2.3.4:30000-40000",
		"[2001:db8::1]:30000-40000",
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
	// the central-config validator must accept range endpoints
	cfg := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "a"}, Endpoints: []string{"1.2.3.4:30000-40000"}},
		},
	}
	if err := CentralConfigValidator(cfg); err != nil {
		t.Errorf("CentralConfigValidator rejected range endpoint: %v", err)
	}
	// and reject malformed ones
	cfg.Routers[0].Endpoints = []string{"1.2.3.4:40000-30000"}
	if err := CentralConfigValidator(cfg); err == nil {
		t.Error("CentralConfigValidator accepted inverted port range")
	}
}

func TestListenPortsValidation(t *testing.T) {
	key := GenerateKey()
	central := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "a", PubKey: key.Pubkey()}},
		},
	}
	node := func(listen string) *LocalCfg {
		return &LocalCfg{
			Port:        30000,
			ListenPorts: listen,
			Key:         key,
			Id:          "a",
		}
	}
	if err := NodeConfigValidator(central, node("30000-30100")); err != nil {
		t.Errorf("valid listen_ports rejected: %v", err)
	}
	if err := NodeConfigValidator(central, node("30100-30200")); err == nil {
		t.Error("listen_ports not containing the primary port was accepted")
	}
	if err := NodeConfigValidator(central, node("30200-30100")); err == nil {
		t.Error("inverted listen_ports was accepted")
	}
	// over-ceiling ranges must be rejected with the in-daemon listener
	over := "10000-60000"
	if err := NodeConfigValidator(central, node(over)); err == nil {
		t.Error("over-ceiling listen_ports was accepted by the in-daemon validator")
	}
}
