package state

import (
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
)

func listenModeNode(listen, mode string) *LocalCfg {
	key := GenerateKey()
	return &LocalCfg{
		Port:        30000,
		ListenPorts: listen,
		ListenMode:  mode,
		Key:         key,
		Id:          "a",
	}
}

func TestListenModeParsing(t *testing.T) {
	src := `
port: 30000
listen_ports: 30000-65000
listen_mode: nftables
id: a
`
	var cfg LocalCfg
	err := yaml.Unmarshal([]byte(src), &cfg)
	assert.NoError(t, err)
	assert.Equal(t, "nftables", cfg.ListenMode)
	assert.True(t, cfg.UsesNftListenMode(), "listen_mode: nftables must select the nftables mode")
}

func TestListenModeDefaultsToSockets(t *testing.T) {
	assert.Equal(t, ListenModeSockets, (&LocalCfg{}).EffectiveListenMode(), "empty listen_mode defaults to sockets")
	assert.Equal(t, ListenModeSockets, (&LocalCfg{ListenMode: "sockets"}).EffectiveListenMode())
	assert.False(t, (&LocalCfg{}).UsesNftListenMode())
}

func TestListenModeValidationMatrix(t *testing.T) {
	central := &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: NodeCfg{Id: "a", PubKey: GenerateKey().Pubkey()}},
		},
	}

	// sockets mode keeps the ceiling
	if err := NodeConfigValidator(central, listenModeNode("10000-60000", "")); err == nil {
		t.Error("over-ceiling listen_ports accepted with the default sockets mode")
	}
	if err := NodeConfigValidator(central, listenModeNode("10000-60000", "sockets")); err == nil {
		t.Error("over-ceiling listen_ports accepted with explicit sockets mode")
	}

	// nftables mode lifts the ceiling (arbitrarily wide ranges)
	if err := NodeConfigValidator(central, listenModeNode("10000-60000", "nftables")); err != nil {
		t.Errorf("over-ceiling listen_ports rejected under nftables mode: %v", err)
	}
	if err := NodeConfigValidator(central, listenModeNode("1024-65535", "nftables")); err != nil {
		t.Errorf("full-range listen_ports rejected under nftables mode: %v", err)
	}

	// both modes keep the contains-primary invariant
	if err := NodeConfigValidator(central, listenModeNode("30100-30200", "nftables")); err == nil {
		t.Error("listen_ports not containing the primary port accepted under nftables mode")
	}

	// unknown mode values are rejected
	if err := NodeConfigValidator(central, listenModeNode("30000-30100", "iptables")); err == nil {
		t.Error("unknown listen_mode accepted")
	}

	// nftables without a range is meaningless
	if err := NodeConfigValidator(central, listenModeNode("", "nftables")); err == nil {
		t.Error("listen_mode nftables without listen_ports accepted")
	}

	// explicit sockets without a range is fine (it is the default)
	if err := NodeConfigValidator(central, listenModeNode("", "sockets")); err != nil {
		t.Errorf("explicit sockets mode without listen_ports rejected: %v", err)
	}
}
