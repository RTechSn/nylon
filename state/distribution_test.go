package state

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestBundleConfigWarnsWhenDistributionKeyDiffers(t *testing.T) {
	signingKey := GenerateKey()
	cfg := CentralCfg{
		Dist: &DistributionCfg{
			Key:   GenerateKey().Pubkey(),
			Repos: []string{"https://example.com/bundle"},
		},
	}
	txt, err := yaml.Marshal(cfg)
	assert.NoError(t, err)

	var logs bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	_, err = BundleConfig(string(txt), signingKey)
	assert.NoError(t, err)
	assert.Contains(t, logs.String(), "bundled public key differs from the signing key")
}

func TestBundleUnbundle(t *testing.T) {
	root := GenerateKey()
	cfg := CentralCfg{
		Dist:    nil,
		Routers: make([]RouterCfg, 0),
		Clients: []ClientCfg{
			{NodeCfg{
				Id:     "blah",
				PubKey: NyPublicKey{},
				Prefixes: []PrefixHealthWrapper{
					{
						&StaticPrefixHealth{
							Prefix: netip.MustParsePrefix("10.0.0.1/32"),
							Metric: 0,
						},
					},
				},
			}},
		},
		Graph: []string{
			"blah, blah",
			"a = blah",
			"b = a",
			"a, b",
		},
		Timestamp: 0,
	}
	txt, err := yaml.Marshal(cfg)
	assert.NoError(t, err)
	bundle, err := BundleConfig(string(txt), root)
	assert.NoError(t, err)

	finalCfg, err := UnbundleConfig(bundle, root.Pubkey())
	assert.NoError(t, err)
	finalCfg.Timestamp = 0 // cannot enforce timestamp to be the same
	assert.EqualValues(t, cfg, *finalCfg)
}

func TestBundleTamper(t *testing.T) {
	root := GenerateKey()
	cfg := CentralCfg{
		Dist:    nil,
		Routers: make([]RouterCfg, 0),
		Clients: []ClientCfg{
			{NodeCfg{
				Id:     "blah",
				PubKey: NyPublicKey{},
				Prefixes: []PrefixHealthWrapper{
					{
						&StaticPrefixHealth{
							Prefix: netip.MustParsePrefix("10.0.0.1/32"),
							Metric: 0,
						},
					},
					{
						&StaticPrefixHealth{
							Prefix: netip.MustParsePrefix("10.0.0.2/32"),
							Metric: 0,
						},
					},
					{
						&StaticPrefixHealth{
							Prefix: netip.MustParsePrefix("10.0.0.3/8"),
							Metric: 0,
						},
					},
				},
			}},
		},
		Graph: []string{
			"blah, blah",
			"a = blah",
			"b = a",
			"a, b",
		},
		Timestamp: 0,
	}
	txt, err := yaml.Marshal(cfg)
	assert.NoError(t, err)
	bundle, err := BundleConfig(string(txt), root)
	assert.NoError(t, err)

	buf := []byte(bundle)
	if buf[0] == 'a' {
		buf[0] = 'b'
	} else {
		buf[0] = 'a'
	}
	bundle = string(buf)

	_, err = UnbundleConfig(bundle, root.Pubkey())
	assert.ErrorContains(t, err, "message authentication failed")
}

func TestBundleInvalidSign(t *testing.T) {
	root := GenerateKey()
	fakePriv := GenerateKey()
	cfg := CentralCfg{
		Dist:    nil,
		Routers: make([]RouterCfg, 0),
		Clients: []ClientCfg{
			{NodeCfg{
				Id:     "blah",
				PubKey: NyPublicKey{},
			}},
		},
		Graph: []string{
			"blah, blah",
			"a = blah",
			"b = a",
			"a, b",
		},
		Timestamp: 0,
	}
	cfg.Timestamp = time.Now().UnixNano()

	plainText, err := yaml.Marshal(cfg)
	assert.NoError(t, err)
	privKey := x25519.PrivateKey(fakePriv[:])
	sig, err := privKey.Sign(rand.Reader, plainText, crypto.Hash(0))
	assert.NoError(t, err)

	plainBundle := append(sig, plainText...)

	pk := root.Pubkey()
	ahead, err := chacha20poly1305.NewX(pk[:])
	assert.NoError(t, err)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err = rand.Read(nonce)
	assert.NoError(t, err)
	cipherText := ahead.Seal(make([]byte, 0), nonce, plainBundle, make([]byte, 0))
	bundle := base64.StdEncoding.EncodeToString(append(nonce, cipherText...))

	_, err = UnbundleConfig(bundle, root.Pubkey())
	assert.ErrorContains(t, err, "invalid signature")
}

func TestBundleInvalidData1(t *testing.T) {
	root := GenerateKey()
	bundle := base64.StdEncoding.EncodeToString([]byte("blah"))
	_, err := UnbundleConfig(bundle, root.Pubkey())
	assert.ErrorContains(t, err, "invalid bundle, too small")
}

func TestBundleInvalidData2(t *testing.T) {
	root := GenerateKey()
	bundle, err := SignBundle([]byte("blah"), root)
	assert.NoError(t, err)
	pub := root.Pubkey()
	bundle, err = SealBundle(bundle, pub[:])
	assert.NoError(t, err)

	_, err = UnbundleConfig(base64.StdEncoding.EncodeToString(bundle), root.Pubkey())
	assert.Error(t, err)
}

func TestBundleConfigPreservesTopLevelPriorityRules(t *testing.T) {
	// regression (field report): priority_rules at the TOP LEVEL of
	// central.yaml was dropped wholesale by the seal roundtrip (CentralCfg
	// had no such field), so a sealed-and-distributed network silently lost
	// its QoS rules
	root := GenerateKey()
	// the three prefix health types ride along so the strict roundtrip
	// covers PrefixHealthWrapper's peek+decode path as well
	src := `routers:
  - id: blah
    prefixes:
      - type: static
        prefix: 10.0.0.1/32
      - type: ping
        prefix: 10.1.0.0/24
        addr: 10.1.0.8
      - type: http
        prefix: 10.2.0.0/24
        url: http://example.com/healthz
clients: []
graph:
  - blah, blah
priority_rules:
  - protocol: udp
    port: 5405
    priority: high
  - protocol: tcp
    port: 22
    priority: high
`
	bundle, err := BundleConfig(src, root)
	assert.NoError(t, err)

	cfg, err := UnbundleConfig(bundle, root.Pubkey())
	assert.NoError(t, err)
	if len(cfg.PriorityRules) != 2 {
		t.Fatalf("mesh-wide priority_rules lost in the bundle: %+v", cfg.PriorityRules)
	}
	if got := cfg.PriorityRules[0]; got.Protocol != "udp" || got.Port != "5405" || got.Priority != PriorityHigh {
		t.Errorf("rule 0: %+v", got)
	}
	if got := cfg.PriorityRules[1]; got.Protocol != "tcp" || got.Port != "22" || got.Priority != PriorityHigh {
		t.Errorf("rule 1: %+v", got)
	}
}

func TestBundleConfigRejectsUnknownTopLevelKeys(t *testing.T) {
	// strict seal: an unknown key must fail loudly, not silently vanish from
	// the distributed bundle (exactly how a misplaced section used to
	// disappear)
	root := GenerateKey()
	src := "routers: []\nclients: []\ngraph: []\nprioroty_rules:\n  - protocol: udp\n    port: 5405\n    priority: high\n"
	_, err := BundleConfig(src, root)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "prioroty_rules")
}

func TestUnbundleConfigRejectsUnknownFields(t *testing.T) {
	// version skew: a newer nylon sealed a field this binary does not know —
	// the poll must fail loudly (the node keeps its last active config)
	// instead of half-applying the bundle
	root := GenerateKey()
	plain := []byte("routers: []\nclients: []\ngraph: []\ntimestamp: 1\nfuture_field: 42\n")
	signed, err := SignBundle(plain, root)
	assert.NoError(t, err)
	pub := root.Pubkey()
	sealed, err := SealBundle(signed, pub[:])
	assert.NoError(t, err)

	_, err = UnbundleConfig(base64.StdEncoding.EncodeToString(sealed), pub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "future_field")
}
