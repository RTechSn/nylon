package state

import (
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
)

const testDistKeyB64 = "7PaN6DmAayz4KnDnsXSXJH+Oy0TFGeoM4FEbQfLriVY="

func TestCentralDistIntervalParsing(t *testing.T) {
	src := `
dist:
  key: ` + testDistKeyB64 + `
  repos: ["https://example.com/central.nybundle"]
  interval: 5m
`
	var cfg CentralCfg
	err := yaml.Unmarshal([]byte(src), &cfg)
	assert.NoError(t, err)
	if !assert.NotNil(t, cfg.Dist) || !assert.NotNil(t, cfg.Dist.Interval) {
		t.Fatalf("expected dist.interval to be parsed, got %+v", cfg.Dist)
	}
	assert.Equal(t, 5*time.Minute, *cfg.Dist.Interval)
}

func TestLocalDistIntervalParsing(t *testing.T) {
	src := `
dist:
  key: ` + testDistKeyB64 + `
  url: https://example.com/central.nybundle
  interval: 30s
`
	var cfg LocalCfg
	err := yaml.Unmarshal([]byte(src), &cfg)
	assert.NoError(t, err)
	if !assert.NotNil(t, cfg.Dist) || !assert.NotNil(t, cfg.Dist.Interval) {
		t.Fatalf("expected dist.interval to be parsed, got %+v", cfg.Dist)
	}
	assert.Equal(t, 30*time.Second, *cfg.Dist.Interval)
}

func TestDistIntervalOmittedIsNil(t *testing.T) {
	src := `
dist:
  key: ` + testDistKeyB64 + `
  repos: ["https://example.com/central.nybundle"]
`
	var cfg CentralCfg
	err := yaml.Unmarshal([]byte(src), &cfg)
	assert.NoError(t, err)
	if !assert.NotNil(t, cfg.Dist) {
		t.Fatal("expected dist block to parse")
	}
	assert.Nil(t, cfg.Dist.Interval)
}

func TestResolveUpdateDelay(t *testing.T) {
	def := 10 * time.Second
	central := 5 * time.Minute
	local := time.Minute
	other := 30 * time.Second
	bad := -time.Second

	assert.Equal(t, def, ResolveUpdateDelay(nil, nil, def), "no dist blocks: default")
	assert.Equal(t, def, ResolveUpdateDelay(&DistributionCfg{}, &LocalDistributionCfg{}, def), "unset intervals: default")
	assert.Equal(t, local, ResolveUpdateDelay(nil, &LocalDistributionCfg{Interval: &local}, def), "local fallback")
	assert.Equal(t, other, ResolveUpdateDelay(&DistributionCfg{}, &LocalDistributionCfg{Interval: &other}, def), "central set but nil interval: local fallback")
	assert.Equal(t, central, ResolveUpdateDelay(&DistributionCfg{Interval: &central}, &LocalDistributionCfg{Interval: &local}, def), "central takes precedence")
	assert.Equal(t, local, ResolveUpdateDelay(&DistributionCfg{Interval: &bad}, &LocalDistributionCfg{Interval: &local}, def), "non-positive central ignored")
}

func TestNodeConfigValidator_RejectsNonPositiveDistInterval(t *testing.T) {
	bad := -time.Second
	err := NodeConfigValidator(nil, &LocalCfg{
		Id:   "valid-node",
		Port: 5,
		Key:  [32]byte{1},
		Dist: &LocalDistributionCfg{
			Url:      "https://example.com/bundle",
			Key:      [32]byte{2},
			Interval: &bad,
		},
	})
	assert.ErrorContains(t, err, "dist.interval must be a positive duration")
}

func TestNodeConfigValidator_AcceptsPositiveDistInterval(t *testing.T) {
	good := time.Hour
	err := NodeConfigValidator(nil, &LocalCfg{
		Id:   "valid-node",
		Port: 5,
		Key:  [32]byte{1},
		Dist: &LocalDistributionCfg{
			Url:      "https://example.com/bundle",
			Key:      [32]byte{2},
			Interval: &good,
		},
	})
	assert.NoError(t, err)
}

func TestCentralConfigValidator_RejectsNonPositiveDistInterval(t *testing.T) {
	bad := -time.Second
	err := CentralConfigValidator(&CentralCfg{
		Dist: &DistributionCfg{
			Key:      [32]byte{2},
			Repos:    []string{"https://example.com/bundle"},
			Interval: &bad,
		},
	})
	assert.ErrorContains(t, err, "dist.interval must be a positive duration")
}

func TestCentralConfigValidator_AcceptsPositiveDistInterval(t *testing.T) {
	good := 6 * time.Hour
	err := CentralConfigValidator(&CentralCfg{
		Dist: &DistributionCfg{
			Key:      [32]byte{2},
			Repos:    []string{"https://example.com/bundle"},
			Interval: &good,
		},
	})
	assert.NoError(t, err)
}
