package state

import (
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
)

func TestDistIntervalCloneRoundtrip(t *testing.T) {
	oneHour := time.Hour
	cfg := CentralCfg{
		Timestamp: 12345,
		Dist: &DistributionCfg{
			Key:      [32]byte{1},
			Repos:    []string{"https://example.com/bundle"},
			Interval: &oneHour,
		},
	}
	data, err := yaml.Marshal(&cfg)
	assert.NoError(t, err)
	t.Logf("marshaled:\n%s", string(data))

	var back CentralCfg
	err = yaml.Unmarshal(data, &back)
	assert.NoError(t, err)
	if !assert.NotNil(t, back.Dist) || !assert.NotNil(t, back.Dist.Interval) {
		t.Fatalf("interval LOST in roundtrip; got dist=%+v", back.Dist)
	}
	assert.Equal(t, oneHour, *back.Dist.Interval)

	// and via Clone(), which is what ApplyCentralConfig uses
	cl, err := cfg.Clone()
	assert.NoError(t, err)
	if !assert.NotNil(t, cl.Dist) || !assert.NotNil(t, cl.Dist.Interval) {
		t.Fatalf("interval LOST via Clone(); got dist=%+v", cl.Dist)
	}
	assert.Equal(t, oneHour, *cl.Dist.Interval)
}
