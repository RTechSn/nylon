//go:build !linux

package core

import (
	"errors"

	"github.com/encodeous/nylon/polyamide/conn"
)

// NftTableName is the nftables table the daemon would own in listen_mode:
// nftables. Non-Linux builds cannot serve the mode at all.
const NftTableName = "nylon"

// nftRangeRedirect is the non-Linux stub: the netfilter redirect mode is only
// implemented for Linux. Validation lets the config through (it stays
// portable), but daemon startup fails loudly here.
type nftRangeRedirect struct{}

func newNftRangeRedirect(primary uint16, rng conn.PortRange) *nftRangeRedirect {
	return &nftRangeRedirect{}
}

func (r *nftRangeRedirect) Install() error {
	return errors.New("listen_mode: nftables is only supported on Linux")
}

func (r *nftRangeRedirect) Remove() error {
	return nil
}
