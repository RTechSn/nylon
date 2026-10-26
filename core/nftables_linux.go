//go:build linux

package core

import (
	"errors"
	"fmt"
	"os"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// NftTableName is the nftables table the daemon owns while running in
// listen_mode: nftables. Creating, replacing and deleting it is managed
// entirely by the daemon; a fresh start replaces any table left behind by a
// crash. Hand-managed nftables setups should not use this mode (see the
// port-hopping guide for the manual alternative).
const NftTableName = "nylon"

// nftRedirectChainName is the base chain the redirect rule lives in.
const nftRedirectChainName = "prerouting"

// nftRangeRedirect serves a listen_ports range through a kernel netfilter
// redirect instead of per-port sockets (the server half of port hopping):
//
//	table inet nylon {
//	  chain prerouting {
//	    type nat hook prerouting priority dstnat; policy accept;
//	    udp dport <range> redirect to :<primary>
//	  }
//	}
//
// The kernel rewrites inbound packets addressed to any port of the range to
// the primary port, where the daemon's single UDP socket listens, and
// conntrack mirrors the reverse direction: replies leave with the original
// destination port as their source, so the NAT path stays symmetric without
// the daemon ever learning which port a peer targeted.
type nftRangeRedirect struct {
	primary uint16
	rng     conn.PortRange
}

func newNftRangeRedirect(primary uint16, rng conn.PortRange) *nftRangeRedirect {
	return &nftRangeRedirect{primary: primary, rng: rng}
}

// Install (re)creates the owned nftables table with the redirect rule. It is
// idempotent: a table left behind by a previous crash (or a concurrent
// instance) is replaced wholesale in one transaction.
func (r *nftRangeRedirect) Install() error {
	c, err := nftables.New()
	if err != nil {
		return wrapNftErr("connect", err)
	}
	tbl := nftOwnedTable()
	exists, err := nftTableExists(c, tbl)
	if err != nil {
		return wrapNftErr("list tables", err)
	}
	if exists {
		// replace any leftovers in the same transaction
		c.DelTable(tbl)
	}
	c.AddTable(tbl)
	chain := nftRedirectChain(tbl)
	c.AddChain(chain)
	c.AddRule(nftRedirectRule(tbl, chain, r.primary, r.rng))
	if err := c.Flush(); err != nil {
		return wrapNftErr("install redirect", err)
	}
	return nil
}

// Remove deletes the owned table. A missing table is not an error (Install
// never ran, or Remove is called twice).
func (r *nftRangeRedirect) Remove() error {
	c, err := nftables.New()
	if err != nil {
		return wrapNftErr("connect", err)
	}
	tbl := nftOwnedTable()
	exists, err := nftTableExists(c, tbl)
	if err != nil {
		return wrapNftErr("list tables", err)
	}
	if !exists {
		return nil
	}
	c.DelTable(tbl)
	if err := c.Flush(); err != nil {
		return wrapNftErr("remove table", err)
	}
	return nil
}

// nftOwnedTable returns the table descriptor owned by the daemon. Family inet
// covers both IPv4 and IPv6 range endpoints with a single rule.
func nftOwnedTable() *nftables.Table {
	return &nftables.Table{Name: NftTableName, Family: nftables.TableFamilyINet}
}

// nftRedirectChain returns the base chain the redirect rule lives in:
// `chain prerouting { type nat hook prerouting priority dstnat; policy accept; }`
func nftRedirectChain(tbl *nftables.Table) *nftables.Chain {
	accept := nftables.ChainPolicyAccept
	return &nftables.Chain{
		Name:     nftRedirectChainName,
		Table:    tbl,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
		Policy:   &accept,
	}
}

// nftTableExists reports whether a table with the same name and family is
// already present.
func nftTableExists(c *nftables.Conn, want *nftables.Table) (bool, error) {
	tables, err := c.ListTablesOfFamily(want.Family)
	if err != nil {
		return false, err
	}
	for _, t := range tables {
		if t.Name == want.Name && t.Family == want.Family {
			return true, nil
		}
	}
	return false, nil
}

// nftRedirectRule builds the bytecode for
// `meta l4proto udp @th,16,16 >= first @th,16,16 <= last redir to :primary`,
// matching the rule `nft add rule ... udp dport first-last redirect to :primary`
// produces.
func nftRedirectRule(tbl *nftables.Table, ch *nftables.Chain, primary uint16, rng conn.PortRange) *nftables.Rule {
	return &nftables.Rule{
		Table: tbl,
		Chain: ch,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			// [ cmp eq reg 1 udp ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
			// [ payload load 2b @ transport header + 2 (dport) => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			// [ cmp gte reg 1 first ]
			&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(rng.First)},
			// [ cmp lte reg 1 last ]
			&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(rng.Last)},
			// [ immediate reg 1 primary ]
			&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(primary)},
			// [ redir proto-min reg 1 ]
			&expr.Redir{RegisterProtoMin: 1},
		},
	}
}

// wrapNftErr annotates netlink failures with the most common root causes so a
// misconfigured deployment fails with an actionable message instead of a bare
// errno.
func wrapNftErr(op string, err error) error {
	e := fmt.Errorf("nftables: %s: %w", op, err)
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%w; listen_mode: nftables requires CAP_NET_ADMIN: run as root or grant the capability to the binary", e)
	case errors.Is(err, unix.EPROTONOSUPPORT), errors.Is(err, unix.EOPNOTSUPP):
		return fmt.Errorf("%w; the kernel lacks nftables support (CONFIG_NF_TABLES / nf_tables module)", e)
	}
	return e
}
