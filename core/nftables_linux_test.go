//go:build linux

package core

import (
	"bytes"
	"strings"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TestNftRedirectRuleset pins the exact netfilter objects the daemon installs
// for listen_mode: nftables. This is the bytecode contract with the kernel —
// equivalent to
//
//	table inet nylon {
//	  chain prerouting {
//	    type nat hook prerouting priority dstnat; policy accept;
//	    udp dport 30000-65535 redirect to :57175
//	  }
//	}
func TestNftRedirectRuleset(t *testing.T) {
	tbl := nftOwnedTable()
	if tbl.Name != "nylon" {
		t.Errorf("table name = %q, want nylon", tbl.Name)
	}
	if tbl.Family != nftables.TableFamilyINet {
		t.Errorf("table family = %v, want inet (covers IPv4 and IPv6)", tbl.Family)
	}

	ch := nftRedirectChain(tbl)
	if ch.Name != "prerouting" {
		t.Errorf("chain name = %q, want prerouting", ch.Name)
	}
	if ch.Type != nftables.ChainTypeNAT {
		t.Errorf("chain type = %q, want nat", ch.Type)
	}
	if ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookPrerouting {
		t.Errorf("chain hook = %v, want prerouting", ch.Hooknum)
	}
	if ch.Priority == nil || *ch.Priority != *nftables.ChainPriorityNATDest {
		t.Errorf("chain priority = %v, want dstnat (-100)", ch.Priority)
	}
	if ch.Policy == nil || *ch.Policy != nftables.ChainPolicyAccept {
		t.Errorf("chain policy = %v, want accept", ch.Policy)
	}

	rng := conn.PortRange{First: 30000, Last: 65535}
	rule := nftRedirectRule(tbl, ch, 57175, rng)
	if rule.Table != tbl || rule.Chain != ch {
		t.Fatal("rule is not attached to the owned table/chain")
	}

	exprs := rule.Exprs
	if len(exprs) != 7 {
		t.Fatalf("len(rule.Exprs) = %d, want 7", len(exprs))
	}

	meta, ok := exprs[0].(*expr.Meta)
	if !ok || meta.Key != expr.MetaKeyL4PROTO || meta.Register != 1 {
		t.Errorf("exprs[0] = %#v, want meta l4proto => reg 1", exprs[0])
	}
	proto, ok := exprs[1].(*expr.Cmp)
	if !ok || proto.Op != expr.CmpOpEq || proto.Register != 1 || !bytes.Equal(proto.Data, []byte{unix.IPPROTO_UDP}) {
		t.Errorf("exprs[1] = %#v, want cmp eq reg 1 udp", exprs[1])
	}
	load, ok := exprs[2].(*expr.Payload)
	if !ok || load.Base != expr.PayloadBaseTransportHeader || load.Offset != 2 || load.Len != 2 || load.DestRegister != 1 {
		t.Errorf("exprs[2] = %#v, want payload load 2b @ th+2 (dport) => reg 1", exprs[2])
	}
	lo, ok := exprs[3].(*expr.Cmp)
	if !ok || lo.Op != expr.CmpOpGte || !bytes.Equal(lo.Data, binaryutil.BigEndian.PutUint16(rng.First)) {
		t.Errorf("exprs[3] = %#v, want cmp gte reg 1 %d (big endian)", exprs[3], rng.First)
	}
	hi, ok := exprs[4].(*expr.Cmp)
	if !ok || hi.Op != expr.CmpOpLte || !bytes.Equal(hi.Data, binaryutil.BigEndian.PutUint16(rng.Last)) {
		t.Errorf("exprs[4] = %#v, want cmp lte reg 1 %d (big endian)", exprs[4], rng.Last)
	}
	imm, ok := exprs[5].(*expr.Immediate)
	if !ok || imm.Register != 1 || !bytes.Equal(imm.Data, binaryutil.BigEndian.PutUint16(57175)) {
		t.Errorf("exprs[5] = %#v, want immediate reg 1 57175 (big endian)", exprs[5])
	}
	redir, ok := exprs[6].(*expr.Redir)
	if !ok || redir.RegisterProtoMin != 1 {
		t.Errorf("exprs[6] = %#v, want redir proto-min reg 1", exprs[6])
	}
}

// TestNftRedirectInstallWithoutCaps exercises the install path on hosts
// without CAP_NET_ADMIN: the failure must carry the capability hint instead
// of a bare errno. On hosts that do have the capability, the install must
// succeed and round-trip clean.
func TestNftRedirectInstallWithoutCaps(t *testing.T) {
	r := newNftRangeRedirect(57175, conn.PortRange{First: 30000, Last: 65535})
	err := r.Install()
	if err == nil {
		// the environment can manage nftables: verify the round-trip
		if rerr := r.Remove(); rerr != nil {
			t.Fatalf("install succeeded but remove failed: %v", rerr)
		}
		// removing again must be a no-op, not an error
		if rerr := r.Remove(); rerr != nil {
			t.Fatalf("second remove errored: %v", rerr)
		}
		return
	}
	msg := err.Error()
	if !strings.Contains(msg, "CAP_NET_ADMIN") && !strings.Contains(msg, "nftables support") {
		t.Fatalf("expected an actionable nftables error (capability or kernel-support hint), got: %v", err)
	}
	t.Logf("install failed as expected without privileges: %v", err)
}
