//go:build !integration

package core

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/encodeous/nylon/log"
	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/polyamide/tun"
)

func NewWireGuardDevice(n *Nylon) (dev *device.Device, tunDevice tun.Device, realItf string, err error) {
	itfName := n.InterfaceName // attempt to name the interface

	if runtime.GOOS == "darwin" && !n.NoTun {
		itfName = "utun"
	}

	mtu := resolveMTU(&n.LocalCfg)

	var tdev tun.Device
	if n.NoTun {
		tdev = tun.NewDummyDevice(itfName, mtu)
	} else {
		tdev, err = tun.CreateTUNWithOptions(itfName, mtu, resolveTunOptions(&n.LocalCfg))
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to create TUN: %v. Check if an interface with the name nylon exists already", err)
		}
	}
	realInterfaceName, err := tdev.Name()
	if err == nil {
		itfName = realInterfaceName
	}
	if mq, ok := tdev.(tun.MultiQueueDevice); ok {
		n.Log.Info("TUN queues", "name", itfName, "queues", mq.QueueCount(), "txqueuelen", mq.TxQueueLen(), "backpressure", mq.Backpressure())
	}

	wgLog := n.Log.With("module", log.ScopePolyamide)

	// Port hopping (server half): MultiBind listens on the primary port
	// plus, when listen_ports is configured, every port of that range,
	// answering each peer from the port its last packet targeted. The
	// client half (rotation) lives in the per-peer hop controller.
	bind := conn.NewMultiBind()

	// setup WireGuard
	dev = device.NewDevice(tdev, bind, &device.Logger{
		// Verbosef only fires when DBG_log_wireguard is set; emitting at Info
		// makes the flag the single gate, visible at the default log level.
		Verbosef: func(format string, args ...any) {
			if n.DBG_log_wireguard {
				wgLog.Info(fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...any) {
			if strings.Contains(format, "Failed to send PolySock packets") {
				return
			}
			wgLog.Error(fmt.Sprintf(format, args...))
		},
	})

	// start uapi for wg command
	n.wgUapi, err = InitUAPI(n.Log, itfName)
	if err != nil {
		return nil, nil, "", err
	}

	if n.wgUapi != nil {
		go func() {
			for n.Context.Err() == nil {
				accept, err := n.wgUapi.Accept()
				if err != nil {
					n.Log.Debug(err.Error())
					continue
				}
				go dev.IpcHandle(accept)
			}
		}()
	}

	if n.NoTun {
		n.Log.Info("Created userspace-only WireGuard device", "name", itfName)
	} else {
		n.Log.Info("Created WireGuard interface", "name", itfName)
	}
	return dev, tdev, itfName, nil
}

func CleanupWireGuardDevice(n *Nylon) error {
	// remove the daemon-owned nftables redirect (listen_mode: nftables)
	// before the socket goes away, so redirected range ports stop being
	// served the moment the primary listener does
	if n.nftRedirect != nil {
		if err := n.nftRedirect.Remove(); err != nil {
			n.Log.Warn("failed to remove the nftables port-hopping table; remove it manually with `nft delete table inet "+NftTableName+"`", "error", err)
		}
	}
	n.Device.Close()
	if n.wgUapi != nil {
		err := n.wgUapi.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
