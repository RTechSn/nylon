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

	// Port hopping: compose the transport bind.
	// - MultiBind: listens on the primary port plus, when listen_ports is
	//   configured, every port of that range (server half).
	// - PortHopBind: destination-port rotation for peers configured with
	//   port ranges (client half). With no ranges in play the composition is
	//   behaviourally identical to a plain StdNetBind.
	hopCfg := conn.DefaultHopConfig()
	if n.LocalCfg.PortHopping != nil {
		if n.LocalCfg.PortHopping.BudgetPackets != nil {
			hopCfg.Budget = *n.LocalCfg.PortHopping.BudgetPackets
		}
		if n.LocalCfg.PortHopping.RecentPorts != nil {
			hopCfg.Recent = *n.LocalCfg.PortHopping.RecentPorts
		}
	}
	bind := conn.NewPortHopBind(conn.NewMultiBind(), hopCfg)

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
	n.Device.Close()
	if n.wgUapi != nil {
		err := n.wgUapi.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
