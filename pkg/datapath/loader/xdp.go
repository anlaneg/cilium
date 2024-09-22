// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

func xdpModeToFlag(xdpMode string) uint32 {
	switch xdpMode {
	case option.XDPModeNative:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	case option.XDPModeLinkDriver:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeLinkGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	}
	return 0
}

// maybeUnloadObsoleteXDPPrograms removes bpf_xdp.o from previously used devices.
func maybeUnloadObsoleteXDPPrograms(xdpDevs []string, xdpMode string) {
	/*取系统所有link*/
	links, err := netlink.LinkList()
	if err != nil {
		log.WithError(err).Warn("Failed to list links for XDP unload")
	}

	/*遍历所有link,移除挂在这些设备上的bpf_xdp.o*/
	for _, link := range links {
		linkxdp := link.Attrs().Xdp
		if linkxdp == nil || !linkxdp.Attached {
			// No XDP program is attached
			continue
		}
		if strings.Contains(link.Attrs().Name, "cilium") {
			// Ignore devices created by cilium-agent
			continue
		}

		used := false
		for _, xdpDev := range xdpDevs {
			if link.Attrs().Name == xdpDev &&
				linkxdp.Flags&xdpModeToFlag(xdpMode) != 0 {
				// XDP mode matches; don't unload, otherwise we might introduce
				// intermittent connectivity problems
				used = true
				break
			}
		}
		if !used {
			netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeLinkGeneric)))
			netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeLinkDriver)))
		}
	}
}

// xdpCompileArgs derives compile arguments for bpf_xdp.c.
func xdpCompileArgs(xdpDev string, extraCArgs []string) ([]string, error) {
	//构造xdpDev对应的link对象
	link, err := netlink.LinkByName(xdpDev)
	if err != nil {
		return nil, err
	}

	args := []string{
		fmt.Sprintf("-DSECLABEL=%d", identity.ReservedIdentityWorld),
		fmt.Sprintf("-DNODE_MAC={.addr=%s}", mac.CArrayString(link.Attrs().HardwareAddr)),/*取link的mac地址*/
		"-DCALLS_MAP=cilium_calls_xdp",
	}
	/*合入额外的args*/
	args = append(args, extraCArgs...)
	if option.Config.EnableNodePort {
		args = append(args, []string{
			fmt.Sprintf("-DTHIS_MTU=%d", link.Attrs().MTU),/*link的mtu*/
			fmt.Sprintf("-DNATIVE_DEV_IFINDEX=%d", link.Attrs().Index),/*link的ifindex*/
			"-DDISABLE_LOOPBACK_LB",
		}...)
	}

	return args, nil
}

// compileAndLoadXDPProg compiles bpf_xdp.c for the given XDP device and loads it.
func compileAndLoadXDPProg(ctx context.Context, xdpDev/*xdp关联的接口名称*/, xdpMode string, extraCArgs []string/*代码编译时的额外选项*/) error {
	args, err := xdpCompileArgs(xdpDev, extraCArgs)
	if err != nil {
		return fmt.Errorf("failed to derive XDP compile extra args: %w", err)
	}

	dirs := &directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		Output:  option.Config.StateDir,
		State:   option.Config.StateDir,
	}
	prog := &progInfo{
		Source:     xdpProg,/*输入文件*/
		Output:     xdpObj,/*输出的文件名称*/
		OutputType: outputObject,/*输出为obj类型*/
		Options:    args,
	}

	/*编译文件并生成obj*/
	if err := compile(ctx, prog, dirs); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	/*构造生成的目标位置*/
	objPath := path.Join(dirs.Output, prog.Output)
	/*将此bpf程序下发给接口xdpDev*/
	finalize, err := replaceDatapath(ctx, xdpDev, objPath, symbolFromHostNetdevEp, "", true, xdpMode)
	if err != nil {
		return err
	}
	finalize()

	return err
}
