// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/tunnel"
)

const (
	tunnelTitle      = "TUNNEL"
	destinationTitle = "VALUE"
)

var bpfTunnelListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List tunnel endpoint entries",
	/*响应bpf tunnel list命令*/
	Run: func(cmd *cobra.Command, args []string) {
	    /*必须有root权限*/
		common.RequireRootPrivilege("cilium bpf tunnel list")

		/*通过dump “cilium_tunnel_map”名称的map拿到tunnel list*/
		tunnelList := make(map[string][]string)
		if err := tunnel.TunnelMap.Dump(tunnelList); err != nil {
			os.Exit(1)
		}

		if command.OutputJSON() {
			/*以json格式输出tunnel list*/
			if err := command.PrintOutput(tunnelList); err != nil {
				os.Exit(1)
			}
			return
		}

		/*输出tunnel list*/
		TablePrinter(tunnelTitle, destinationTitle, tunnelList)
	},
}

func init() {
    /*在bpf tunnel下添加 list命令*/
	bpfTunnelCmd.AddCommand(bpfTunnelListCmd)
	command.AddJSONOutput(bpfTunnelListCmd)
}
