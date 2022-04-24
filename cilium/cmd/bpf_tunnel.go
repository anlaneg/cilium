// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

var bpfTunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Tunnel endpoint map",
}

func init() {
    /*在bpf下添加tunnel命令*/
	bpfCmd.AddCommand(bpfTunnelCmd)
}
