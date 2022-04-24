// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfCtCmd represents the bpf_ct command
var bpfLBCmd = &cobra.Command{
	Use:   "lb",
	Short: "Load-balancing configuration",
}

func init() {
	/*注册bpf lb命令*/
	bpfCmd.AddCommand(bpfLBCmd)
}
