// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
)

// bpfCmd represents the bpf command
var bpfCmd = &cobra.Command{
	Use:   "bpf",
	Short: "Direct access to local BPF maps",
}

func init() {
	/*在root命令下添加bpf命令*/
	rootCmd.AddCommand(bpfCmd)
}
