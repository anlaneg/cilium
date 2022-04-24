// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

// enableIPForwarding on OS X and Darwin is not doing anything. It just exists
// to make compilation possible.
func enableIPForwarding() error {
	/*这两个系统默认已开启*/
	return nil
}
