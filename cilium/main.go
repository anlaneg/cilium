// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium

// Ensure build fails on versions of Go that are not supported by Cilium.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.17
// +build go1.17

package main

//此句导入会导致cmd目录下所有.go中的init函数被调用
import (
	"github.com/cilium/cilium/cilium/cmd"
)

func main() {
	cmd.Execute()
}
