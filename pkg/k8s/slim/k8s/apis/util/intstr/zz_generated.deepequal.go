//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2022 Authors of Cilium

// Code generated by main. DO NOT EDIT.

package intstr

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IntOrString) DeepEqual(other *IntOrString) bool {
	if other == nil {
		return false
	}

	if in.Type != other.Type {
		return false
	}
	if in.IntVal != other.IntVal {
		return false
	}
	if in.StrVal != other.StrVal {
		return false
	}

	return true
}