//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2022 Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package lxcmap

import (
	bpf "github.com/cilium/cilium/pkg/bpf"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EndpointInfo) DeepCopyInto(out *EndpointInfo) {
	*out = *in
	in.Pad.DeepCopyInto(&out.Pad)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EndpointInfo.
func (in *EndpointInfo) DeepCopy() *EndpointInfo {
	if in == nil {
		return nil
	}
	out := new(EndpointInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapValue is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapValue.
func (in *EndpointInfo) DeepCopyMapValue() bpf.MapValue {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EndpointKey) DeepCopyInto(out *EndpointKey) {
	*out = *in
	in.EndpointKey.DeepCopyInto(&out.EndpointKey)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EndpointKey.
func (in *EndpointKey) DeepCopy() *EndpointKey {
	if in == nil {
		return nil
	}
	out := new(EndpointKey)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyMapKey is an autogenerated deepcopy function, copying the receiver, creating a new bpf.MapKey.
func (in *EndpointKey) DeepCopyMapKey() bpf.MapKey {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
