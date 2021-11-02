//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package labels

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Requirement) DeepCopyInto(out *Requirement) {
	*out = *in
	if in.strValues != nil {
		in, out := &in.strValues, &out.strValues
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Requirement.
func (in *Requirement) DeepCopy() *Requirement {
	if in == nil {
		return nil
	}
	out := new(Requirement)
	in.DeepCopyInto(out)
	return out
}
