//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2022 Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package types

import (
	models "github.com/cilium/cilium/api/v1/models"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumEndpoint) DeepCopyInto(out *CiliumEndpoint) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Identity != nil {
		in, out := &in.Identity, &out.Identity
		*out = new(v2.EndpointIdentity)
		(*in).DeepCopyInto(*out)
	}
	if in.Networking != nil {
		in, out := &in.Networking, &out.Networking
		*out = new(v2.EndpointNetworking)
		(*in).DeepCopyInto(*out)
	}
	if in.Encryption != nil {
		in, out := &in.Encryption, &out.Encryption
		*out = new(v2.EncryptionSpec)
		**out = **in
	}
	if in.NamedPorts != nil {
		in, out := &in.NamedPorts, &out.NamedPorts
		*out = make(models.NamedPorts, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(models.Port)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumEndpoint.
func (in *CiliumEndpoint) DeepCopy() *CiliumEndpoint {
	if in == nil {
		return nil
	}
	out := new(CiliumEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumEndpoint) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in IPSlice) DeepCopyInto(out *IPSlice) {
	{
		in := &in
		*out = make(IPSlice, len(*in))
		copy(*out, *in)
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPSlice.
func (in IPSlice) DeepCopy() IPSlice {
	if in == nil {
		return nil
	}
	out := new(IPSlice)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SlimCNP) DeepCopyInto(out *SlimCNP) {
	*out = *in
	if in.CiliumNetworkPolicy != nil {
		in, out := &in.CiliumNetworkPolicy, &out.CiliumNetworkPolicy
		*out = new(v2.CiliumNetworkPolicy)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SlimCNP.
func (in *SlimCNP) DeepCopy() *SlimCNP {
	if in == nil {
		return nil
	}
	out := new(SlimCNP)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *SlimCNP) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
