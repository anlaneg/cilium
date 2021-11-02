// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCiliumClusterwideNetworkPolicies implements CiliumClusterwideNetworkPolicyInterface
type FakeCiliumClusterwideNetworkPolicies struct {
	Fake *FakeCiliumV2
}

var ciliumclusterwidenetworkpoliciesResource = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}

var ciliumclusterwidenetworkpoliciesKind = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumClusterwideNetworkPolicy"}

// Get takes name of the ciliumClusterwideNetworkPolicy, and returns the corresponding ciliumClusterwideNetworkPolicy object, and an error if there is any.
func (c *FakeCiliumClusterwideNetworkPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2.CiliumClusterwideNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(ciliumclusterwidenetworkpoliciesResource, name), &v2.CiliumClusterwideNetworkPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.CiliumClusterwideNetworkPolicy), err
}

// List takes label and field selectors, and returns the list of CiliumClusterwideNetworkPolicies that match those selectors.
func (c *FakeCiliumClusterwideNetworkPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v2.CiliumClusterwideNetworkPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(ciliumclusterwidenetworkpoliciesResource, ciliumclusterwidenetworkpoliciesKind, opts), &v2.CiliumClusterwideNetworkPolicyList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2.CiliumClusterwideNetworkPolicyList{ListMeta: obj.(*v2.CiliumClusterwideNetworkPolicyList).ListMeta}
	for _, item := range obj.(*v2.CiliumClusterwideNetworkPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested ciliumClusterwideNetworkPolicies.
func (c *FakeCiliumClusterwideNetworkPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(ciliumclusterwidenetworkpoliciesResource, opts))
}

// Create takes the representation of a ciliumClusterwideNetworkPolicy and creates it.  Returns the server's representation of the ciliumClusterwideNetworkPolicy, and an error, if there is any.
func (c *FakeCiliumClusterwideNetworkPolicies) Create(ctx context.Context, ciliumClusterwideNetworkPolicy *v2.CiliumClusterwideNetworkPolicy, opts v1.CreateOptions) (result *v2.CiliumClusterwideNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(ciliumclusterwidenetworkpoliciesResource, ciliumClusterwideNetworkPolicy), &v2.CiliumClusterwideNetworkPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.CiliumClusterwideNetworkPolicy), err
}

// Update takes the representation of a ciliumClusterwideNetworkPolicy and updates it. Returns the server's representation of the ciliumClusterwideNetworkPolicy, and an error, if there is any.
func (c *FakeCiliumClusterwideNetworkPolicies) Update(ctx context.Context, ciliumClusterwideNetworkPolicy *v2.CiliumClusterwideNetworkPolicy, opts v1.UpdateOptions) (result *v2.CiliumClusterwideNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(ciliumclusterwidenetworkpoliciesResource, ciliumClusterwideNetworkPolicy), &v2.CiliumClusterwideNetworkPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.CiliumClusterwideNetworkPolicy), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCiliumClusterwideNetworkPolicies) UpdateStatus(ctx context.Context, ciliumClusterwideNetworkPolicy *v2.CiliumClusterwideNetworkPolicy, opts v1.UpdateOptions) (*v2.CiliumClusterwideNetworkPolicy, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(ciliumclusterwidenetworkpoliciesResource, "status", ciliumClusterwideNetworkPolicy), &v2.CiliumClusterwideNetworkPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.CiliumClusterwideNetworkPolicy), err
}

// Delete takes name of the ciliumClusterwideNetworkPolicy and deletes it. Returns an error if one occurs.
func (c *FakeCiliumClusterwideNetworkPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(ciliumclusterwidenetworkpoliciesResource, name), &v2.CiliumClusterwideNetworkPolicy{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCiliumClusterwideNetworkPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(ciliumclusterwidenetworkpoliciesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v2.CiliumClusterwideNetworkPolicyList{})
	return err
}

// Patch applies the patch and returns the patched ciliumClusterwideNetworkPolicy.
func (c *FakeCiliumClusterwideNetworkPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.CiliumClusterwideNetworkPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(ciliumclusterwidenetworkpoliciesResource, name, pt, data, subresources...), &v2.CiliumClusterwideNetworkPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.CiliumClusterwideNetworkPolicy), err
}
