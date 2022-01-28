// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2022 Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2

import (
	"context"
	"time"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// CiliumIdentitiesGetter has a method to return a CiliumIdentityInterface.
// A group's client should implement this interface.
type CiliumIdentitiesGetter interface {
	CiliumIdentities() CiliumIdentityInterface
}

// CiliumIdentityInterface has methods to work with CiliumIdentity resources.
type CiliumIdentityInterface interface {
	Create(ctx context.Context, ciliumIdentity *v2.CiliumIdentity, opts v1.CreateOptions) (*v2.CiliumIdentity, error)
	Update(ctx context.Context, ciliumIdentity *v2.CiliumIdentity, opts v1.UpdateOptions) (*v2.CiliumIdentity, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2.CiliumIdentity, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2.CiliumIdentityList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.CiliumIdentity, err error)
	CiliumIdentityExpansion
}

// ciliumIdentities implements CiliumIdentityInterface
type ciliumIdentities struct {
	client rest.Interface
}

// newCiliumIdentities returns a CiliumIdentities
func newCiliumIdentities(c *CiliumV2Client) *ciliumIdentities {
	return &ciliumIdentities{
		client: c.RESTClient(),
	}
}

// Get takes name of the ciliumIdentity, and returns the corresponding ciliumIdentity object, and an error if there is any.
func (c *ciliumIdentities) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2.CiliumIdentity, err error) {
	result = &v2.CiliumIdentity{}
	err = c.client.Get().
		Resource("ciliumidentities").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of CiliumIdentities that match those selectors.
func (c *ciliumIdentities) List(ctx context.Context, opts v1.ListOptions) (result *v2.CiliumIdentityList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v2.CiliumIdentityList{}
	err = c.client.Get().
		Resource("ciliumidentities").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested ciliumIdentities.
func (c *ciliumIdentities) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("ciliumidentities").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a ciliumIdentity and creates it.  Returns the server's representation of the ciliumIdentity, and an error, if there is any.
func (c *ciliumIdentities) Create(ctx context.Context, ciliumIdentity *v2.CiliumIdentity, opts v1.CreateOptions) (result *v2.CiliumIdentity, err error) {
	result = &v2.CiliumIdentity{}
	err = c.client.Post().
		Resource("ciliumidentities").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(ciliumIdentity).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a ciliumIdentity and updates it. Returns the server's representation of the ciliumIdentity, and an error, if there is any.
func (c *ciliumIdentities) Update(ctx context.Context, ciliumIdentity *v2.CiliumIdentity, opts v1.UpdateOptions) (result *v2.CiliumIdentity, err error) {
	result = &v2.CiliumIdentity{}
	err = c.client.Put().
		Resource("ciliumidentities").
		Name(ciliumIdentity.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(ciliumIdentity).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the ciliumIdentity and deletes it. Returns an error if one occurs.
func (c *ciliumIdentities) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("ciliumidentities").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *ciliumIdentities) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("ciliumidentities").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched ciliumIdentity.
func (c *ciliumIdentities) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.CiliumIdentity, err error) {
	result = &v2.CiliumIdentity{}
	err = c.client.Patch(pt).
		Resource("ciliumidentities").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
