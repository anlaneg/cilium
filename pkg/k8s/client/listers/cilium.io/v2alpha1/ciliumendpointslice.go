// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2022 Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v2alpha1

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// CiliumEndpointSliceLister helps list CiliumEndpointSlices.
// All objects returned here must be treated as read-only.
type CiliumEndpointSliceLister interface {
	// List lists all CiliumEndpointSlices in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2alpha1.CiliumEndpointSlice, err error)
	// Get retrieves the CiliumEndpointSlice from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2alpha1.CiliumEndpointSlice, error)
	CiliumEndpointSliceListerExpansion
}

// ciliumEndpointSliceLister implements the CiliumEndpointSliceLister interface.
type ciliumEndpointSliceLister struct {
	indexer cache.Indexer
}

// NewCiliumEndpointSliceLister returns a new CiliumEndpointSliceLister.
func NewCiliumEndpointSliceLister(indexer cache.Indexer) CiliumEndpointSliceLister {
	return &ciliumEndpointSliceLister{indexer: indexer}
}

// List lists all CiliumEndpointSlices in the indexer.
func (s *ciliumEndpointSliceLister) List(selector labels.Selector) (ret []*v2alpha1.CiliumEndpointSlice, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v2alpha1.CiliumEndpointSlice))
	})
	return ret, err
}

// Get retrieves the CiliumEndpointSlice from the index for a given name.
func (s *ciliumEndpointSliceLister) Get(name string) (*v2alpha1.CiliumEndpointSlice, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v2alpha1.Resource("ciliumendpointslice"), name)
	}
	return obj.(*v2alpha1.CiliumEndpointSlice), nil
}
