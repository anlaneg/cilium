// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

// Code generated by informer-gen. DO NOT EDIT.

package v2alpha1

import (
	"context"
	time "time"

	ciliumiov2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	versioned "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	internalinterfaces "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions/internalinterfaces"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/listers/cilium.io/v2alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// CiliumEgressNATPolicyInformer provides access to a shared informer and lister for
// CiliumEgressNATPolicies.
type CiliumEgressNATPolicyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v2alpha1.CiliumEgressNATPolicyLister
}

type ciliumEgressNATPolicyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewCiliumEgressNATPolicyInformer constructs a new informer for CiliumEgressNATPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewCiliumEgressNATPolicyInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredCiliumEgressNATPolicyInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredCiliumEgressNATPolicyInformer constructs a new informer for CiliumEgressNATPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredCiliumEgressNATPolicyInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CiliumV2alpha1().CiliumEgressNATPolicies().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CiliumV2alpha1().CiliumEgressNATPolicies().Watch(context.TODO(), options)
			},
		},
		&ciliumiov2alpha1.CiliumEgressNATPolicy{},
		resyncPeriod,
		indexers,
	)
}

func (f *ciliumEgressNATPolicyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredCiliumEgressNATPolicyInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *ciliumEgressNATPolicyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&ciliumiov2alpha1.CiliumEgressNATPolicy{}, f.defaultInformer)
}

func (f *ciliumEgressNATPolicyInformer) Lister() v2alpha1.CiliumEgressNATPolicyLister {
	return v2alpha1.NewCiliumEgressNATPolicyLister(f.Informer().GetIndexer())
}
