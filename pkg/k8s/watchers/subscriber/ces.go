// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package subscriber

import (
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// NewCES creates a new ces subscriber list.
func NewCES() *CESList {
	return &CESList{}
}

// CESHandler is implemented by event handlers responding to
// CiliumEndpointSlice events.
type CESHandler interface {
	OnAdd(ces *cilium_v2a1.CiliumEndpointSlice)
	OnUpdate(oldCES, newCES *cilium_v2a1.CiliumEndpointSlice)
	OnDelete(ces *cilium_v2a1.CiliumEndpointSlice)
}

// Register registers the CES event handler as a subscriber.
func (l *CESList) Register(c CESHandler) {
	l.Lock()
	defer l.Unlock()
	l.subs = append(l.subs, c)
}

// NotifyAdd notifies all the subscribers of an add event to an object.
func (l *CESList) NotifyAdd(ces *cilium_v2a1.CiliumEndpointSlice) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnAdd(ces)
	}
}

// NotifyUpdate notifies all the subscribers of an update event to an object.
func (l *CESList) NotifyUpdate(oldCES, newCES *cilium_v2a1.CiliumEndpointSlice) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnUpdate(oldCES, newCES)
	}
}

// NotifyDelete notifies all the subscribers of a delete event to an object.
func (l *CESList) NotifyDelete(ces *cilium_v2a1.CiliumEndpointSlice) {
	l.RLock()
	defer l.RUnlock()
	for _, s := range l.subs {
		s.OnDelete(ces)
	}
}

// CESList holds the CES subscribers to any CiliumEndpointSlice resource / object changes in
// the K8s watchers.
type CESList struct {
	list
	subs []CESHandler
}
