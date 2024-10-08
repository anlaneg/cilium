// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"reflect"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
)

// EndpointProxy defines any L7 proxy with which an Endpoint must interact.
type EndpointProxy interface {
	CreateOrUpdateRedirect(l4 policy.ProxyPolicy, id string, localEndpoint logger.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc)
	RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc)
	UpdateNetworkPolicy(ep logger.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error)
	UseCurrentNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup)
	RemoveNetworkPolicy(ep logger.EndpointInfoSource)
}

// SetProxy sets the proxy for this endpoint.
func (e *Endpoint) SetProxy(p EndpointProxy) {
	e.unconditionalLock()
	defer e.unlock()
	e.proxy = p
}

func (e *Endpoint) removeNetworkPolicy() {
	if e.isProxyDisabled() {
		return
	}
	e.proxy.RemoveNetworkPolicy(e)
}

func (e *Endpoint) isProxyDisabled() bool {
	return e.proxy == nil || reflect.ValueOf(e.proxy).IsNil()
}

// FakeEndpointProxy is a stub proxy used for testing.
type FakeEndpointProxy struct{}

// CreateOrUpdateRedirect does nothing.
func (f *FakeEndpointProxy) CreateOrUpdateRedirect(l4 policy.ProxyPolicy, id string, localEndpoint logger.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	return
}

// RemoveRedirect does nothing.
func (f *FakeEndpointProxy) RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

// UpdateNetworkPolicy does nothing.
func (f *FakeEndpointProxy) UpdateNetworkPolicy(ep logger.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return nil, nil
}

// UseCurrentNetworkPolicy does nothing.
func (f *FakeEndpointProxy) UseCurrentNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
}

// RemoveNetworkPolicy does nothing.
func (f *FakeEndpointProxy) RemoveNetworkPolicy(ep logger.EndpointInfoSource) {}
