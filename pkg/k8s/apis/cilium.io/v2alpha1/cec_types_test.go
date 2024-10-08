// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package v2alpha1

import (
	"encoding/json"
	"fmt"
	"testing"

	"sigs.k8s.io/yaml"

	_ "github.com/cilium/proxy/go/envoy/config/listener/v3"
	_ "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type CiliumV2Alpha1Suite struct{}

var _ = Suite(&CiliumV2Alpha1Suite{})

var (
	envoySpec = []byte(`resources:
- "@type": type.googleapis.com/envoy.config.listener.v3.Listener
  name: envoy-prometheus-metrics-listener
  address:
    socket_address:
      address: "::"
      ipv4_compat: true
      port_value: 10000
  filter_chains:
  - filters:
    - name: envoy.filters.network.http_connection_manager
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
        stat_prefix: envoy-prometheus-metrics-listener
        route_config:
          virtual_hosts:
          - name: "prometheus_metrics_route"
            domains: ["*"]
            routes:
            - match:
                path: "/metrics"
              route:
                cluster: "envoy-admin"
                prefix_rewrite: "/stats/prometheus"
        http_filters:
        - name: envoy.filters.http.router
`)
)

func (s *CiliumV2Alpha1Suite) TestParseEnvoySpec(c *C) {
	// option.Config.Debug = true
	// logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	jsonBytes, err := yaml.YAMLToJSON([]byte(envoySpec))
	c.Assert(err, IsNil)
	fmt.Printf("\nJSON spec:\n%s\n", string(jsonBytes))
	cec := &CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, &cec.Spec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, HasLen, 1)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")
}
