// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"fmt"
	"sync/atomic"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
)

type PolicyClient interface {
	Close()
	Path() string
}

type AccessLogger interface {
	Log(pblog *cilium.LogEntry)
	Close()
	Path() string
}

type PolicyUpdater interface {
	PolicyUpdate(resp *envoy_service_discovery.DiscoveryResponse) error
}

type Instance struct {
	/*自动增长的instance编号*/
	id           uint64
	/*被打开的次数*/
	openCount    uint64
	/*对应的node id*/
	nodeID       string
	accessLogger AccessLogger
	policyClient PolicyClient

	policyMap atomic.Value // holds PolicyMap
}

var (
	// mutex protects instances
	mutex lock.RWMutex
	// Key uint64 is a monotonically increasing instance ID
	instances map[uint64]*Instance = make(map[uint64]*Instance)
	// Last instance ID used
	instanceId uint64 = 0
)

func NewInstance(nodeID string, accessLogger AccessLogger) *Instance {

	/*instance增加，变更instanceID*/
	instanceId++

	/*未指定nodeID,则使用默认的nodeID*/
	if nodeID == "" {
		nodeID = fmt.Sprintf("host~127.0.0.2~libcilium-%d~localdomain", instanceId)
	}

	// TODO: Sidecar instance id needs to be different.
	ins := &Instance{
		id:           instanceId,
		openCount:    1,
		nodeID:       nodeID,
		accessLogger: accessLogger,
	}
	
	//设置空的policy map
	ins.setPolicyMap(newPolicyMap())

	return ins
}

// OpenInstance creates a new instance or finds an existing one with equivalent parameters.
// returns the instance id.
func OpenInstance(nodeID string, xdsPath string, newPolicyClient func(path, nodeID string, updater PolicyUpdater) PolicyClient,
	accessLogPath string, newAccessLogger func(accessLogPath string) AccessLogger) uint64 {
	mutex.Lock()
	defer mutex.Unlock()

	// Check if have an instance with these params already
	for id, old := range instances {
		oldXdsPath := ""
		if old.policyClient != nil {
			/*取xdspath*/
			oldXdsPath = old.policyClient.Path()
		}
		oldAccessLogPath := ""
		if old.accessLogger != nil {
			/*取access log path*/
			oldAccessLogPath = old.accessLogger.Path()
		}
		if (nodeID == "" || old.nodeID == nodeID) && xdsPath == oldXdsPath && accessLogPath == oldAccessLogPath {
			/*要打开的instance与map中存放的一致：一样的nodeId,一样的accessLogpath,一样的xdspath*/
			old.openCount++
			logrus.Debugf("Opened existing library instance %d, open count: %d", id, old.openCount)
			return id
		}
	}

	/*未在map instances中查询到此instance,这里进行创建*/
	ins := NewInstance(nodeID, newAccessLogger(accessLogPath)/*通过传入的回调，创建AccessLogger*/)
	// policy client needs the instance so we set it after instance has been created
	ins.policyClient = newPolicyClient(xdsPath, ins.nodeID, ins)/*通过传入的回调，创建policy client*/

	/*以自动索引为key,设置此Instance*/
	instances[instanceId] = ins

	logrus.Debugf("Opened new library instance %d", instanceId)

	return instanceId
}

/*给定instance id返回对应的Instance对象*/
func FindInstance(id uint64) *Instance {
	mutex.RLock()
	defer mutex.RUnlock()
	return instances[id]
}

// Close returns the new open count
func CloseInstance(id uint64) uint64 {
	mutex.Lock()
	defer mutex.Unlock()

	count := uint64(0)
	if ins, ok := instances[id]; ok {
		ins.openCount--
		count = ins.openCount
		if count == 0 {
			if ins.policyClient != nil {
				ins.policyClient.Close()
			}
			if ins.accessLogger != nil {
				ins.accessLogger.Close()
			}
			delete(instances, id)
		}
		logrus.Debugf("CloseInstance(%d): Remaining open count: %d", id, count)
	} else {
		logrus.Debugf("CloseInstance(%d): Not found (closed already?)", id)
	}
	return count
}

func (ins *Instance) getPolicyMap() PolicyMap {
	return ins.policyMap.Load().(PolicyMap)
}

func (ins *Instance) setPolicyMap(newMap PolicyMap) {
	ins.policyMap.Store(newMap)
}

func (ins *Instance) PolicyMatches(endpointPolicyName string, ingress bool, port, remoteId uint32, l7 interface{}) bool {
	// Policy maps are never modified once published
	policy, found := ins.getPolicyMap()[endpointPolicyName]
	if !found {
		logrus.Debugf("NPDS: Policy for %s not found", endpointPolicyName)
	}

	return found && policy.Matches(ingress, port, remoteId, l7)
}

// Update the PolicyMap from a protobuf. PolicyMap is only ever changed if the whole update is successful.
func (ins *Instance) PolicyUpdate(resp *envoy_service_discovery.DiscoveryResponse) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); !ok {
				err = fmt.Errorf("NPDS: Panic: %v", r)
			}
		}
	}()

	logrus.Debugf("NPDS: Updating policy from %v", resp)

	oldMap := ins.getPolicyMap()
	newMap := newPolicyMap()

	for _, any := range resp.Resources {
		if any.TypeUrl != resp.TypeUrl {
			return fmt.Errorf("NPDS: Mismatching TypeUrls: %s != %s", any.TypeUrl, resp.TypeUrl)
		}
		var config cilium.NetworkPolicy
		if err = proto.Unmarshal(any.Value, &config); err != nil {
			return fmt.Errorf("NPDS: Policy unmarshal error: %v", err)
		}

		policyName := config.GetName()

		// Locate the old version, if any
		oldPolicy, found := oldMap[policyName]
		if found {
			// Check if the new policy is the same as the old one
			if proto.Equal(&config, oldPolicy.protobuf) {
				logrus.Debugf("NPDS: New policy for %s is equal to the old one, no need to change", policyName)
				newMap[policyName] = oldPolicy
				continue
			}
		}

		// Validate new config
		if err = config.Validate(); err != nil {
			return fmt.Errorf("NPDS: Policy validation error for %s: %v", policyName, err)
		}

		// Create new PolicyInstance, may panic. Takes ownership of 'config'.
		newMap[policyName] = newPolicyInstance(&config)
	}

	// Store the new policy map
	ins.setPolicyMap(newMap)

	logrus.Debugf("NPDS: Policy Update completed for instance %d: %v", ins.id, newMap)
	return
}

func (ins *Instance) Log(pblog *cilium.LogEntry) {
	ins.accessLogger.Log(pblog)
}
