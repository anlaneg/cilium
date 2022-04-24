// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build linux
// +build linux

package bpf

import (
	"path"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	mutex       lock.RWMutex
	/*记录map与路径的映射关系*/
	mapRegister = map[string]*Map{}
)

/*记录bpf object路径与map的映射关系*/
func registerMap(path string, m *Map) {
	mutex.Lock()
	mapRegister[path] = m
	mutex.Unlock()

	log.WithField("path", path).Debug("Registered BPF map")
}

/*移除bpf map与路径的映射关系*/
func unregisterMap(path string, m *Map) {
	mutex.Lock()
	delete(mapRegister, path)
	mutex.Unlock()

	log.WithField("path", path).Debug("Unregistered BPF map")
}

// GetMap returns the registered map with the given name or absolute path
func GetMap(name string) *Map {
	mutex.RLock()
	defer mutex.RUnlock()

	if !path.IsAbs(name) {
		name = MapPath(name)
	}

    /*通过路径名称获取bpf map*/
	return mapRegister[name]
}

// GetOpenMaps returns a slice of all open BPF maps. This is identical to
// calling GetMap() on all open maps.
func GetOpenMaps() []*models.BPFMap {
	// create a copy of mapRegister so we can unlock the mutex again as
	// locking Map.lock inside of the mutex is not permitted
	mutex.RLock()
	maps := []*Map{}
	for _, m := range mapRegister {
	    /*收集注册的所有map*/
		maps = append(maps, m)
	}
	mutex.RUnlock()

	/*申请map数组*/
	mapList := make([]*models.BPFMap, len(maps))

    /*填充mapList*/
	i := 0
	for _, m := range maps {
		mapList[i] = m.GetModel()
		i++
	}

	return mapList
}
