// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2022 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DebugInfo groups some debugging related information on the agent
//
// swagger:model DebugInfo
type DebugInfo struct {

	// cilium memory map
	CiliumMemoryMap string `json:"cilium-memory-map,omitempty"`

	// cilium nodemonitor memory map
	CiliumNodemonitorMemoryMap string `json:"cilium-nodemonitor-memory-map,omitempty"`

	// cilium status
	CiliumStatus *StatusResponse `json:"cilium-status,omitempty"`

	// cilium version
	CiliumVersion string `json:"cilium-version,omitempty"`

	// encryption
	Encryption *DebugInfoEncryption `json:"encryption,omitempty"`

	// endpoint list
	EndpointList []*Endpoint `json:"endpoint-list"`

	// environment variables
	EnvironmentVariables []string `json:"environment-variables"`

	// kernel version
	KernelVersion string `json:"kernel-version,omitempty"`

	// policy
	Policy *Policy `json:"policy,omitempty"`

	// service list
	ServiceList []*Service `json:"service-list"`

	// subsystem
	Subsystem map[string]string `json:"subsystem,omitempty"`
}

// Validate validates this debug info
func (m *DebugInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCiliumStatus(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEncryption(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndpointList(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicy(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateServiceList(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DebugInfo) validateCiliumStatus(formats strfmt.Registry) error {

	if swag.IsZero(m.CiliumStatus) { // not required
		return nil
	}

	if m.CiliumStatus != nil {
		if err := m.CiliumStatus.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("cilium-status")
			}
			return err
		}
	}

	return nil
}

func (m *DebugInfo) validateEncryption(formats strfmt.Registry) error {

	if swag.IsZero(m.Encryption) { // not required
		return nil
	}

	if m.Encryption != nil {
		if err := m.Encryption.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("encryption")
			}
			return err
		}
	}

	return nil
}

func (m *DebugInfo) validateEndpointList(formats strfmt.Registry) error {

	if swag.IsZero(m.EndpointList) { // not required
		return nil
	}

	for i := 0; i < len(m.EndpointList); i++ {
		if swag.IsZero(m.EndpointList[i]) { // not required
			continue
		}

		if m.EndpointList[i] != nil {
			if err := m.EndpointList[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("endpoint-list" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DebugInfo) validatePolicy(formats strfmt.Registry) error {

	if swag.IsZero(m.Policy) { // not required
		return nil
	}

	if m.Policy != nil {
		if err := m.Policy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("policy")
			}
			return err
		}
	}

	return nil
}

func (m *DebugInfo) validateServiceList(formats strfmt.Registry) error {

	if swag.IsZero(m.ServiceList) { // not required
		return nil
	}

	for i := 0; i < len(m.ServiceList); i++ {
		if swag.IsZero(m.ServiceList[i]) { // not required
			continue
		}

		if m.ServiceList[i] != nil {
			if err := m.ServiceList[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("service-list" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *DebugInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DebugInfo) UnmarshalBinary(b []byte) error {
	var res DebugInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DebugInfoEncryption debug info encryption
//
// swagger:model DebugInfoEncryption
type DebugInfoEncryption struct {

	// Status of the Wireguard agent
	Wireguard *WireguardStatus `json:"wireguard,omitempty"`
}

// Validate validates this debug info encryption
func (m *DebugInfoEncryption) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateWireguard(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DebugInfoEncryption) validateWireguard(formats strfmt.Registry) error {

	if swag.IsZero(m.Wireguard) { // not required
		return nil
	}

	if m.Wireguard != nil {
		if err := m.Wireguard.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("encryption" + "." + "wireguard")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DebugInfoEncryption) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DebugInfoEncryption) UnmarshalBinary(b []byte) error {
	var res DebugInfoEncryption
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
