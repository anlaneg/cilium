// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2022 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ProxyRedirect Configured proxy redirection state
//
// swagger:model ProxyRedirect
type ProxyRedirect struct {

	// Name of the proxy redirect
	Name string `json:"name,omitempty"`

	// Name of the proxy this redirect points to
	Proxy string `json:"proxy,omitempty"`

	// Host port that this redirect points to
	ProxyPort int64 `json:"proxy-port,omitempty"`
}

// Validate validates this proxy redirect
func (m *ProxyRedirect) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ProxyRedirect) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ProxyRedirect) UnmarshalBinary(b []byte) error {
	var res ProxyRedirect
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
