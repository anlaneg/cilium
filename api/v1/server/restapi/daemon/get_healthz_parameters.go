// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package daemon

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewGetHealthzParams creates a new GetHealthzParams object
// no default values defined in spec.
func NewGetHealthzParams() GetHealthzParams {

	return GetHealthzParams{}
}

// GetHealthzParams contains all the bound params for the get healthz operation
// typically these are obtained from a http.Request
//
// swagger:parameters GetHealthz
type GetHealthzParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Brief will return a brief representation of the Cilium status.

	  In: header
	*/
	Brief *bool
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetHealthzParams() beforehand.
func (o *GetHealthzParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if err := o.bindBrief(r.Header[http.CanonicalHeaderKey("brief")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindBrief binds and validates parameter Brief from header.
func (o *GetHealthzParams) bindBrief(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("brief", "header", "bool", raw)
	}
	o.Brief = &value

	return nil
}
