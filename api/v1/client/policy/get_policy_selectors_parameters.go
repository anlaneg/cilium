// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetPolicySelectorsParams creates a new GetPolicySelectorsParams object
// with the default values initialized.
func NewGetPolicySelectorsParams() *GetPolicySelectorsParams {

	return &GetPolicySelectorsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetPolicySelectorsParamsWithTimeout creates a new GetPolicySelectorsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetPolicySelectorsParamsWithTimeout(timeout time.Duration) *GetPolicySelectorsParams {

	return &GetPolicySelectorsParams{

		timeout: timeout,
	}
}

// NewGetPolicySelectorsParamsWithContext creates a new GetPolicySelectorsParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetPolicySelectorsParamsWithContext(ctx context.Context) *GetPolicySelectorsParams {

	return &GetPolicySelectorsParams{

		Context: ctx,
	}
}

// NewGetPolicySelectorsParamsWithHTTPClient creates a new GetPolicySelectorsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetPolicySelectorsParamsWithHTTPClient(client *http.Client) *GetPolicySelectorsParams {

	return &GetPolicySelectorsParams{
		HTTPClient: client,
	}
}

/*GetPolicySelectorsParams contains all the parameters to send to the API endpoint
for the get policy selectors operation typically these are written to a http.Request
*/
type GetPolicySelectorsParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get policy selectors params
func (o *GetPolicySelectorsParams) WithTimeout(timeout time.Duration) *GetPolicySelectorsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get policy selectors params
func (o *GetPolicySelectorsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get policy selectors params
func (o *GetPolicySelectorsParams) WithContext(ctx context.Context) *GetPolicySelectorsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get policy selectors params
func (o *GetPolicySelectorsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get policy selectors params
func (o *GetPolicySelectorsParams) WithHTTPClient(client *http.Client) *GetPolicySelectorsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get policy selectors params
func (o *GetPolicySelectorsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetPolicySelectorsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
