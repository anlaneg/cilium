// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2022 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/models"
)

// GetFqdnNamesOKCode is the HTTP code returned for type GetFqdnNamesOK
const GetFqdnNamesOKCode int = 200

/*GetFqdnNamesOK Success

swagger:response getFqdnNamesOK
*/
type GetFqdnNamesOK struct {

	/*
	  In: Body
	*/
	Payload *models.NameManager `json:"body,omitempty"`
}

// NewGetFqdnNamesOK creates GetFqdnNamesOK with default headers values
func NewGetFqdnNamesOK() *GetFqdnNamesOK {

	return &GetFqdnNamesOK{}
}

// WithPayload adds the payload to the get fqdn names o k response
func (o *GetFqdnNamesOK) WithPayload(payload *models.NameManager) *GetFqdnNamesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get fqdn names o k response
func (o *GetFqdnNamesOK) SetPayload(payload *models.NameManager) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetFqdnNamesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetFqdnNamesBadRequestCode is the HTTP code returned for type GetFqdnNamesBadRequest
const GetFqdnNamesBadRequestCode int = 400

/*GetFqdnNamesBadRequest Invalid request (error parsing parameters)

swagger:response getFqdnNamesBadRequest
*/
type GetFqdnNamesBadRequest struct {

	/*
	  In: Body
	*/
	Payload models.Error `json:"body,omitempty"`
}

// NewGetFqdnNamesBadRequest creates GetFqdnNamesBadRequest with default headers values
func NewGetFqdnNamesBadRequest() *GetFqdnNamesBadRequest {

	return &GetFqdnNamesBadRequest{}
}

// WithPayload adds the payload to the get fqdn names bad request response
func (o *GetFqdnNamesBadRequest) WithPayload(payload models.Error) *GetFqdnNamesBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get fqdn names bad request response
func (o *GetFqdnNamesBadRequest) SetPayload(payload models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetFqdnNamesBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
