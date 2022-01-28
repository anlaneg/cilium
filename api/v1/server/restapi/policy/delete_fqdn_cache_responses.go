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

// DeleteFqdnCacheOKCode is the HTTP code returned for type DeleteFqdnCacheOK
const DeleteFqdnCacheOKCode int = 200

/*DeleteFqdnCacheOK Success

swagger:response deleteFqdnCacheOK
*/
type DeleteFqdnCacheOK struct {
}

// NewDeleteFqdnCacheOK creates DeleteFqdnCacheOK with default headers values
func NewDeleteFqdnCacheOK() *DeleteFqdnCacheOK {

	return &DeleteFqdnCacheOK{}
}

// WriteResponse to the client
func (o *DeleteFqdnCacheOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}

// DeleteFqdnCacheBadRequestCode is the HTTP code returned for type DeleteFqdnCacheBadRequest
const DeleteFqdnCacheBadRequestCode int = 400

/*DeleteFqdnCacheBadRequest Invalid request (error parsing parameters)

swagger:response deleteFqdnCacheBadRequest
*/
type DeleteFqdnCacheBadRequest struct {

	/*
	  In: Body
	*/
	Payload models.Error `json:"body,omitempty"`
}

// NewDeleteFqdnCacheBadRequest creates DeleteFqdnCacheBadRequest with default headers values
func NewDeleteFqdnCacheBadRequest() *DeleteFqdnCacheBadRequest {

	return &DeleteFqdnCacheBadRequest{}
}

// WithPayload adds the payload to the delete fqdn cache bad request response
func (o *DeleteFqdnCacheBadRequest) WithPayload(payload models.Error) *DeleteFqdnCacheBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete fqdn cache bad request response
func (o *DeleteFqdnCacheBadRequest) SetPayload(payload models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteFqdnCacheBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
