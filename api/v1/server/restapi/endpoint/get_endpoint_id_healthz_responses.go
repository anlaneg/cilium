// Code generated by go-swagger; DO NOT EDIT.

// Copyright Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package endpoint

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/cilium/cilium/api/v1/models"
)

// GetEndpointIDHealthzOKCode is the HTTP code returned for type GetEndpointIDHealthzOK
const GetEndpointIDHealthzOKCode int = 200

/*GetEndpointIDHealthzOK Success

swagger:response getEndpointIdHealthzOK
*/
type GetEndpointIDHealthzOK struct {

	/*
	  In: Body
	*/
	Payload *models.EndpointHealth `json:"body,omitempty"`
}

// NewGetEndpointIDHealthzOK creates GetEndpointIDHealthzOK with default headers values
func NewGetEndpointIDHealthzOK() *GetEndpointIDHealthzOK {

	return &GetEndpointIDHealthzOK{}
}

// WithPayload adds the payload to the get endpoint Id healthz o k response
func (o *GetEndpointIDHealthzOK) WithPayload(payload *models.EndpointHealth) *GetEndpointIDHealthzOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the get endpoint Id healthz o k response
func (o *GetEndpointIDHealthzOK) SetPayload(payload *models.EndpointHealth) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *GetEndpointIDHealthzOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// GetEndpointIDHealthzInvalidCode is the HTTP code returned for type GetEndpointIDHealthzInvalid
const GetEndpointIDHealthzInvalidCode int = 400

/*GetEndpointIDHealthzInvalid Invalid identity provided

swagger:response getEndpointIdHealthzInvalid
*/
type GetEndpointIDHealthzInvalid struct {
}

// NewGetEndpointIDHealthzInvalid creates GetEndpointIDHealthzInvalid with default headers values
func NewGetEndpointIDHealthzInvalid() *GetEndpointIDHealthzInvalid {

	return &GetEndpointIDHealthzInvalid{}
}

// WriteResponse to the client
func (o *GetEndpointIDHealthzInvalid) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(400)
}

// GetEndpointIDHealthzNotFoundCode is the HTTP code returned for type GetEndpointIDHealthzNotFound
const GetEndpointIDHealthzNotFoundCode int = 404

/*GetEndpointIDHealthzNotFound Endpoint not found

swagger:response getEndpointIdHealthzNotFound
*/
type GetEndpointIDHealthzNotFound struct {
}

// NewGetEndpointIDHealthzNotFound creates GetEndpointIDHealthzNotFound with default headers values
func NewGetEndpointIDHealthzNotFound() *GetEndpointIDHealthzNotFound {

	return &GetEndpointIDHealthzNotFound{}
}

// WriteResponse to the client
func (o *GetEndpointIDHealthzNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(404)
}

// GetEndpointIDHealthzTooManyRequestsCode is the HTTP code returned for type GetEndpointIDHealthzTooManyRequests
const GetEndpointIDHealthzTooManyRequestsCode int = 429

/*GetEndpointIDHealthzTooManyRequests Rate-limiting too many requests in the given time frame

swagger:response getEndpointIdHealthzTooManyRequests
*/
type GetEndpointIDHealthzTooManyRequests struct {
}

// NewGetEndpointIDHealthzTooManyRequests creates GetEndpointIDHealthzTooManyRequests with default headers values
func NewGetEndpointIDHealthzTooManyRequests() *GetEndpointIDHealthzTooManyRequests {

	return &GetEndpointIDHealthzTooManyRequests{}
}

// WriteResponse to the client
func (o *GetEndpointIDHealthzTooManyRequests) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(429)
}
