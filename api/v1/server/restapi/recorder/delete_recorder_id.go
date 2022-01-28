// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2022 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package recorder

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// DeleteRecorderIDHandlerFunc turns a function with the right signature into a delete recorder ID handler
type DeleteRecorderIDHandlerFunc func(DeleteRecorderIDParams) middleware.Responder

// Handle executing the request and returning a response
func (fn DeleteRecorderIDHandlerFunc) Handle(params DeleteRecorderIDParams) middleware.Responder {
	return fn(params)
}

// DeleteRecorderIDHandler interface for that can handle valid delete recorder ID params
type DeleteRecorderIDHandler interface {
	Handle(DeleteRecorderIDParams) middleware.Responder
}

// NewDeleteRecorderID creates a new http.Handler for the delete recorder ID operation
func NewDeleteRecorderID(ctx *middleware.Context, handler DeleteRecorderIDHandler) *DeleteRecorderID {
	return &DeleteRecorderID{Context: ctx, Handler: handler}
}

/*DeleteRecorderID swagger:route DELETE /recorder/{id} recorder deleteRecorderId

Delete a recorder

*/
type DeleteRecorderID struct {
	Context *middleware.Context
	Handler DeleteRecorderIDHandler
}

func (o *DeleteRecorderID) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewDeleteRecorderIDParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
