// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2021 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetServiceHandlerFunc turns a function with the right signature into a get service handler
type GetServiceHandlerFunc func(GetServiceParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetServiceHandlerFunc) Handle(params GetServiceParams) middleware.Responder {
	return fn(params)
}

// GetServiceHandler interface for that can handle valid get service params
type GetServiceHandler interface {
	Handle(GetServiceParams) middleware.Responder
}

// NewGetService creates a new http.Handler for the get service operation
func NewGetService(ctx *middleware.Context, handler GetServiceHandler) *GetService {
	return &GetService{Context: ctx, Handler: handler}
}

/*GetService swagger:route GET /service service getService

Retrieve list of all services

*/
type GetService struct {
	Context *middleware.Context
	Handler GetServiceHandler
}

func (o *GetService) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewGetServiceParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
