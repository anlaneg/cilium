// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2022 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package recorder

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/api/v1/models"
)

// PutRecorderIDReader is a Reader for the PutRecorderID structure.
type PutRecorderIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PutRecorderIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPutRecorderIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 201:
		result := NewPutRecorderIDCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewPutRecorderIDFailure()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewPutRecorderIDOK creates a PutRecorderIDOK with default headers values
func NewPutRecorderIDOK() *PutRecorderIDOK {
	return &PutRecorderIDOK{}
}

/*PutRecorderIDOK handles this case with default header values.

Updated
*/
type PutRecorderIDOK struct {
}

func (o *PutRecorderIDOK) Error() string {
	return fmt.Sprintf("[PUT /recorder/{id}][%d] putRecorderIdOK ", 200)
}

func (o *PutRecorderIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPutRecorderIDCreated creates a PutRecorderIDCreated with default headers values
func NewPutRecorderIDCreated() *PutRecorderIDCreated {
	return &PutRecorderIDCreated{}
}

/*PutRecorderIDCreated handles this case with default header values.

Created
*/
type PutRecorderIDCreated struct {
}

func (o *PutRecorderIDCreated) Error() string {
	return fmt.Sprintf("[PUT /recorder/{id}][%d] putRecorderIdCreated ", 201)
}

func (o *PutRecorderIDCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPutRecorderIDFailure creates a PutRecorderIDFailure with default headers values
func NewPutRecorderIDFailure() *PutRecorderIDFailure {
	return &PutRecorderIDFailure{}
}

/*PutRecorderIDFailure handles this case with default header values.

Error while creating recorder
*/
type PutRecorderIDFailure struct {
	Payload models.Error
}

func (o *PutRecorderIDFailure) Error() string {
	return fmt.Sprintf("[PUT /recorder/{id}][%d] putRecorderIdFailure  %+v", 500, o.Payload)
}

func (o *PutRecorderIDFailure) GetPayload() models.Error {
	return o.Payload
}

func (o *PutRecorderIDFailure) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
