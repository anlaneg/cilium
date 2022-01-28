// Code generated by go-swagger; DO NOT EDIT.

// Copyright 2017-2022 Authors of Cilium
// SPDX-License-Identifier: Apache-2.0

package prefilter

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/api/v1/models"
)

// GetPrefilterReader is a Reader for the GetPrefilter structure.
type GetPrefilterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetPrefilterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetPrefilterOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewGetPrefilterFailure()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetPrefilterOK creates a GetPrefilterOK with default headers values
func NewGetPrefilterOK() *GetPrefilterOK {
	return &GetPrefilterOK{}
}

/*GetPrefilterOK handles this case with default header values.

Success
*/
type GetPrefilterOK struct {
	Payload *models.Prefilter
}

func (o *GetPrefilterOK) Error() string {
	return fmt.Sprintf("[GET /prefilter][%d] getPrefilterOK  %+v", 200, o.Payload)
}

func (o *GetPrefilterOK) GetPayload() *models.Prefilter {
	return o.Payload
}

func (o *GetPrefilterOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Prefilter)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetPrefilterFailure creates a GetPrefilterFailure with default headers values
func NewGetPrefilterFailure() *GetPrefilterFailure {
	return &GetPrefilterFailure{}
}

/*GetPrefilterFailure handles this case with default header values.

Prefilter get failed
*/
type GetPrefilterFailure struct {
	Payload models.Error
}

func (o *GetPrefilterFailure) Error() string {
	return fmt.Sprintf("[GET /prefilter][%d] getPrefilterFailure  %+v", 500, o.Payload)
}

func (o *GetPrefilterFailure) GetPayload() models.Error {
	return o.Payload
}

func (o *GetPrefilterFailure) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
