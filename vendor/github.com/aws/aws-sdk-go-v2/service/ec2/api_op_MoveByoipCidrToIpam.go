// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Move an BYOIP IPv4 CIDR to IPAM from a public IPv4 pool. If you already have an
// IPv4 BYOIP CIDR with Amazon Web Services, you can move the CIDR to IPAM from a
// public IPv4 pool. You cannot move an IPv6 CIDR to IPAM. If you are bringing a
// new IP address to Amazon Web Services for the first time, complete the steps in
// Tutorial: BYOIP address CIDRs to IPAM.
func (c *Client) MoveByoipCidrToIpam(ctx context.Context, params *MoveByoipCidrToIpamInput, optFns ...func(*Options)) (*MoveByoipCidrToIpamOutput, error) {
	if params == nil {
		params = &MoveByoipCidrToIpamInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "MoveByoipCidrToIpam", params, optFns, c.addOperationMoveByoipCidrToIpamMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*MoveByoipCidrToIpamOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type MoveByoipCidrToIpamInput struct {

	// The BYOIP CIDR.
	//
	// This member is required.
	Cidr *string

	// The IPAM pool ID.
	//
	// This member is required.
	IpamPoolId *string

	// The Amazon Web Services account ID of the owner of the IPAM pool.
	//
	// This member is required.
	IpamPoolOwner *string

	// A check for whether you have the required permissions for the action without
	// actually making the request and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	noSmithyDocumentSerde
}

type MoveByoipCidrToIpamOutput struct {

	// Information about an address range that is provisioned for use with your Amazon
	// Web Services resources through bring your own IP addresses (BYOIP).
	ByoipCidr *types.ByoipCidr

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationMoveByoipCidrToIpamMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpMoveByoipCidrToIpam{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpMoveByoipCidrToIpam{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpMoveByoipCidrToIpamValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opMoveByoipCidrToIpam(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opMoveByoipCidrToIpam(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "MoveByoipCidrToIpam",
	}
}
