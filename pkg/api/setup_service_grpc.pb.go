// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.12
// source: setup_service.proto

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	SetupService_RegisterForSetup_FullMethodName     = "/helium_proto.SetupService/RegisterForSetup"
	SetupService_GetAggregationOutput_FullMethodName = "/helium_proto.SetupService/GetAggregationOutput"
	SetupService_PutShare_FullMethodName             = "/helium_proto.SetupService/PutShare"
	SetupService_StreamShares_FullMethodName         = "/helium_proto.SetupService/StreamShares"
)

// SetupServiceClient is the client API for SetupService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SetupServiceClient interface {
	RegisterForSetup(ctx context.Context, in *Void, opts ...grpc.CallOption) (SetupService_RegisterForSetupClient, error)
	GetAggregationOutput(ctx context.Context, in *ProtocolID, opts ...grpc.CallOption) (*Aggregation, error)
	// PutShare is used to push the caller's share in the protocol described by the Share.ShareDescriptor
	// field to the callee.
	PutShare(ctx context.Context, in *Share, opts ...grpc.CallOption) (*Void, error)
	// StreamShares is a bidirectional stream of shares between the client and server
	StreamShares(ctx context.Context, opts ...grpc.CallOption) (SetupService_StreamSharesClient, error)
}

type setupServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewSetupServiceClient(cc grpc.ClientConnInterface) SetupServiceClient {
	return &setupServiceClient{cc}
}

func (c *setupServiceClient) RegisterForSetup(ctx context.Context, in *Void, opts ...grpc.CallOption) (SetupService_RegisterForSetupClient, error) {
	stream, err := c.cc.NewStream(ctx, &SetupService_ServiceDesc.Streams[0], SetupService_RegisterForSetup_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &setupServiceRegisterForSetupClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type SetupService_RegisterForSetupClient interface {
	Recv() (*ProtocolUpdate, error)
	grpc.ClientStream
}

type setupServiceRegisterForSetupClient struct {
	grpc.ClientStream
}

func (x *setupServiceRegisterForSetupClient) Recv() (*ProtocolUpdate, error) {
	m := new(ProtocolUpdate)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *setupServiceClient) GetAggregationOutput(ctx context.Context, in *ProtocolID, opts ...grpc.CallOption) (*Aggregation, error) {
	out := new(Aggregation)
	err := c.cc.Invoke(ctx, SetupService_GetAggregationOutput_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *setupServiceClient) PutShare(ctx context.Context, in *Share, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, SetupService_PutShare_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *setupServiceClient) StreamShares(ctx context.Context, opts ...grpc.CallOption) (SetupService_StreamSharesClient, error) {
	stream, err := c.cc.NewStream(ctx, &SetupService_ServiceDesc.Streams[1], SetupService_StreamShares_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &setupServiceStreamSharesClient{stream}
	return x, nil
}

type SetupService_StreamSharesClient interface {
	Send(*Share) error
	Recv() (*Share, error)
	grpc.ClientStream
}

type setupServiceStreamSharesClient struct {
	grpc.ClientStream
}

func (x *setupServiceStreamSharesClient) Send(m *Share) error {
	return x.ClientStream.SendMsg(m)
}

func (x *setupServiceStreamSharesClient) Recv() (*Share, error) {
	m := new(Share)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// SetupServiceServer is the server API for SetupService service.
// All implementations must embed UnimplementedSetupServiceServer
// for forward compatibility
type SetupServiceServer interface {
	RegisterForSetup(*Void, SetupService_RegisterForSetupServer) error
	GetAggregationOutput(context.Context, *ProtocolID) (*Aggregation, error)
	// PutShare is used to push the caller's share in the protocol described by the Share.ShareDescriptor
	// field to the callee.
	PutShare(context.Context, *Share) (*Void, error)
	// StreamShares is a bidirectional stream of shares between the client and server
	StreamShares(SetupService_StreamSharesServer) error
	mustEmbedUnimplementedSetupServiceServer()
}

// UnimplementedSetupServiceServer must be embedded to have forward compatible implementations.
type UnimplementedSetupServiceServer struct {
}

func (UnimplementedSetupServiceServer) RegisterForSetup(*Void, SetupService_RegisterForSetupServer) error {
	return status.Errorf(codes.Unimplemented, "method RegisterForSetup not implemented")
}
func (UnimplementedSetupServiceServer) GetAggregationOutput(context.Context, *ProtocolID) (*Aggregation, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAggregationOutput not implemented")
}
func (UnimplementedSetupServiceServer) PutShare(context.Context, *Share) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PutShare not implemented")
}
func (UnimplementedSetupServiceServer) StreamShares(SetupService_StreamSharesServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamShares not implemented")
}
func (UnimplementedSetupServiceServer) mustEmbedUnimplementedSetupServiceServer() {}

// UnsafeSetupServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SetupServiceServer will
// result in compilation errors.
type UnsafeSetupServiceServer interface {
	mustEmbedUnimplementedSetupServiceServer()
}

func RegisterSetupServiceServer(s grpc.ServiceRegistrar, srv SetupServiceServer) {
	s.RegisterService(&SetupService_ServiceDesc, srv)
}

func _SetupService_RegisterForSetup_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Void)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(SetupServiceServer).RegisterForSetup(m, &setupServiceRegisterForSetupServer{stream})
}

type SetupService_RegisterForSetupServer interface {
	Send(*ProtocolUpdate) error
	grpc.ServerStream
}

type setupServiceRegisterForSetupServer struct {
	grpc.ServerStream
}

func (x *setupServiceRegisterForSetupServer) Send(m *ProtocolUpdate) error {
	return x.ServerStream.SendMsg(m)
}

func _SetupService_GetAggregationOutput_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProtocolID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SetupServiceServer).GetAggregationOutput(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SetupService_GetAggregationOutput_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SetupServiceServer).GetAggregationOutput(ctx, req.(*ProtocolID))
	}
	return interceptor(ctx, in, info, handler)
}

func _SetupService_PutShare_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Share)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SetupServiceServer).PutShare(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SetupService_PutShare_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SetupServiceServer).PutShare(ctx, req.(*Share))
	}
	return interceptor(ctx, in, info, handler)
}

func _SetupService_StreamShares_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(SetupServiceServer).StreamShares(&setupServiceStreamSharesServer{stream})
}

type SetupService_StreamSharesServer interface {
	Send(*Share) error
	Recv() (*Share, error)
	grpc.ServerStream
}

type setupServiceStreamSharesServer struct {
	grpc.ServerStream
}

func (x *setupServiceStreamSharesServer) Send(m *Share) error {
	return x.ServerStream.SendMsg(m)
}

func (x *setupServiceStreamSharesServer) Recv() (*Share, error) {
	m := new(Share)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// SetupService_ServiceDesc is the grpc.ServiceDesc for SetupService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SetupService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "helium_proto.SetupService",
	HandlerType: (*SetupServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAggregationOutput",
			Handler:    _SetupService_GetAggregationOutput_Handler,
		},
		{
			MethodName: "PutShare",
			Handler:    _SetupService_PutShare_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RegisterForSetup",
			Handler:       _SetupService_RegisterForSetup_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "StreamShares",
			Handler:       _SetupService_StreamShares_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "setup_service.proto",
}
