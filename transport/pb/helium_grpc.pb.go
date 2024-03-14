// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.3
// source: helium.proto

package pb

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

// HeliumClient is the client API for Helium service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type HeliumClient interface {
	// Register registers the caller as a peer node to the helium server
	Register(ctx context.Context, in *Void, opts ...grpc.CallOption) (Helium_RegisterClient, error)
	// PutShare pushes the caller's share in the protocol described by the Share.ShareDescriptor
	// field to the callee.
	PutShare(ctx context.Context, in *Share, opts ...grpc.CallOption) (*Void, error)
	// GetShare queries the aggregation output of the protocol described by PrototocolDescriptor
	GetAggregationOutput(ctx context.Context, in *ProtocolDescriptor, opts ...grpc.CallOption) (*AggregationOutput, error)
	// GetCiphertext queries the ciphertext with the given ID from the callee
	GetCiphertext(ctx context.Context, in *CiphertextID, opts ...grpc.CallOption) (*Ciphertext, error)
	// PutCiphertext pushes the ciphertext to the callee
	PutCiphertext(ctx context.Context, in *Ciphertext, opts ...grpc.CallOption) (*CiphertextID, error)
}

type heliumClient struct {
	cc grpc.ClientConnInterface
}

func NewHeliumClient(cc grpc.ClientConnInterface) HeliumClient {
	return &heliumClient{cc}
}

func (c *heliumClient) Register(ctx context.Context, in *Void, opts ...grpc.CallOption) (Helium_RegisterClient, error) {
	stream, err := c.cc.NewStream(ctx, &Helium_ServiceDesc.Streams[0], "/helium_proto.Helium/Register", opts...)
	if err != nil {
		return nil, err
	}
	x := &heliumRegisterClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Helium_RegisterClient interface {
	Recv() (*Event, error)
	grpc.ClientStream
}

type heliumRegisterClient struct {
	grpc.ClientStream
}

func (x *heliumRegisterClient) Recv() (*Event, error) {
	m := new(Event)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *heliumClient) PutShare(ctx context.Context, in *Share, opts ...grpc.CallOption) (*Void, error) {
	out := new(Void)
	err := c.cc.Invoke(ctx, "/helium_proto.Helium/PutShare", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heliumClient) GetAggregationOutput(ctx context.Context, in *ProtocolDescriptor, opts ...grpc.CallOption) (*AggregationOutput, error) {
	out := new(AggregationOutput)
	err := c.cc.Invoke(ctx, "/helium_proto.Helium/GetAggregationOutput", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heliumClient) GetCiphertext(ctx context.Context, in *CiphertextID, opts ...grpc.CallOption) (*Ciphertext, error) {
	out := new(Ciphertext)
	err := c.cc.Invoke(ctx, "/helium_proto.Helium/GetCiphertext", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *heliumClient) PutCiphertext(ctx context.Context, in *Ciphertext, opts ...grpc.CallOption) (*CiphertextID, error) {
	out := new(CiphertextID)
	err := c.cc.Invoke(ctx, "/helium_proto.Helium/PutCiphertext", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HeliumServer is the server API for Helium service.
// All implementations must embed UnimplementedHeliumServer
// for forward compatibility
type HeliumServer interface {
	// Register registers the caller as a peer node to the helium server
	Register(*Void, Helium_RegisterServer) error
	// PutShare pushes the caller's share in the protocol described by the Share.ShareDescriptor
	// field to the callee.
	PutShare(context.Context, *Share) (*Void, error)
	// GetShare queries the aggregation output of the protocol described by PrototocolDescriptor
	GetAggregationOutput(context.Context, *ProtocolDescriptor) (*AggregationOutput, error)
	// GetCiphertext queries the ciphertext with the given ID from the callee
	GetCiphertext(context.Context, *CiphertextID) (*Ciphertext, error)
	// PutCiphertext pushes the ciphertext to the callee
	PutCiphertext(context.Context, *Ciphertext) (*CiphertextID, error)
	mustEmbedUnimplementedHeliumServer()
}

// UnimplementedHeliumServer must be embedded to have forward compatible implementations.
type UnimplementedHeliumServer struct {
}

func (UnimplementedHeliumServer) Register(*Void, Helium_RegisterServer) error {
	return status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedHeliumServer) PutShare(context.Context, *Share) (*Void, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PutShare not implemented")
}
func (UnimplementedHeliumServer) GetAggregationOutput(context.Context, *ProtocolDescriptor) (*AggregationOutput, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAggregationOutput not implemented")
}
func (UnimplementedHeliumServer) GetCiphertext(context.Context, *CiphertextID) (*Ciphertext, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCiphertext not implemented")
}
func (UnimplementedHeliumServer) PutCiphertext(context.Context, *Ciphertext) (*CiphertextID, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PutCiphertext not implemented")
}
func (UnimplementedHeliumServer) mustEmbedUnimplementedHeliumServer() {}

// UnsafeHeliumServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to HeliumServer will
// result in compilation errors.
type UnsafeHeliumServer interface {
	mustEmbedUnimplementedHeliumServer()
}

func RegisterHeliumServer(s grpc.ServiceRegistrar, srv HeliumServer) {
	s.RegisterService(&Helium_ServiceDesc, srv)
}

func _Helium_Register_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Void)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(HeliumServer).Register(m, &heliumRegisterServer{stream})
}

type Helium_RegisterServer interface {
	Send(*Event) error
	grpc.ServerStream
}

type heliumRegisterServer struct {
	grpc.ServerStream
}

func (x *heliumRegisterServer) Send(m *Event) error {
	return x.ServerStream.SendMsg(m)
}

func _Helium_PutShare_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Share)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeliumServer).PutShare(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/helium_proto.Helium/PutShare",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeliumServer).PutShare(ctx, req.(*Share))
	}
	return interceptor(ctx, in, info, handler)
}

func _Helium_GetAggregationOutput_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProtocolDescriptor)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeliumServer).GetAggregationOutput(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/helium_proto.Helium/GetAggregationOutput",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeliumServer).GetAggregationOutput(ctx, req.(*ProtocolDescriptor))
	}
	return interceptor(ctx, in, info, handler)
}

func _Helium_GetCiphertext_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CiphertextID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeliumServer).GetCiphertext(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/helium_proto.Helium/GetCiphertext",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeliumServer).GetCiphertext(ctx, req.(*CiphertextID))
	}
	return interceptor(ctx, in, info, handler)
}

func _Helium_PutCiphertext_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Ciphertext)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HeliumServer).PutCiphertext(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/helium_proto.Helium/PutCiphertext",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HeliumServer).PutCiphertext(ctx, req.(*Ciphertext))
	}
	return interceptor(ctx, in, info, handler)
}

// Helium_ServiceDesc is the grpc.ServiceDesc for Helium service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Helium_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "helium_proto.Helium",
	HandlerType: (*HeliumServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PutShare",
			Handler:    _Helium_PutShare_Handler,
		},
		{
			MethodName: "GetAggregationOutput",
			Handler:    _Helium_GetAggregationOutput_Handler,
		},
		{
			MethodName: "GetCiphertext",
			Handler:    _Helium_GetCiphertext_Handler,
		},
		{
			MethodName: "PutCiphertext",
			Handler:    _Helium_PutCiphertext_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Register",
			Handler:       _Helium_Register_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "helium.proto",
}