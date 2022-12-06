// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.15.8
// source: manage_service.proto

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

// ManageServiceClient is the client API for ManageService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ManageServiceClient interface {
	SayHello(ctx context.Context, in *HelloRequest, opts ...grpc.CallOption) (*HelloResponse, error)
}

type manageServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewManageServiceClient(cc grpc.ClientConnInterface) ManageServiceClient {
	return &manageServiceClient{cc}
}

func (c *manageServiceClient) SayHello(ctx context.Context, in *HelloRequest, opts ...grpc.CallOption) (*HelloResponse, error) {
	out := new(HelloResponse)
	err := c.cc.Invoke(ctx, "/helium_proto.ManageService/SayHello", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ManageServiceServer is the server API for ManageService service.
// All implementations must embed UnimplementedManageServiceServer
// for forward compatibility
type ManageServiceServer interface {
	SayHello(context.Context, *HelloRequest) (*HelloResponse, error)
	mustEmbedUnimplementedManageServiceServer()
}

// UnimplementedManageServiceServer must be embedded to have forward compatible implementations.
type UnimplementedManageServiceServer struct {
}

func (UnimplementedManageServiceServer) SayHello(context.Context, *HelloRequest) (*HelloResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SayHello not implemented")
}
func (UnimplementedManageServiceServer) mustEmbedUnimplementedManageServiceServer() {}

// UnsafeManageServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ManageServiceServer will
// result in compilation errors.
type UnsafeManageServiceServer interface {
	mustEmbedUnimplementedManageServiceServer()
}

func RegisterManageServiceServer(s grpc.ServiceRegistrar, srv ManageServiceServer) {
	s.RegisterService(&ManageService_ServiceDesc, srv)
}

func _ManageService_SayHello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HelloRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ManageServiceServer).SayHello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/helium_proto.ManageService/SayHello",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ManageServiceServer).SayHello(ctx, req.(*HelloRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ManageService_ServiceDesc is the grpc.ServiceDesc for ManageService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ManageService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "helium_proto.ManageService",
	HandlerType: (*ManageServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SayHello",
			Handler:    _ManageService_SayHello_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "manage_service.proto",
}
