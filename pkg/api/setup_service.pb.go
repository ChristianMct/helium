// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.12
// source: setup_service.proto

package api

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_setup_service_proto protoreflect.FileDescriptor

var file_setup_service_proto_rawDesc = []byte{
	0x0a, 0x13, 0x73, 0x65, 0x74, 0x75, 0x70, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x32, 0x9e, 0x02, 0x0a, 0x0c, 0x53, 0x65, 0x74, 0x75, 0x70, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x48, 0x0a, 0x10, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x46, 0x6f,
	0x72, 0x53, 0x65, 0x74, 0x75, 0x70, 0x12, 0x12, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x56, 0x6f, 0x69, 0x64, 0x1a, 0x1c, 0x2e, 0x68, 0x65, 0x6c,
	0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63,
	0x6f, 0x6c, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x22, 0x00, 0x30, 0x01, 0x12, 0x4d, 0x0a, 0x14,
	0x47, 0x65, 0x74, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x75,
	0x74, 0x70, 0x75, 0x74, 0x12, 0x18, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x1a, 0x19,
	0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x41, 0x67,
	0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x00, 0x12, 0x35, 0x0a, 0x08, 0x50,
	0x75, 0x74, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d,
	0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x1a, 0x12, 0x2e, 0x68,
	0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x56, 0x6f, 0x69, 0x64,
	0x22, 0x00, 0x12, 0x3e, 0x0a, 0x0c, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x53, 0x68, 0x61, 0x72,
	0x65, 0x73, 0x12, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x1a, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d,
	0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x22, 0x00, 0x28, 0x01,
	0x30, 0x01, 0x42, 0x21, 0x5a, 0x1f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x6c, 0x64, 0x73, 0x65, 0x63, 0x2f, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6b,
	0x67, 0x2f, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_setup_service_proto_goTypes = []interface{}{
	(*Void)(nil),           // 0: helium_proto.Void
	(*ProtocolID)(nil),     // 1: helium_proto.ProtocolID
	(*Share)(nil),          // 2: helium_proto.Share
	(*ProtocolUpdate)(nil), // 3: helium_proto.ProtocolUpdate
	(*Aggregation)(nil),    // 4: helium_proto.Aggregation
}
var file_setup_service_proto_depIdxs = []int32{
	0, // 0: helium_proto.SetupService.RegisterForSetup:input_type -> helium_proto.Void
	1, // 1: helium_proto.SetupService.GetAggregationOutput:input_type -> helium_proto.ProtocolID
	2, // 2: helium_proto.SetupService.PutShare:input_type -> helium_proto.Share
	2, // 3: helium_proto.SetupService.StreamShares:input_type -> helium_proto.Share
	3, // 4: helium_proto.SetupService.RegisterForSetup:output_type -> helium_proto.ProtocolUpdate
	4, // 5: helium_proto.SetupService.GetAggregationOutput:output_type -> helium_proto.Aggregation
	0, // 6: helium_proto.SetupService.PutShare:output_type -> helium_proto.Void
	2, // 7: helium_proto.SetupService.StreamShares:output_type -> helium_proto.Share
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_setup_service_proto_init() }
func file_setup_service_proto_init() {
	if File_setup_service_proto != nil {
		return
	}
	file_common_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_setup_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_setup_service_proto_goTypes,
		DependencyIndexes: file_setup_service_proto_depIdxs,
	}.Build()
	File_setup_service_proto = out.File
	file_setup_service_proto_rawDesc = nil
	file_setup_service_proto_goTypes = nil
	file_setup_service_proto_depIdxs = nil
}
