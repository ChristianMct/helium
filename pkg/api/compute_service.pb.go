// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.25.2
// source: compute_service.proto

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

var File_compute_service_proto protoreflect.FileDescriptor

var file_compute_service_proto_rawDesc = []byte{
	0x0a, 0x15, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x32, 0xe9, 0x02, 0x0a, 0x0e, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x49, 0x0a, 0x12, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74,
	0x65, 0x72, 0x46, 0x6f, 0x72, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x12, 0x12, 0x2e, 0x68,
	0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x56, 0x6f, 0x69, 0x64,
	0x1a, 0x1b, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x22, 0x00, 0x30,
	0x01, 0x12, 0x4c, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65,
	0x78, 0x74, 0x12, 0x1f, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x22, 0x00, 0x12,
	0x47, 0x0a, 0x0d, 0x50, 0x75, 0x74, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74,
	0x12, 0x18, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x1a, 0x1a, 0x2e, 0x68, 0x65, 0x6c,
	0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x74, 0x65, 0x78, 0x74, 0x49, 0x44, 0x22, 0x00, 0x12, 0x35, 0x0a, 0x08, 0x50, 0x75, 0x74, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x12, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x1a, 0x12, 0x2e, 0x68, 0x65, 0x6c, 0x69,
	0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x56, 0x6f, 0x69, 0x64, 0x22, 0x00, 0x12,
	0x3e, 0x0a, 0x0c, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x53, 0x68, 0x61, 0x72, 0x65, 0x73, 0x12,
	0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53,
	0x68, 0x61, 0x72, 0x65, 0x1a, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x42,
	0x21, 0x5a, 0x1f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c, 0x64,
	0x73, 0x65, 0x63, 0x2f, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x61,
	0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_compute_service_proto_goTypes = []interface{}{
	(*Void)(nil),              // 0: helium_proto.Void
	(*CiphertextRequest)(nil), // 1: helium_proto.CiphertextRequest
	(*Ciphertext)(nil),        // 2: helium_proto.Ciphertext
	(*Share)(nil),             // 3: helium_proto.Share
	(*ComputeUpdate)(nil),     // 4: helium_proto.ComputeUpdate
	(*CiphertextID)(nil),      // 5: helium_proto.CiphertextID
}
var file_compute_service_proto_depIdxs = []int32{
	0, // 0: helium_proto.ComputeService.RegisterForCompute:input_type -> helium_proto.Void
	1, // 1: helium_proto.ComputeService.GetCiphertext:input_type -> helium_proto.CiphertextRequest
	2, // 2: helium_proto.ComputeService.PutCiphertext:input_type -> helium_proto.Ciphertext
	3, // 3: helium_proto.ComputeService.PutShare:input_type -> helium_proto.Share
	3, // 4: helium_proto.ComputeService.StreamShares:input_type -> helium_proto.Share
	4, // 5: helium_proto.ComputeService.RegisterForCompute:output_type -> helium_proto.ComputeUpdate
	2, // 6: helium_proto.ComputeService.GetCiphertext:output_type -> helium_proto.Ciphertext
	5, // 7: helium_proto.ComputeService.PutCiphertext:output_type -> helium_proto.CiphertextID
	0, // 8: helium_proto.ComputeService.PutShare:output_type -> helium_proto.Void
	3, // 9: helium_proto.ComputeService.StreamShares:output_type -> helium_proto.Share
	5, // [5:10] is the sub-list for method output_type
	0, // [0:5] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_compute_service_proto_init() }
func file_compute_service_proto_init() {
	if File_compute_service_proto != nil {
		return
	}
	file_common_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_compute_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_compute_service_proto_goTypes,
		DependencyIndexes: file_compute_service_proto_depIdxs,
	}.Build()
	File_compute_service_proto = out.File
	file_compute_service_proto_rawDesc = nil
	file_compute_service_proto_goTypes = nil
	file_compute_service_proto_depIdxs = nil
}
