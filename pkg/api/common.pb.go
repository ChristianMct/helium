// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.4
// source: common.proto

package api

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ProtocolID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ProtocolID string `protobuf:"bytes,1,opt,name=ProtocolID,proto3" json:"ProtocolID,omitempty"`
}

func (x *ProtocolID) Reset() {
	*x = ProtocolID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProtocolID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProtocolID) ProtoMessage() {}

func (x *ProtocolID) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProtocolID.ProtoReflect.Descriptor instead.
func (*ProtocolID) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{0}
}

func (x *ProtocolID) GetProtocolID() string {
	if x != nil {
		return x.ProtocolID
	}
	return ""
}

type SessionID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SessionId string `protobuf:"bytes,1,opt,name=session_id,json=sessionId,proto3" json:"session_id,omitempty"`
}

func (x *SessionID) Reset() {
	*x = SessionID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionID) ProtoMessage() {}

func (x *SessionID) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionID.ProtoReflect.Descriptor instead.
func (*SessionID) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{1}
}

func (x *SessionID) GetSessionId() string {
	if x != nil {
		return x.SessionId
	}
	return ""
}

type NodeID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NodeId string `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
}

func (x *NodeID) Reset() {
	*x = NodeID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NodeID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeID) ProtoMessage() {}

func (x *NodeID) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeID.ProtoReflect.Descriptor instead.
func (*NodeID) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{2}
}

func (x *NodeID) GetNodeId() string {
	if x != nil {
		return x.NodeId
	}
	return ""
}

type Void struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Void) Reset() {
	*x = Void{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Void) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Void) ProtoMessage() {}

func (x *Void) ProtoReflect() protoreflect.Message {
	mi := &file_common_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Void.ProtoReflect.Descriptor instead.
func (*Void) Descriptor() ([]byte, []int) {
	return file_common_proto_rawDescGZIP(), []int{3}
}

var File_common_proto protoreflect.FileDescriptor

var file_common_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c,
	0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x2c, 0x0a, 0x0a,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x12, 0x1e, 0x0a, 0x0a, 0x50, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x22, 0x2a, 0x0a, 0x09, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x44, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x22, 0x21, 0x0a, 0x06, 0x4e, 0x6f, 0x64, 0x65, 0x49, 0x44,
	0x12, 0x17, 0x0a, 0x07, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x6e, 0x6f, 0x64, 0x65, 0x49, 0x64, 0x22, 0x06, 0x0a, 0x04, 0x56, 0x6f, 0x69,
	0x64, 0x42, 0x21, 0x5a, 0x1f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x6c, 0x64, 0x73, 0x65, 0x63, 0x2f, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6b, 0x67,
	0x2f, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_proto_rawDescOnce sync.Once
	file_common_proto_rawDescData = file_common_proto_rawDesc
)

func file_common_proto_rawDescGZIP() []byte {
	file_common_proto_rawDescOnce.Do(func() {
		file_common_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_proto_rawDescData)
	})
	return file_common_proto_rawDescData
}

var file_common_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_common_proto_goTypes = []interface{}{
	(*ProtocolID)(nil), // 0: helium_proto.ProtocolID
	(*SessionID)(nil),  // 1: helium_proto.SessionID
	(*NodeID)(nil),     // 2: helium_proto.NodeID
	(*Void)(nil),       // 3: helium_proto.Void
}
var file_common_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_common_proto_init() }
func file_common_proto_init() {
	if File_common_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProtocolID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_common_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_common_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NodeID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_common_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Void); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_common_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_proto_goTypes,
		DependencyIndexes: file_common_proto_depIdxs,
		MessageInfos:      file_common_proto_msgTypes,
	}.Build()
	File_common_proto = out.File
	file_common_proto_rawDesc = nil
	file_common_proto_goTypes = nil
	file_common_proto_depIdxs = nil
}
