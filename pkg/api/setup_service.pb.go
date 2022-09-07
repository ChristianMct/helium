// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.4
// source: setup_service.proto

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

// ProtocolType is a enumerate type for identifying protocol types
type ProtocolType int32

const (
	ProtocolType_UNSPECIFIED ProtocolType = 0
	ProtocolType_SKG         ProtocolType = 1 // secret-key generation
	ProtocolType_CKG         ProtocolType = 2 // public encryption-key generation
	ProtocolType_RKG         ProtocolType = 3 // public relinearization-key generation
	ProtocolType_RTG         ProtocolType = 4 // public rotation-key generation
)

// Enum value maps for ProtocolType.
var (
	ProtocolType_name = map[int32]string{
		0: "UNSPECIFIED",
		1: "SKG",
		2: "CKG",
		3: "RKG",
		4: "RTG",
	}
	ProtocolType_value = map[string]int32{
		"UNSPECIFIED": 0,
		"SKG":         1,
		"CKG":         2,
		"RKG":         3,
		"RTG":         4,
	}
)

func (x ProtocolType) Enum() *ProtocolType {
	p := new(ProtocolType)
	*p = x
	return p
}

func (x ProtocolType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ProtocolType) Descriptor() protoreflect.EnumDescriptor {
	return file_setup_service_proto_enumTypes[0].Descriptor()
}

func (ProtocolType) Type() protoreflect.EnumType {
	return &file_setup_service_proto_enumTypes[0]
}

func (x ProtocolType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ProtocolType.Descriptor instead.
func (ProtocolType) EnumDescriptor() ([]byte, []int) {
	return file_setup_service_proto_rawDescGZIP(), []int{0}
}

// ProtocolDescriptor is a message type to describe a protocol by its type
//and arguments. It should be sufficient for parties to instantiate a protocol
//within a given session
type ProtocolDescriptor struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type ProtocolType      `protobuf:"varint,1,opt,name=Type,proto3,enum=helium_proto.ProtocolType" json:"Type,omitempty"`
	Args map[string]string `protobuf:"bytes,3,rep,name=Args,proto3" json:"Args,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ProtocolDescriptor) Reset() {
	*x = ProtocolDescriptor{}
	if protoimpl.UnsafeEnabled {
		mi := &file_setup_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProtocolDescriptor) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProtocolDescriptor) ProtoMessage() {}

func (x *ProtocolDescriptor) ProtoReflect() protoreflect.Message {
	mi := &file_setup_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProtocolDescriptor.ProtoReflect.Descriptor instead.
func (*ProtocolDescriptor) Descriptor() ([]byte, []int) {
	return file_setup_service_proto_rawDescGZIP(), []int{0}
}

func (x *ProtocolDescriptor) GetType() ProtocolType {
	if x != nil {
		return x.Type
	}
	return ProtocolType_UNSPECIFIED
}

func (x *ProtocolDescriptor) GetArgs() map[string]string {
	if x != nil {
		return x.Args
	}
	return nil
}

// ShareRequest represents a request for a party's share in the protocol
//defined by its ProtocolDesc field.
type ShareRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ProtocolID   *ProtocolID `protobuf:"bytes,1,opt,name=ProtocolID,proto3" json:"ProtocolID,omitempty"`
	Round        *uint64     `protobuf:"varint,2,opt,name=Round,proto3,oneof" json:"Round,omitempty"`
	Previous     *Share      `protobuf:"bytes,3,opt,name=Previous,proto3,oneof" json:"Previous,omitempty"`
	AggregateFor []*NodeID   `protobuf:"bytes,4,rep,name=AggregateFor,proto3" json:"AggregateFor,omitempty"`
	NoData       *bool       `protobuf:"varint,5,opt,name=NoData,proto3,oneof" json:"NoData,omitempty"`
}

func (x *ShareRequest) Reset() {
	*x = ShareRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_setup_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ShareRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ShareRequest) ProtoMessage() {}

func (x *ShareRequest) ProtoReflect() protoreflect.Message {
	mi := &file_setup_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ShareRequest.ProtoReflect.Descriptor instead.
func (*ShareRequest) Descriptor() ([]byte, []int) {
	return file_setup_service_proto_rawDescGZIP(), []int{1}
}

func (x *ShareRequest) GetProtocolID() *ProtocolID {
	if x != nil {
		return x.ProtocolID
	}
	return nil
}

func (x *ShareRequest) GetRound() uint64 {
	if x != nil && x.Round != nil {
		return *x.Round
	}
	return 0
}

func (x *ShareRequest) GetPrevious() *Share {
	if x != nil {
		return x.Previous
	}
	return nil
}

func (x *ShareRequest) GetAggregateFor() []*NodeID {
	if x != nil {
		return x.AggregateFor
	}
	return nil
}

func (x *ShareRequest) GetNoData() bool {
	if x != nil && x.NoData != nil {
		return *x.NoData
	}
	return false
}

// Share represents a party's share in the protocol described by its ProtocolDesc
//field.
type Share struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ProtocolID *ProtocolID `protobuf:"bytes,1,opt,name=ProtocolID,proto3" json:"ProtocolID,omitempty"`
	Round      *uint64     `protobuf:"varint,2,opt,name=Round,proto3,oneof" json:"Round,omitempty"`
	Share      []byte      `protobuf:"bytes,3,opt,name=share,proto3" json:"share,omitempty"`
}

func (x *Share) Reset() {
	*x = Share{}
	if protoimpl.UnsafeEnabled {
		mi := &file_setup_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Share) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Share) ProtoMessage() {}

func (x *Share) ProtoReflect() protoreflect.Message {
	mi := &file_setup_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Share.ProtoReflect.Descriptor instead.
func (*Share) Descriptor() ([]byte, []int) {
	return file_setup_service_proto_rawDescGZIP(), []int{2}
}

func (x *Share) GetProtocolID() *ProtocolID {
	if x != nil {
		return x.ProtocolID
	}
	return nil
}

func (x *Share) GetRound() uint64 {
	if x != nil && x.Round != nil {
		return *x.Round
	}
	return 0
}

func (x *Share) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

var File_setup_service_proto protoreflect.FileDescriptor

var file_setup_service_proto_rawDesc = []byte{
	0x0a, 0x13, 0x73, 0x65, 0x74, 0x75, 0x70, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0xbd, 0x01, 0x0a, 0x12, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x44, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x12, 0x2e, 0x0a, 0x04, 0x54, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1a, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70, 0x65, 0x12, 0x3e, 0x0a, 0x04, 0x41, 0x72, 0x67, 0x73,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x44, 0x65,
	0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e, 0x41, 0x72, 0x67, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x04, 0x41, 0x72, 0x67, 0x73, 0x1a, 0x37, 0x0a, 0x09, 0x41, 0x72, 0x67, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0x92, 0x02, 0x0a, 0x0c, 0x53, 0x68, 0x61, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x38, 0x0a, 0x0a, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44,
	0x52, 0x0a, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x12, 0x19, 0x0a, 0x05,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x48, 0x00, 0x52, 0x05, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x88, 0x01, 0x01, 0x12, 0x34, 0x0a, 0x08, 0x50, 0x72, 0x65, 0x76, 0x69,
	0x6f, 0x75, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69,
	0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x48, 0x01,
	0x52, 0x08, 0x50, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x88, 0x01, 0x01, 0x12, 0x38, 0x0a,
	0x0c, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x65, 0x46, 0x6f, 0x72, 0x18, 0x04, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x49, 0x44, 0x52, 0x0c, 0x41, 0x67, 0x67, 0x72, 0x65,
	0x67, 0x61, 0x74, 0x65, 0x46, 0x6f, 0x72, 0x12, 0x1b, 0x0a, 0x06, 0x4e, 0x6f, 0x44, 0x61, 0x74,
	0x61, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x48, 0x02, 0x52, 0x06, 0x4e, 0x6f, 0x44, 0x61, 0x74,
	0x61, 0x88, 0x01, 0x01, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x42, 0x0b,
	0x0a, 0x09, 0x5f, 0x50, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x42, 0x09, 0x0a, 0x07, 0x5f,
	0x4e, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x22, 0x7c, 0x0a, 0x05, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12,
	0x38, 0x0a, 0x0a, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x52, 0x0a, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x49, 0x44, 0x12, 0x19, 0x0a, 0x05, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x48, 0x00, 0x52, 0x05, 0x52, 0x6f, 0x75, 0x6e,
	0x64, 0x88, 0x01, 0x01, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x42, 0x08, 0x0a, 0x06, 0x5f, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x2a, 0x43, 0x0a, 0x0c, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x0f, 0x0a, 0x0b, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46,
	0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x53, 0x4b, 0x47, 0x10, 0x01, 0x12, 0x07,
	0x0a, 0x03, 0x43, 0x4b, 0x47, 0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x52, 0x4b, 0x47, 0x10, 0x03,
	0x12, 0x07, 0x0a, 0x03, 0x52, 0x54, 0x47, 0x10, 0x04, 0x32, 0x84, 0x01, 0x0a, 0x0c, 0x53, 0x65,
	0x74, 0x75, 0x70, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x3d, 0x0a, 0x08, 0x47, 0x65,
	0x74, 0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x1a, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x22, 0x00, 0x12, 0x35, 0x0a, 0x08, 0x50, 0x75, 0x74,
	0x53, 0x68, 0x61, 0x72, 0x65, 0x12, 0x13, 0x2e, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x5f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x68, 0x61, 0x72, 0x65, 0x1a, 0x12, 0x2e, 0x68, 0x65, 0x6c,
	0x69, 0x75, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x56, 0x6f, 0x69, 0x64, 0x22, 0x00,
	0x42, 0x21, 0x5a, 0x1f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6c,
	0x64, 0x73, 0x65, 0x63, 0x2f, 0x68, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6b, 0x67, 0x2f,
	0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_setup_service_proto_rawDescOnce sync.Once
	file_setup_service_proto_rawDescData = file_setup_service_proto_rawDesc
)

func file_setup_service_proto_rawDescGZIP() []byte {
	file_setup_service_proto_rawDescOnce.Do(func() {
		file_setup_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_setup_service_proto_rawDescData)
	})
	return file_setup_service_proto_rawDescData
}

var file_setup_service_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_setup_service_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_setup_service_proto_goTypes = []interface{}{
	(ProtocolType)(0),          // 0: helium_proto.ProtocolType
	(*ProtocolDescriptor)(nil), // 1: helium_proto.ProtocolDescriptor
	(*ShareRequest)(nil),       // 2: helium_proto.ShareRequest
	(*Share)(nil),              // 3: helium_proto.Share
	nil,                        // 4: helium_proto.ProtocolDescriptor.ArgsEntry
	(*ProtocolID)(nil),         // 5: helium_proto.ProtocolID
	(*NodeID)(nil),             // 6: helium_proto.NodeID
	(*Void)(nil),               // 7: helium_proto.Void
}
var file_setup_service_proto_depIdxs = []int32{
	0, // 0: helium_proto.ProtocolDescriptor.Type:type_name -> helium_proto.ProtocolType
	4, // 1: helium_proto.ProtocolDescriptor.Args:type_name -> helium_proto.ProtocolDescriptor.ArgsEntry
	5, // 2: helium_proto.ShareRequest.ProtocolID:type_name -> helium_proto.ProtocolID
	3, // 3: helium_proto.ShareRequest.Previous:type_name -> helium_proto.Share
	6, // 4: helium_proto.ShareRequest.AggregateFor:type_name -> helium_proto.NodeID
	5, // 5: helium_proto.Share.ProtocolID:type_name -> helium_proto.ProtocolID
	2, // 6: helium_proto.SetupService.GetShare:input_type -> helium_proto.ShareRequest
	3, // 7: helium_proto.SetupService.PutShare:input_type -> helium_proto.Share
	3, // 8: helium_proto.SetupService.GetShare:output_type -> helium_proto.Share
	7, // 9: helium_proto.SetupService.PutShare:output_type -> helium_proto.Void
	8, // [8:10] is the sub-list for method output_type
	6, // [6:8] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_setup_service_proto_init() }
func file_setup_service_proto_init() {
	if File_setup_service_proto != nil {
		return
	}
	file_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_setup_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProtocolDescriptor); i {
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
		file_setup_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ShareRequest); i {
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
		file_setup_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Share); i {
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
	file_setup_service_proto_msgTypes[1].OneofWrappers = []interface{}{}
	file_setup_service_proto_msgTypes[2].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_setup_service_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_setup_service_proto_goTypes,
		DependencyIndexes: file_setup_service_proto_depIdxs,
		EnumInfos:         file_setup_service_proto_enumTypes,
		MessageInfos:      file_setup_service_proto_msgTypes,
	}.Build()
	File_setup_service_proto = out.File
	file_setup_service_proto_rawDesc = nil
	file_setup_service_proto_goTypes = nil
	file_setup_service_proto_depIdxs = nil
}
