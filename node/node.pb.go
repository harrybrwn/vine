// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        (unknown)
// source: node.proto

package node

import (
	proto "github.com/golang/protobuf/proto"
	block "github.com/harrybrwn/go-ledger/block"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Status_StatusCode int32

const (
	Status_Ok  Status_StatusCode = 0
	Status_Err Status_StatusCode = 1
)

// Enum value maps for Status_StatusCode.
var (
	Status_StatusCode_name = map[int32]string{
		0: "Ok",
		1: "Err",
	}
	Status_StatusCode_value = map[string]int32{
		"Ok":  0,
		"Err": 1,
	}
)

func (x Status_StatusCode) Enum() *Status_StatusCode {
	p := new(Status_StatusCode)
	*p = x
	return p
}

func (x Status_StatusCode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Status_StatusCode) Descriptor() protoreflect.EnumDescriptor {
	return file_node_proto_enumTypes[0].Descriptor()
}

func (Status_StatusCode) Type() protoreflect.EnumType {
	return &file_node_proto_enumTypes[0]
}

func (x Status_StatusCode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Status_StatusCode.Descriptor instead.
func (Status_StatusCode) EnumDescriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{0, 0}
}

type Status struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code   Status_StatusCode `protobuf:"varint,1,opt,name=code,proto3,enum=node.Status_StatusCode" json:"code,omitempty"`
	Status string            `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *Status) Reset() {
	*x = Status{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Status) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Status) ProtoMessage() {}

func (x *Status) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Status.ProtoReflect.Descriptor instead.
func (*Status) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{0}
}

func (x *Status) GetCode() Status_StatusCode {
	if x != nil {
		return x.Code
	}
	return Status_Ok
}

func (x *Status) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

type BlockMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sender string       `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	Block  *block.Block `protobuf:"bytes,2,opt,name=block,proto3" json:"block,omitempty"`
	Error  string       `protobuf:"bytes,3,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *BlockMsg) Reset() {
	*x = BlockMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BlockMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlockMsg) ProtoMessage() {}

func (x *BlockMsg) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlockMsg.ProtoReflect.Descriptor instead.
func (*BlockMsg) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{1}
}

func (x *BlockMsg) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

func (x *BlockMsg) GetBlock() *block.Block {
	if x != nil {
		return x.Block
	}
	return nil
}

func (x *BlockMsg) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type TxMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sender string             `protobuf:"bytes,1,opt,name=sender,proto3" json:"sender,omitempty"`
	Tx     *block.Transaction `protobuf:"bytes,2,opt,name=tx,proto3" json:"tx,omitempty"`
	Error  string             `protobuf:"bytes,3,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *TxMsg) Reset() {
	*x = TxMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TxMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TxMsg) ProtoMessage() {}

func (x *TxMsg) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TxMsg.ProtoReflect.Descriptor instead.
func (*TxMsg) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{2}
}

func (x *TxMsg) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

func (x *TxMsg) GetTx() *block.Transaction {
	if x != nil {
		return x.Tx
	}
	return nil
}

func (x *TxMsg) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

type BlockReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *BlockReq) Reset() {
	*x = BlockReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BlockReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlockReq) ProtoMessage() {}

func (x *BlockReq) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlockReq.ProtoReflect.Descriptor instead.
func (*BlockReq) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{3}
}

func (x *BlockReq) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

type TxReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash []byte `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *TxReq) Reset() {
	*x = TxReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TxReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TxReq) ProtoMessage() {}

func (x *TxReq) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TxReq.ProtoReflect.Descriptor instead.
func (*TxReq) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{4}
}

func (x *TxReq) GetHash() []byte {
	if x != nil {
		return x.Hash
	}
	return nil
}

type Empty struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Empty) Reset() {
	*x = Empty{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Empty) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Empty) ProtoMessage() {}

func (x *Empty) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Empty.ProtoReflect.Descriptor instead.
func (*Empty) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{5}
}

var File_node_proto protoreflect.FileDescriptor

var file_node_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x6e, 0x6f,
	0x64, 0x65, 0x1a, 0x14, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x6c, 0x0a, 0x06, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x12, 0x2b, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x17, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x43, 0x6f, 0x64, 0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12,
	0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x1d, 0x0a, 0x0a, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x06, 0x0a, 0x02, 0x4f, 0x6b, 0x10, 0x00, 0x12, 0x07, 0x0a,
	0x03, 0x45, 0x72, 0x72, 0x10, 0x01, 0x22, 0x5c, 0x0a, 0x08, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4d,
	0x73, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x12, 0x22, 0x0a, 0x05, 0x62, 0x6c,
	0x6f, 0x63, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x62, 0x6c, 0x6f, 0x63,
	0x6b, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52, 0x05, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x12, 0x14,
	0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x22, 0x59, 0x0a, 0x05, 0x54, 0x78, 0x4d, 0x73, 0x67, 0x12, 0x16, 0x0a,
	0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73,
	0x65, 0x6e, 0x64, 0x65, 0x72, 0x12, 0x22, 0x0a, 0x02, 0x74, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x12, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x02, 0x74, 0x78, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22,
	0x1e, 0x0a, 0x08, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52, 0x65, 0x71, 0x12, 0x12, 0x0a, 0x04, 0x68,
	0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x22,
	0x1b, 0x0a, 0x05, 0x54, 0x78, 0x52, 0x65, 0x71, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x22, 0x07, 0x0a, 0x05,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x32, 0xf9, 0x01, 0x0a, 0x0a, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x53,
	0x74, 0x6f, 0x72, 0x65, 0x12, 0x2c, 0x0a, 0x08, 0x67, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x12, 0x0e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52, 0x65, 0x71,
	0x1a, 0x0e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4d, 0x73, 0x67,
	0x22, 0x00, 0x12, 0x23, 0x0a, 0x05, 0x67, 0x65, 0x74, 0x54, 0x78, 0x12, 0x0b, 0x2e, 0x6e, 0x6f,
	0x64, 0x65, 0x2e, 0x54, 0x78, 0x52, 0x65, 0x71, 0x1a, 0x0b, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e,
	0x54, 0x78, 0x4d, 0x73, 0x67, 0x22, 0x00, 0x12, 0x25, 0x0a, 0x04, 0x68, 0x65, 0x61, 0x64, 0x12,
	0x0b, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x0e, 0x2e, 0x6e,
	0x6f, 0x64, 0x65, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4d, 0x73, 0x67, 0x22, 0x00, 0x12, 0x25,
	0x0a, 0x04, 0x62, 0x61, 0x73, 0x65, 0x12, 0x0b, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x1a, 0x0e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x4d, 0x73, 0x67, 0x22, 0x00, 0x12, 0x21, 0x0a, 0x02, 0x74, 0x78, 0x12, 0x0b, 0x2e, 0x6e, 0x6f,
	0x64, 0x65, 0x2e, 0x54, 0x78, 0x4d, 0x73, 0x67, 0x1a, 0x0c, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x00, 0x12, 0x27, 0x0a, 0x05, 0x6d, 0x69, 0x6e, 0x65,
	0x64, 0x12, 0x0e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4d, 0x73,
	0x67, 0x1a, 0x0c, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22,
	0x00, 0x42, 0x2a, 0x5a, 0x28, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x68, 0x61, 0x72, 0x72, 0x79, 0x62, 0x72, 0x77, 0x6e, 0x2f, 0x67, 0x6f, 0x2d, 0x6c, 0x65, 0x64,
	0x67, 0x65, 0x72, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x3b, 0x6e, 0x6f, 0x64, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_node_proto_rawDescOnce sync.Once
	file_node_proto_rawDescData = file_node_proto_rawDesc
)

func file_node_proto_rawDescGZIP() []byte {
	file_node_proto_rawDescOnce.Do(func() {
		file_node_proto_rawDescData = protoimpl.X.CompressGZIP(file_node_proto_rawDescData)
	})
	return file_node_proto_rawDescData
}

var file_node_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_node_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_node_proto_goTypes = []interface{}{
	(Status_StatusCode)(0),    // 0: node.Status.StatusCode
	(*Status)(nil),            // 1: node.Status
	(*BlockMsg)(nil),          // 2: node.BlockMsg
	(*TxMsg)(nil),             // 3: node.TxMsg
	(*BlockReq)(nil),          // 4: node.BlockReq
	(*TxReq)(nil),             // 5: node.TxReq
	(*Empty)(nil),             // 6: node.Empty
	(*block.Block)(nil),       // 7: block.Block
	(*block.Transaction)(nil), // 8: block.Transaction
}
var file_node_proto_depIdxs = []int32{
	0, // 0: node.Status.code:type_name -> node.Status.StatusCode
	7, // 1: node.BlockMsg.block:type_name -> block.Block
	8, // 2: node.TxMsg.tx:type_name -> block.Transaction
	4, // 3: node.BlockStore.getBlock:input_type -> node.BlockReq
	5, // 4: node.BlockStore.getTx:input_type -> node.TxReq
	6, // 5: node.BlockStore.head:input_type -> node.Empty
	6, // 6: node.BlockStore.base:input_type -> node.Empty
	3, // 7: node.BlockStore.tx:input_type -> node.TxMsg
	2, // 8: node.BlockStore.mined:input_type -> node.BlockMsg
	2, // 9: node.BlockStore.getBlock:output_type -> node.BlockMsg
	3, // 10: node.BlockStore.getTx:output_type -> node.TxMsg
	2, // 11: node.BlockStore.head:output_type -> node.BlockMsg
	2, // 12: node.BlockStore.base:output_type -> node.BlockMsg
	1, // 13: node.BlockStore.tx:output_type -> node.Status
	1, // 14: node.BlockStore.mined:output_type -> node.Status
	9, // [9:15] is the sub-list for method output_type
	3, // [3:9] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_node_proto_init() }
func file_node_proto_init() {
	if File_node_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_node_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Status); i {
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
		file_node_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BlockMsg); i {
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
		file_node_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TxMsg); i {
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
		file_node_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BlockReq); i {
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
		file_node_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TxReq); i {
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
		file_node_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Empty); i {
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
			RawDescriptor: file_node_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_node_proto_goTypes,
		DependencyIndexes: file_node_proto_depIdxs,
		EnumInfos:         file_node_proto_enumTypes,
		MessageInfos:      file_node_proto_msgTypes,
	}.Build()
	File_node_proto = out.File
	file_node_proto_rawDesc = nil
	file_node_proto_goTypes = nil
	file_node_proto_depIdxs = nil
}
