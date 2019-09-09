/*
Package pbft is a generated protocol buffer package.

It is generated from these files:
	messages.proto

It has these top-level messages:
	PbftMessage
	Request
	PrePrepare
	Prepare
	Commit
	BlockInfo
	Checkpoint
	ViewChange
	PQset
	NewView
	Metadata
	BlockMsg
	HeaderMsg
	TransactionMsg
	TxdataMsg
*/
package types

import (
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp" //=> used for common.Address define --Agzs

	google_protobuf "github.com/golang/protobuf/ptypes/timestamp"
)

const (
	// PbftMessage payload
	PrePrepareMsg     = 0x01
	PrepareMsg        = 0x02
	CommitMsg         = 0x03
	CheckpointMsg     = 0x04
	ViewChangeMsg     = 0x05
	NewViewMsg        = 0x06
	FetchBlockMsgMsg  = 0x07
	PrePrepareTestMsg = 0x08 //test hibe
	PrepareTestMsg    = 0x09 //test hibe
	CommitTestMsg     = 0x09 //test hibe
)

// This structure is used for incoming PBFT bound messages

type PbftMessage struct {
	// Types that are valid to be assigned to Payload:
	// PrePrepare *PrePrepare //=> payload = 1
	// Prepare    *Prepare    //=> payload = 2
	// Commit     *Commit     //=> payload = 3
	// Checkpoint *Checkpoint //=> payload = 4
	// ViewChange *ViewChange //=> payload = 5
	// NewView    *NewView    //=> payload = 6
	//FetchBlockMsg *FetchBlockMsg //=> payload = 7
	Sender      uint64 //=>add. --Agzs
	PayloadCode uint64
	Payload     interface{}
}

//=>func Hash(m *PbftMessage) common.Hash          { return rlpHash(m) } //=>Add for hash(pbftMessage). --Agzs
func Hash(m interface{}) common.Hash           { return rlpHash(m) } //=>Add for hash everything. --Agzs
func (m *PbftMessage) GetSender() uint64       { return m.Sender }   //=>Add --Agzs
func (m *PbftMessage) SetSender(sender uint64) { m.Sender = sender } //=>Add --Agzs

type pbftMessage struct {
	// PrePrepare *PrePrepare //=> payload = 1
	// Prepare    *Prepare    //=> payload = 2
	// Commit     *Commit     //=> payload = 3
	// Checkpoint *Checkpoint //=> payload = 4
	// ViewChange *ViewChange //=> payload = 5
	// NewView    *NewView    //=> payload = 6
	//FetchBlockMsg *FetchBlockMsg //=> payload = 7
	Sender      uint64 //=>add. --Agzs
	PayloadCode uint64
	Payload     interface{}
}

// DecodeRLP decodes the PbftMessage
func (m *PbftMessage) DecodeRLP(s *rlp.Stream) error {
	var pbftMsg pbftMessage

	if err := s.Decode(&pbftMsg); err != nil {
		return err
	}

	// m.PrePrepare = pbftMsg.PrePrepare
	// m.Prepare = pbftMsg.Prepare
	// m.Commit = pbftMsg.Commit
	// m.Checkpoint = pbftMsg.Checkpoint
	// m.ViewChange = pbftMsg.ViewChange
	// m.NewView = pbftMsg.NewView
	//m.FetchBlockMsg = pbftMsg.FetchBlockMsg
	m.Sender = pbftMsg.Sender
	m.PayloadCode = pbftMsg.PayloadCode
	m.Payload = pbftMsg.Payload

	return nil
}

// EncodeRLP serializes m into the PbftMessage RLP format.
func (m *PbftMessage) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, pbftMessage{
		// PrePrepare: m.PrePrepare,
		// Prepare:    m.Prepare,
		// Commit:     m.Commit,
		// Checkpoint: m.Checkpoint,
		// ViewChange: m.ViewChange,
		// NewView:    m.NewView,
		//FetchBlockMsg: m.FetchBlockMsg,
		Sender:      m.Sender,
		PayloadCode: m.PayloadCode,
		Payload:     m.Payload,
	})
}

func (m *PbftMessage) GetPayloadCode() uint64 {
	if m != nil {
		return m.PayloadCode
	}
	return 0
}

func (m *PbftMessage) GetPayload() interface{} {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *PbftMessage) GetPrePrepare() *PrePrepare {
	if x, ok := m.GetPayload().(*PrePrepare); ok && m.GetPayloadCode() == PrePrepareMsg {
		// if m.GetPayloadCode() == PrePrepareMsg {
		// 	preprep := m.GetPayload().(*PrePrepare)
		// 	if preprep == nil {
		// 		log.Info("preprep is nil")
		// 	}
		// 	return preprep
		return x
	}
	return nil
}

func (m *PbftMessage) GetPrepare() *Prepare {
	if x, ok := m.GetPayload().(*Prepare); ok && m.GetPayloadCode() == PrepareMsg {
		return x
	}
	return nil
}

func (m *PbftMessage) GetCommit() *Commit {
	if x, ok := m.GetPayload().(*Commit); ok && m.GetPayloadCode() == CommitMsg {
		return x
	}
	return nil
}

func (m *PbftMessage) GetCheckpoint() *Checkpoint {
	if x, ok := m.GetPayload().(*Checkpoint); ok && m.GetPayloadCode() == CheckpointMsg {
		return x
	}
	return nil
}

func (m *PbftMessage) GetViewChange() *ViewChange {
	if x, ok := m.GetPayload().(*ViewChange); ok && m.GetPayloadCode() == ViewChangeMsg {
		return x
	}
	return nil
}

func (m *PbftMessage) GetNewView() *NewView {
	if x, ok := m.GetPayload().(*NewView); ok && m.GetPayloadCode() == NewViewMsg {
		return x
	}
	return nil
}

// //=>TODO. --Agzs
// func (m *PbftMessage) GetFetchBlockMsg() *FetchBlockMsg {
// 	if m.GetPayloadCode() == FetchBlockMsgMsg {
// 		return m.FetchBlockMsg
// 	}
// 	return nil
// }

type Request struct {
	Timestamp *google_protobuf.Timestamp
	Payload   []byte
	ReplicaId uint64
	Signature []byte
}

func (m *Request) GetTimestamp() *google_protobuf.Timestamp {
	if m != nil {
		return m.Timestamp
	}
	return nil
}

func (m *Request) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *Request) GetReplicaId() uint64 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

func (m *Request) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type PrePrepare struct {
	View           uint64 `json:"view"            gencodec:"required"`
	SequenceNumber uint64 `json:"sequenceNumber"  gencodec:"required"`
	BlockHash      []byte `json:"blockHash"       gencodec:"required"`
	Block          *Block `json:"block"           gencodec:"required"`
	ReplicaId      uint64 `json:"replicaId"       gencodec:"required"`
}

func (m *PrePrepare) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

func (m *PrePrepare) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

func (m *PrePrepare) GetBlockHash() []byte {
	if m != nil {
		return m.BlockHash
	}
	return nil
}

func (m *PrePrepare) GetBlockMsg() *Block {
	if m != nil {
		return m.Block
	}
	return nil
}

func (m *PrePrepare) GetReplicaId() uint64 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

type Prepare struct {
	View           uint64 `json:"view"            gencodec:"required"`
	SequenceNumber uint64 `json:"sequenceNumber"  gencodec:"required"`
	BlockHash      []byte `json:"blockHash"       gencodec:"required"`
	ReplicaId      uint64 `json:"replicaId"       gencodec:"required"`
}

func (m *Prepare) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

func (m *Prepare) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

func (m *Prepare) GetBlockHash() []byte {
	if m != nil {
		return m.BlockHash
	}
	return nil
}

func (m *Prepare) GetReplicaId() uint64 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

type Commit struct {
	View           uint64 `json:"view"            gencodec:"required"`
	SequenceNumber uint64 `json:"sequenceNumber"  gencodec:"required"`
	BlockHash      []byte `json:"blockHash"       gencodec:"required"`
	ReplicaId      uint64 `json:"replicaId"       gencodec:"required"`
}

func (m *Commit) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

func (m *Commit) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

func (m *Commit) GetBlockHash() []byte {
	if m != nil {
		return m.BlockHash
	}
	return nil
}

func (m *Commit) GetReplicaId() uint64 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

type BlockInfo struct {
	BlockNumber uint64
	BlockHash   []byte
}

func (m *BlockInfo) GetBlockNumber() uint64 {
	if m != nil {
		return m.BlockNumber
	}
	return 0
}

func (m *BlockInfo) GetBlockHash() []byte {
	if m != nil {
		return m.BlockHash
	}
	return nil
}

type Checkpoint struct {
	SequenceNumber uint64 `json:"sequenceNumber"  gencodec:"required"`
	ReplicaId      uint64 `json:"replicaId"       gencodec:"required"`
	Id             string `json:"id"              gencodec:"required"` ////digest,can mark the state of checkpoint --xiaobei
}

func (m *Checkpoint) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

func (m *Checkpoint) GetReplicaId() uint64 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

func (m *Checkpoint) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

type ViewChange struct {
	View      uint64
	H         uint64
	Cset      []*ViewChange_C
	Pset      []*ViewChange_PQ
	Qset      []*ViewChange_PQ
	ReplicaId uint64
	Signature []byte
	Signer    common.Address //=> add Signer used for verifying signature --Agzs
}

func (m *ViewChange) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

func (m *ViewChange) GetH() uint64 {
	if m != nil {
		return m.H
	}
	return 0
}

func (m *ViewChange) GetCset() []*ViewChange_C {
	if m != nil {
		return m.Cset
	}
	return nil
}

func (m *ViewChange) GetPset() []*ViewChange_PQ {
	if m != nil {
		return m.Pset
	}
	return nil
}

func (m *ViewChange) GetQset() []*ViewChange_PQ {
	if m != nil {
		return m.Qset
	}
	return nil
}

func (m *ViewChange) GetReplicaId() uint64 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

func (m *ViewChange) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func (m *ViewChange) GetSigner() common.Address { //=> GetSigner() return signer --Agzs
	var address common.Address

	if m != nil {
		address = m.Signer
	}
	return address
}

func (m *ViewChange) SetSigner(addr common.Address) {
	if m != nil {
		m.Signer = addr
	}
}

// This message should go away and become a checkpoint once replica_id is removed
type ViewChange_C struct {
	SequenceNumber uint64 `json:"sequenceNumber"   gencodec:"required"`
	Id             string `json:"id"               gencodec:"required"`
}

func (m *ViewChange_C) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

func (m *ViewChange_C) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

type ViewChange_PQ struct {
	SequenceNumber uint64      `json:"sequenceNumber"   gencodec:"required"`
	BlockHash      common.Hash `json:"blockHash"        gencodec:"required"` ////string->common.Hash --xiaobei 11.21
	View           uint64      `json:"view"             gencodec:"required"`
}

func (m *ViewChange_PQ) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

func (m *ViewChange_PQ) GetBlockHash() common.Hash { ////string->common.Hash --xiaobei 11.21
	if m != nil {
		return m.BlockHash
	}
	return common.Hash{} ////""->common.Hash{} --xiaobei 11.21
}

func (m *ViewChange_PQ) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

type PQset struct {
	Set []*ViewChange_PQ
}

type Test struct {
	//Valuea common.Hash
	Valueb string
	Seq    uint64
}

func (m *PQset) String() { ////--xiaobei 11.21
	for _, value := range m.Set {
		fmt.Println("set.seqNo[%d]=%x", value.SequenceNumber, value.BlockHash)
	}
}

func (m *PQset) GetSet() []*ViewChange_PQ {
	if m != nil {
		return m.Set
	}
	return nil
}

type XSet struct {
	Seq  uint64 `json:"seq"      gencodec:"required"`
	Hash string `json:"hash"     gencodec:"required"`
}
type NewView struct {
	View uint64
	Vset []*ViewChange
	//Xset      map[uint64]string
	Xset      []*XSet
	ReplicaId uint64
}

func (m *NewView) GetView() uint64 {
	if m != nil {
		return m.View
	}
	return 0
}

func (m *NewView) GetVset() []*ViewChange {
	if m != nil {
		return m.Vset
	}
	return nil
}

func (m *NewView) GetXset() []*XSet {
	if m != nil {
		return m.Xset
	}
	return nil
}

func (m *NewView) GetReplicaId() uint64 {
	if m != nil {
		return m.ReplicaId
	}
	return 0
}

//=>TODO. --Agzs
type FetchBlockMsg struct {
	BlockHash string
	ReplicaId uint64
}

type Metadata struct {
	SeqNo uint64
}

func (m *Metadata) GetSeqNo() uint64 {
	if m != nil {
		return m.SeqNo
	}
	return 0
}

// Contains information about the blockchain ledger such as height, current
// block hash, and previous block hash.
////xiaobei
type BlockchainInfo struct {
	Height            uint64
	CurrentBlockHash  []byte
	PreviousBlockHash []byte
}

//=>func (*BlockchainInfo) Descriptor() ([]byte, []int) { return fileDescriptor5, []int{4} }

////
////xiaobei
type PeerID struct {
	Name string
}

//=>func (*PeerID) Descriptor() ([]byte, []int) { return fileDescriptor5, []int{7} }

////
