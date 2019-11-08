// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_convert -lff  -lsnark -lstdc++  -lgmp -lgmpxx
#include "hashcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"container/heap"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"
	"unsafe"

	"github.com/ethereum/go-ethereum/hibe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate gencodec -type txdata -field-override txdataMarshaling -out gen_tx_json.go

var (
	ErrInvalidSig = errors.New("invalid transaction v, r, s values")
	errNoSigner   = errors.New("missing signing methods")
)

var (
	TxNormal     uint32 = 0
	TxDhibe      uint32 = 1
	TxHeader     uint32 = 2
	TxCrossChain uint32 = 3
	TxZK         uint32 = 4
)

var (
	TxConvert  uint32 = 1
	TxRedeem   uint32 = 2
	TxDeposit  uint32 = 3
	TxWithdraw uint32 = 4
)

var RootAccount common.Address = common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff")

// deriveSigner makes a *best* guess about which signer to use.
func deriveSigner(V *big.Int) Signer {
	if V.Sign() != 0 && isProtectedV(V) {
		return NewEIP155Signer(deriveChainId(V))
	} else {
		return HomesteadSigner{}
	}
}

type Transaction struct {
	data txdata
	//Header *Header
	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type txdata struct {
	TxCode       uint32 //convert,redeem,deposit,withdraw
	ZKCMTbal     common.Hash
	ZKCMTfd      common.Hash
	ZKValue      uint64
	ZKSN         common.Hash
	RootHash     common.Hash
	ZKProof      []byte
	ZKEnc        []byte
	ZKIntEnc     []byte
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	TxType       uint32          //txnormal txheader txdhihe txcorsschain txzk
	Price        *big.Int        `json:"gasPrice" gencodec:"required"`
	GasLimit     *big.Int        `json:"gas"      gencodec:"required"`
	Sender       *common.Address `json:"from"     rlp:"nil"`
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`
	Level        uint32          `json:"level"    gencodec:"required"`
	Headers      []*common.Hash  `json:"headers"    gencodec:"required"`
	ZKHeader     common.Hash     `json:"zkheader"    gencodec:"required"`
	CrossTxProof [][]byte
	// Signature values
	V                   *big.Int `json:"v" gencodec:"required"`
	R                   *big.Int `json:"r" gencodec:"required"`
	S                   *big.Int `json:"s" gencodec:"required"`
	CrossChainSender    common.Address
	CrossChainRecipient common.Address
	HibeSig             *hibe.CompressedSIGBytes
	//HibeSig [hibe.HibeSigLength]byte
	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}

type HeaderTx struct {
	Index uint32
	Tx    *Transaction
}

type txdataMarshaling struct {
	AccountNonce hexutil.Uint64
	Price        *hexutil.Big
	GasLimit     *hexutil.Big
	Amount       *hexutil.Big
	Payload      hexutil.Bytes
	V            *hexutil.Big
	R            *hexutil.Big
	S            *hexutil.Big
}

func DHibeSignTx(tx *Transaction) {
	privateKey, pubKey := hibe.DHibePrivatekey(), hibe.DHibePubkey()
	if privateKey == nil || pubKey == nil || hibe.Random == nil {
		fmt.Println("private key does not exist")
		return
	}
	hash := HibeHash(tx)

	signature := hibe.Sign(privateKey, pubKey, hash.Bytes(), hibe.Random)
	WithSignature(tx, &signature)

}

func WithSignature(tx *Transaction, sig *hibe.CompressedSIGBytes) (*Transaction, error) {
	if len(sig.SIG) != hibe.HibeSigLength {
		panic(fmt.Sprintf("wrong size for signature: got %d, want %d", len(sig.SIG), hibe.HibeSigLength))
	}

	tx.WithHibeSig(sig.SIG)

	return tx, nil
}

func CopyTransaction(tx *Transaction) *Transaction {
	return &Transaction{data: tx.data}
}

func (tx *Transaction) SetCrossAddress() {
	crossAddress := tx.data.Recipient
	tx.data.CrossChainRecipient = *crossAddress
	tx.data.Recipient = &RootAccount
	tx.data.CrossChainSender = tx.Sender()
}

func (tx *Transaction) SetRequestCrossAddress() {
	tx.data.CrossChainSender = tx.Sender()
	tx.data.Sender = &RootAccount
	recipient := tx.Recipient()
	tx.data.CrossChainRecipient = recipient
}

func (tx *Transaction) SetDhibeSig(sig *hibe.CompressedSIGBytes) {
	tx.data.HibeSig = sig
}

func (tx *Transaction) GetDhibeSig() *hibe.CompressedSIGBytes {
	return tx.data.HibeSig
}

func (tx *Transaction) SetFromAddress(address common.Address) {
	tx.data.Sender = &address
}

func (tx *Transaction) Sender() common.Address {
	return *tx.data.Sender
}

func (tx *Transaction) Recipient() common.Address {
	return *tx.data.Recipient
}

func (tx *Transaction) SetRecipient(add common.Address) {
	*tx.data.Recipient = add
}

func (tx *Transaction) CrossChainSender() common.Address {
	return tx.data.CrossChainSender
}
func (tx *Transaction) CrossChainRecipient() common.Address {
	return tx.data.CrossChainRecipient
}

func (tx *Transaction) SetPrice(price *big.Int) {
	tx.data.Price = price
}

func (tx *Transaction) SetTxType(txType uint32) {
	tx.data.TxType = txType
}

func (tx *Transaction) SetTxCode(code uint32) {
	tx.data.TxCode = code
}

func (tx *Transaction) TxCode() uint32 {
	return tx.data.TxCode
}
func (tx *Transaction) SetValue(value *big.Int) {
	tx.data.Amount = value
}
func (tx *Transaction) SetZKValue(Value uint64) {
	tx.data.ZKValue = Value
}
func (tx *Transaction) ZKValue() uint64 {
	return tx.data.ZKValue
}

//
func (tx *Transaction) ZKProof() []byte {
	return tx.data.ZKProof
}

//
func (tx *Transaction) SetZKProof(proof []byte) {
	tx.data.ZKProof = make([]byte, len(proof))
	copy(tx.data.ZKProof[:], proof[:])
}
func (tx *Transaction) TxType() uint32 {
	return tx.data.TxType
}

func (tx *Transaction) SetProof(proof []hexutil.Bytes) {
	tx.data.CrossTxProof = make([][]byte, len(proof))
	for i, bytes := range proof {
		tx.data.CrossTxProof[i] = bytes
	}
}

func (tx *Transaction) Proof() [][]byte {
	return tx.data.CrossTxProof
}

func (tx *Transaction) ID() string {
	//	var ID string
	var IDBytes []byte
	resultBytes := make([]byte, 0)
	if tx.TxType() == TxCrossChain && tx.Recipient() != RootAccount {
		IDBytes = tx.data.Recipient.Bytes()
	} else {
		IDBytes = tx.data.Sender.Bytes()
	}
	for i := 0; i < 18; i++ {
		if IDBytes[i] == 0 {
			break
		}
		resultBytes = append(resultBytes, IDBytes[i])
		//fmt.Println("byte", i, IDBytes[i], ID)
		//ID += string(IDBytes[i])
	}
	//fmt.Println(string(resultBytes[:]))
	return string(resultBytes[:])
}
func NewTransaction(nonce uint64, to common.Address, amount, gasLimit, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, &to, amount, gasLimit, gasPrice, data)
}

func NewRandomAddress() *common.Address {
	uuid := make([]byte, 20)
	io.ReadFull(rand.Reader, uuid)
	addr := common.BytesToAddress(uuid)
	return &addr
}

func NewHeaderTransaction(nonce uint64, headers []*common.Hash, addr *common.Address, level uint32) *Transaction {

	tx := newTransaction(nonce, addr, big.NewInt(0), big.NewInt(0), big.NewInt(0), []byte{})
	for _, header := range headers {
		if header != nil {
			tx.data.Headers = append(tx.data.Headers, header)
		}
	}
	tx.SetTxType(TxHeader)
	tx.data.Sender = addr
	tx.data.Recipient = NewRandomAddress()
	tx.data.Level = level
	tx.data.GasLimit = big.NewInt(90000)
	return tx
}

func NewContractCreation(nonce uint64, amount, gasLimit, gasPrice *big.Int, data []byte) *Transaction {
	return newTransaction(nonce, nil, amount, gasLimit, gasPrice, data)
}

func newZKTransaction(nonce uint64, to *common.Address, amount, gasLimit, gasPrice *big.Int, data []byte) *Transaction {
	//newTransaction(nonce, to, amount, gasLimit, gasPrice, data)

	return newTransaction(nonce, to, amount, gasLimit, gasPrice, data)
}

func newTransaction(nonce uint64, to *common.Address, amount, gasLimit, gasPrice *big.Int, data []byte) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := txdata{
		AccountNonce: nonce,
		Recipient:    to,
		Payload:      data,
		Amount:       new(big.Int),
		GasLimit:     new(big.Int),
		Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
		Headers:      make([]*common.Hash, 0),
		//	CrossTxProof: make([][]byte, 2),
	}
	//d.CrossTxProof[0] = make([]byte, 0)
	//d.CrossTxProof[1] = make([]byte, 0)

	if amount != nil {
		d.Amount.Set(amount)
	}
	if gasLimit != nil {
		d.GasLimit.Set(gasLimit)
	}
	if gasPrice != nil {
		d.Price.Set(gasPrice)
	}

	return &Transaction{data: d}
}

func (tx *Transaction) SetZKSN(sn common.Hash) {
	tx.data.ZKSN = sn
}

//
func (tx *Transaction) ZKSN() common.Hash {
	return tx.data.ZKSN
}

func (tx *Transaction) ZKCMTbal() common.Hash {
	return tx.data.ZKCMTbal
}

//
func (tx *Transaction) ZKCMTfd() common.Hash {
	return tx.data.ZKCMTfd
}

//
func (tx *Transaction) SetZKCMTbal(hash common.Hash) {
	tx.data.ZKCMTbal = hash
}

//
func (tx *Transaction) SetZKCMTfd(hash common.Hash) {
	tx.data.ZKCMTfd = hash
}

func (tx *Transaction) SetLevel(level uint32) {
	tx.data.Level = level
}

func (tx *Transaction) SetNounce(nounce uint64) {
	tx.data.AccountNonce = nounce
}

func (tx *Transaction) Headers() []*common.Hash {
	return tx.data.Headers
}

func (tx *Transaction) SetZKHeader(header common.Hash) {
	tx.data.ZKHeader = header
}

func (tx *Transaction) ZKHeader() common.Hash {
	return tx.data.ZKHeader
}

func (tx *Transaction) WithHibeSig(sig []byte) {
	if len(sig) != hibe.HibeSigLength {
		return
	}
	tx.data.HibeSig = &hibe.CompressedSIGBytes{}
	tx.data.HibeSig.SIG = make([]byte, hibe.HibeSigLength)
	copy(tx.data.HibeSig.SIG[:], sig[:])
	//fmt.Println("sig", tx.data.HibeSig.SIG)
}

// ChainId returns which chain id this transaction was signed for (if at all)
func (tx *Transaction) ChainId() *big.Int {
	return deriveChainId(tx.data.V)
}

// Protected returns whether the transaction is protected from replay protection.
func (tx *Transaction) Protected() bool {
	return isProtectedV(tx.data.V)
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 are considered unprotected
	return true
}

// DecodeRLP implements rlp.Encoder
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &tx.data)
}

// DecodeRLP implements rlp.Decoder
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	err := s.Decode(&tx.data)
	if err == nil {
		tx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}

	return err
}

func (tx *Transaction) MarshalJSON() ([]byte, error) {
	hash := tx.Hash()
	data := tx.data
	data.Hash = &hash
	return data.MarshalJSON()
}

// UnmarshalJSON decodes the web3 RPC transaction format.
func (tx *Transaction) UnmarshalJSON(input []byte) error {
	var dec txdata
	if err := dec.UnmarshalJSON(input); err != nil {
		return err
	}
	var V byte
	if isProtectedV(dec.V) {
		chainId := deriveChainId(dec.V).Uint64()
		V = byte(dec.V.Uint64() - 35 - 2*chainId)
	} else {
		V = byte(dec.V.Uint64() - 27)
	}
	if !crypto.ValidateSignatureValues(V, dec.R, dec.S, false) {
		return ErrInvalidSig
	}
	*tx = Transaction{data: dec}
	return nil
}

func (tx *Transaction) Data() []byte       { return common.CopyBytes(tx.data.Payload) }
func (tx *Transaction) Gas() *big.Int      { return new(big.Int).Set(tx.data.GasLimit) }
func (tx *Transaction) GasPrice() *big.Int { return new(big.Int).Set(tx.data.Price) }
func (tx *Transaction) Value() *big.Int    { return new(big.Int).Set(tx.data.Amount) }
func (tx *Transaction) Nonce() uint64      { return tx.data.AccountNonce }
func (tx *Transaction) CheckNonce() bool   { return true }

// To returns the recipient address of the transaction.
// It returns nil if the transaction is a contract creation.
func (tx *Transaction) To() *common.Address {
	if tx.data.Recipient == nil {
		return nil
	} else {
		to := *tx.data.Recipient
		return &to
	}
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) Hash() common.Hash {
	// if hash := tx.hash.Load(); hash != nil {
	// 	return hash.(common.Hash)
	// }
	// v := rlpHash(tx)
	// tx.hash.Store(v)
	// return v
	return ZKHashTx(tx)

}

func (tx *Transaction) RLPHash() common.Hash {

	v := rlpHash(tx)

	return v
}
func TestHash(str string) common.Hash {

	//fmt.Println(tx.data.ZKSN.Bytes())
	TargetString := C.CString(str)
	//SNString2 := C.CString(common.ToHex(tx.data.ZKSN.Bytes()))
	defer C.free(unsafe.Pointer(TargetString))
	//defer C.free(unsafe.Pointer(SNString2))
	size := C.ulong(len(str))
	hashString := C.hash(TargetString, size)
	hashGo := C.GoString(hashString)
	hashbytes, _ := hex.DecodeString(hashGo)
	hash := common.BytesToHash(hashbytes)
	return hash
}

func ZKHashTx(tx *Transaction) common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	//fmt.Println(tx.data.ZKSN.Bytes())
	targetbytes := append(tx.data.ZKSN.Bytes(), tx.data.ZKCMTbal.Bytes()...)
	header := common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if len(tx.data.Headers) > 0 {
		header = *(tx.data.Headers[0])
	}
	targetbytes = append(targetbytes, header.Bytes()...)
	targetbytes = append(targetbytes, tx.Sender().Bytes()...)

	TargetStringgo := common.ToHex(targetbytes)[2:] //
	TargetString := C.CString(TargetStringgo)

	defer C.free(unsafe.Pointer(TargetString))
	//defer C.free(unsafe.Pointer(SNString2))
	size := C.ulong(len(tx.data.ZKSN.Bytes()) + len(tx.data.ZKCMTbal.Bytes()) + len(header.Bytes()) + len(tx.Sender().Bytes()))
	hashString := C.hash(TargetString, 2*size)
	hashGo := C.GoString(hashString)
	hashbytes, _ := hex.DecodeString(hashGo)
	hash := common.BytesToHash(hashbytes)
	tx.hash.Store(hash)
	return hash
}

func ZKHashBlock(header *Header) common.Hash {
	// if hash := tx.hash.Load(); hash != nil {
	// 	return hash.(common.Hash)
	// }
	//fmt.Println(tx.data.ZKSN.Bytes())
	targetbytes := append(header.TxHash.Bytes(), header.Root.Bytes()...)
	targetbytes = append(targetbytes, header.RootCMTfd.Bytes()...)

	// var buf = make([]byte, 8)
	// binary.LittleEndian.PutUint64(buf, header.Number.Uint64())
	// targetbytes = append(targetbytes, buf...)

	TargetStringgo := common.ToHex(targetbytes)[2:]
	TargetString := C.CString(TargetStringgo)

	//fmt.Println("******************************", common.ToHex(header.TxHash.Bytes())+common.ToHex(header.Root.Bytes())+common.ToHex(header.RootCMTfd.Bytes()))
	defer C.free(unsafe.Pointer(TargetString))
	//size := C.ulong(len(header.TxHash.Bytes()) + len(header.Root.Bytes()) + len(header.RootCMTfd.Bytes()) + len(buf))
	size := C.ulong(len(header.TxHash.Bytes()) + len(header.Root.Bytes()) + len(header.RootCMTfd.Bytes()))
	hashString := C.hash(TargetString, 2*size) //the length of string is twice of bytes
	hashGo := C.GoString(hashString)
	hashbytes, _ := hex.DecodeString(hashGo)
	hash := common.BytesToHash(hashbytes)
	//header.hash.Store(hash)
	// fmt.Println()
	// fmt.Println("header number", header.Number.Uint64())
	// fmt.Println("header number little endian", common.Bytes2Hex(buf))
	// fmt.Println("TargetString", common.ToHex(targetbytes)[2:])
	// fmt.Println("TargetString length", size)
	// fmt.Println("header hash", hash.Hex())
	// fmt.Println()
	return hash
}

// SigHash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (tx *Transaction) SigHash(signer Signer) common.Hash {
	return signer.Hash(tx)
}

func (tx *Transaction) Size() common.StorageSize {
	if size := tx.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, &tx.data)
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

// AsMessage returns the transaction as a core.Message.
//
// AsMessage requires a signer to derive the sender.
//
// XXX Rename message to something less arbitrary?
func (tx *Transaction) AsMessage(s Signer) (Message, error) {
	msg := Message{
		nonce:      tx.data.AccountNonce,
		price:      new(big.Int).Set(tx.data.Price),
		gasLimit:   new(big.Int).Set(tx.data.GasLimit),
		to:         tx.data.Recipient,
		amount:     tx.data.Amount,
		data:       tx.data.Payload,
		checkNonce: true,
		zkValue:    tx.ZKValue(),
		cmt:        &tx.data.ZKCMTbal,
		txCode:     tx.data.TxCode,
	}

	msg.from = *(tx.data.Sender)
	return msg, nil
	//var err error
	//	msg.from, err = Sender(s, tx)
	//return msg, err
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be formatted as described in the yellow paper (v+27).
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	return signer.WithSignature(tx, sig)
}

// Cost returns amount + gasprice * gaslimit.
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.data.Price, tx.data.GasLimit)
	total.Add(total, tx.data.Amount)
	return total
}

func (tx *Transaction) RawSignatureValues() (*big.Int, *big.Int, *big.Int) {
	return tx.data.V, tx.data.R, tx.data.S
}

func (tx *Transaction) String() string {
	var from, to string
	if tx.data.V != nil && tx.data.TxType == TxNormal {
		// make a best guess about the signer and use that to derive
		// the sender.
		signer := deriveSigner(tx.data.V)
		if f, err := Sender(signer, tx); err != nil { // derive but don't cache
			from = "[invalid sender: invalid sig]"
		} else {
			from = fmt.Sprintf("%x", f[:])
		}
	} else if tx.TxType() == TxDhibe || tx.TxType() == TxHeader || tx.TxType() == TxCrossChain {
		signer := NewDHibeSigner()
		//signer := deriveSigner(tx.data.V)             //TBD
		if f, err := Sender(signer, tx); err != nil { // derive but don't cache
			from = "[invalid sender: invalid sig]"
		} else {
			from = fmt.Sprintf("%x", f[:])
		}
	} else if tx.TxType() == TxZK {
		signer := NewZKSigner()
		if f, err := Sender(signer, tx); err != nil { // derive but don't cache
			from = "[invalid sender: invalid sig]"
		} else {
			from = fmt.Sprintf("%x", f[:])
		}
	} else {
		from = "[invalid sender: nil V field]"
	}

	if tx.data.Recipient == nil {
		to = "[contract creation]"
	} else {
		if tx.TxType() == TxNormal {
			to = fmt.Sprintf("%x", tx.data.Recipient[:])
		} else {
			to = fmt.Sprintf("%x", tx.data.Recipient[:])
		}
	}
	enc, _ := rlp.EncodeToBytes(&tx.data)

	return fmt.Sprintf(`
	TX(%x)
	Contract:   %v
	CrossChain  %v
	From:       %s
	To:         %s
	Nonce:      %v
	GasPrice:   %#x
	GasLimit    %#x
	Value:      %#x
	Data:       0x%x
	V:          %#x
	R:          %#x
	S:          %#x
	Hex:        %x
	Level:      %v
	HibeSig     %v
	Type:       %v
	Headers:    %v
	CrossTxProof: %v
`,
		tx.Hash(),
		len(tx.data.Recipient) == 0,
		tx.TxType() == TxCrossChain,
		from,
		to,
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Amount,
		tx.data.Payload,
		tx.data.V,
		tx.data.R,
		tx.data.S,
		enc,
		tx.data.Level,
		tx.data.HibeSig.SIG,
		tx.data.TxType,
		tx.data.Headers,
		tx.data.CrossTxProof,
	)
}

//
func PID(id string) string {
	var pid string
	if len(id) > 0 {
		pid = id[:len(id)-2]
	}
	return pid
}

// Transaction slice type for basic sorting.
type Transactions []*Transaction

// Len returns the length of s
func (s Transactions) Len() int { return len(s) }

// Swap swaps the i'th and the j'th element in s
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// GetRlp implements Rlpable and returns the i'th element of s in rlp
func (s Transactions) GetRlp(i int) []byte {
	enc, _ := rlp.EncodeToBytes(s[i])
	return enc
}

// Returns a new set t which is the difference between a to b
func TxDifference(a, b Transactions) (keep Transactions) {
	keep = make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}

// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].data.AccountNonce < s[j].data.AccountNonce }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// TxByPrice implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type TxByPrice Transactions

func (s TxByPrice) Len() int           { return len(s) }
func (s TxByPrice) Less(i, j int) bool { return s[i].data.Price.Cmp(s[j].data.Price) > 0 }
func (s TxByPrice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func (s *TxByPrice) Push(x interface{}) {
	*s = append(*s, x.(*Transaction))
}

func (s *TxByPrice) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

// TransactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximising sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type TransactionsByPriceAndNonce struct {
	txs   map[common.Address]Transactions // Per account nonce-sorted list of transactions
	heads TxByPrice                       // Next transaction for each unique account (price heap)
}

// NewTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providng it to the constructor.
func NewTransactionsByPriceAndNonce(txs map[common.Address]Transactions) *TransactionsByPriceAndNonce {
	// Initialize a price based heap with the head transactions
	heads := make(TxByPrice, 0, len(txs))
	for acc, accTxs := range txs {
		heads = append(heads, accTxs[0])
		txs[acc] = accTxs[1:]
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	return &TransactionsByPriceAndNonce{
		txs:   txs,
		heads: heads,
	}
}

// Peek returns the next transaction by price.
func (t *TransactionsByPriceAndNonce) Peek() *Transaction {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Shift replaces the current best head with the next one from the same account.
func (t *TransactionsByPriceAndNonce) Shift() {
	signer := deriveSigner(t.heads[0].data.V)
	// derive signer but don't cache.
	acc, _ := Sender(signer, t.heads[0]) // we only sort valid txs so this cannot fail
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		t.heads[0], t.txs[acc] = txs[0], txs[1:]
		heap.Fix(&t.heads, 0)
	} else {
		heap.Pop(&t.heads)
	}
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *TransactionsByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// Message is a fully derived transaction and implements core.Message
//
// NOTE: In a future PR this will be removed.
type Message struct {
	to                      *common.Address
	from                    common.Address
	nonce                   uint64
	amount, price, gasLimit *big.Int
	data                    []byte
	checkNonce              bool
	txCode                  uint32
	cmt                     *common.Hash
	zkValue                 uint64
}

func NewMessage(from common.Address, to *common.Address, nonce uint64, amount, gasLimit, price *big.Int, data []byte, checkNonce bool) Message {
	return Message{
		from:       from,
		to:         to,
		nonce:      nonce,
		amount:     amount,
		price:      price,
		gasLimit:   gasLimit,
		data:       data,
		checkNonce: checkNonce,
	}
}

func (m Message) From() common.Address { return m.from }
func (m Message) To() *common.Address  { return m.to }
func (m Message) GasPrice() *big.Int   { return m.price }
func (m Message) Value() *big.Int      { return m.amount }
func (m Message) Gas() *big.Int        { return m.gasLimit }
func (m Message) Nonce() uint64        { return m.nonce }
func (m Message) Data() []byte         { return m.data }
func (m Message) CheckNonce() bool     { return m.checkNonce }
func (m Message) CMT() *common.Hash    { return m.cmt }
func (m Message) ZKValue() uint64      { return m.zkValue }
func (m Message) TxCode() uint32       { return m.txCode }
