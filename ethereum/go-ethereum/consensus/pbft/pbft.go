/*
Copyright IBM Corp. 2016 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
		 http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
//////////////////////////////////////////////////////
///  1. this file merges pbft.go of fabric and clique.go of ethereum
///  2. clique.go provide a method to sign a block
///  3. pbft.go provides a method for pbft consensus
///  Main modifications;
///  1) add a protocolManager to the consensus engine.
///  2) remove all execution-related parts from pbft.go. because our design
///     does not require any execution of transactions. Executions are already done
///     before consensus with engine.Finalize()
//////////////////////////////////////////////////////

package pbft

import (

	///	"github.com/ethereum/go-ethereum/event"

	"fmt"
	"os"
	"path/filepath"

	///	"strconv"
	"strings"
	/////////////////////////////////////////////////
	// Copy from clique.go    Zhiguo Wan
	"bytes"
	"errors"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/hibe"
	"github.com/ethereum/go-ethereum/node"

	///"github.com/ethereum/go-ethereum/eth" // for ProtocolManager. ---Zhiguo Wan
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/util/events"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	lru "github.com/hashicorp/golang-lru"

	//"github.com/ethereum/go-ethereum/eth" //=> for Ethereum. need to solve import cycle not allowed --Agzs
	"github.com/ethereum/go-ethereum/params"
	///        "gopkg.in/urfave/cli.v1"
	///        "github.com/ethereum/go-ethereum/cmd/utils"

	/////////////////////////////////////////////////

	//////////////////////////////////////////////////
	// commented by Zhiguo Wan 20/09/2017
	//	"github.com/ethereum/go-ethereum/consensus/ethash/fabric/consensus"
	//	pb "github.com/ethereum/go-ethereum/consensus/ethash/fabric/protos"

	///	"github.com/golang/protobuf/proto"
	"github.com/spf13/viper"
)

const configPrefix = "CORE_PBFT"

const DefaultPbftID = 1000 //=> set DefaultPbftID to 1000 --Agzs 12.13

var configV *viper.Viper //=>config->configV. delete configV in New() --Agzs

/////////////////////////////////////////////
// from clique.go
const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	//=> certStorePeriod = 100 //=> Number of blocks after clean up certStore and blockStore --Agzs

	wiggleTime = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
)

// PBFT protocol constants.
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes
	blockPeriod = uint64(15)    // Default minimum difference between two consecutive block's timestamps

	extraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signer seal

	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signer
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signer.

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes, or not the correct
	// ones).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is not either
	// of 1 or 2, or if the value does not match the turn of the signer.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorized is returned if a header is signed by a non-authorized entity.
	errUnauthorized = errors.New("unauthorized")

	///  errNotPrimay is returned if the node is not primary.
	ErrNotPrimary = errors.New("not primary node, cannot issue Seal") /// New error type. --Zhiguo

	//=> errNotPrimay is returned if the node is not primary.
	errNotVP = errors.New("not signer(primary and backup), cannot issue Seal") /// New error type. --Zhiguo
)

// SignerFn is a signer callback function to request a hash to be signed by a
// backing account.
type SignerFn func(accounts.Account, []byte) ([]byte, error)

// sigHash returns the hash which is used as input for the proof-of-authority
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
//
//=> overwrite sigHash used for both types.Header and types.ViewChange --Agzs
func sigHash(header *types.Header, viewChange *types.ViewChange) (hash common.Hash) {
	hasher := sha3.NewKeccak256()
	if header != nil {
		rlp.Encode(hasher, []interface{}{
			header.ParentHash,
			header.UncleHash,
			header.Coinbase,
			header.Root,
			header.TxHash,
			header.ReceiptHash,
			header.Bloom,
			header.Difficulty,
			header.Number,
			header.GasLimit,
			header.GasUsed,
			header.Time,
			header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
			header.MixDigest,
			header.Nonce,
		})
		hasher.Sum(hash[:0])
	} else {
		rlp.Encode(hasher, []interface{}{
			viewChange.View,
			viewChange.H,
			viewChange.Cset,
			viewChange.Pset,
			viewChange.Qset,
			viewChange.ReplicaId,
			//viewChange.Signature,
			//=>delete signature, because sign() doesn't have contain this, verify() contains this may be wrong. --Agzs
		})
		hasher.Sum(hash[:0])
	}

	return hash
}

//=> overwrite sigHash() --Agzs
// func sigHash(header *types.Header) (hash common.Hash) {
// 	hasher := sha3.NewKeccak256()

// 	rlp.Encode(hasher, []interface{}{
// 		header.ParentHash,
// 		header.UncleHash,
// 		header.Coinbase,
// 		header.Root,
// 		header.TxHash,
// 		header.ReceiptHash,
// 		header.Bloom,
// 		header.Difficulty,
// 		header.Number,
// 		header.GasLimit,
// 		header.GasUsed,
// 		header.Time,
// 		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
// 		header.MixDigest,
// 		header.Nonce,
// 	})
// 	hasher.Sum(hash[:0])
// 	return hash
// }

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sigHash(header, nil).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

//=> ecrecoverFromSignature extracts the Ethereum account address from a signed header. --Agzs
func ecrecoverFromSignature(viewchange *types.ViewChange) (common.Address, error) {

	signature := viewchange.Signature

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(sigHash(nil, viewchange).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	return signer, nil
}

// PBFT is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type PBFT struct {
	///  Still inherit Fabric's config solution: Viper. Also use PBFTConfig  --Zhiguo
	configV *viper.Viper // Consensus engine configuration parameters
	config  *params.PBFTConfig
	db      ethdb.Database // Database to store and retrieve snapshot checkpoints
	// db may not be required ---Zhiguo Wan 21/09

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	proposals map[common.Address]bool // Current list of proposals we are pushing

	///	pm	*eth.ProtocolManager	// pm for communications. ---Zhiguo Wan 21/09
	// TODO: pm needs to be passed when initialized
	pbft         *pbftCore // core pbft algorithm. ---Zhiguo 26/09
	commChan     chan *types.PbftMessage
	finishedChan chan struct{}
	manager      events.Manager /// for timer management, copy from fabric --Zhiguo 10/10
	id           uint64

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with
	lock   sync.RWMutex   // Protects the signer fields
}

// New creates a PBFT consensus engine with the initial
// signers set to the ones provided by the user.
/// func New(id uint64, config *params.PBFTConfig, db ethdb.Database) *PBFT{
//=>func New(id uint64, configV *viper.Viper, config *params.PBFTConfig, db ethdb.Database) *PBFT {
func New(id uint64, config *params.PBFTConfig, db ethdb.Database) *PBFT { //=> delete configV, and replaced by loadConfig() --Agzs
	// Set any missing consensus parameters to their defaults
	conf := *config
	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)

	com := make(chan *types.PbftMessage)
	fin := make(chan struct{})

	pb := &PBFT{
		config: &conf,
		db:     db,
		///                pm:	&pm,		// need for communications. ---Zhiguo Wan
		///pbft:   newPbftCore(id, config, etf, com, fin),               /// PBFTCore
		commChan:     com,
		finishedChan: fin,
		manager:      events.NewManagerImpl(),
		id:           id,

		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),
	}

	if pb.config.Epoch == 0 {
		pb.config.Epoch = epochLength
	}
	if pb.config.Period == 0 {
		pb.config.Period = blockPeriod
	}

	if pb.id == DefaultPbftID { //=> add for ordinary node. --Agzs 12.13
		return pb
	}

	pb.manager.SetReceiver(pb) /// Need to implement ProcessEvent. --Zhiguo
	etf := events.NewTimerFactoryImpl(pb.manager)

	//=>configV := loadConfig()   --Agzs                        //=>replace configV in New()  prams. --Agzs
	pb.pbft = newPbftCore(id, configV, etf, com, fin) /// PBFTCore

	pb.pbft.helper.manager = pb.manager //=> add helper.manager --Agzs

	pb.manager.Start()

	// if op.batchTimeout >= pb.pbft.requestTimeout {
	// 	op.pbft.requestTimeout = 3 * op.batchTimeout / 2
	// 	logger.Warningf("Configured request timeout must be greater than batch timeout, setting to %v", op.pbft.requestTimeout)
	// }
	if pb.pbft.requestTimeout >= pb.pbft.nullRequestTimeout && pb.pbft.nullRequestTimeout != 0 { //=> TODO. add --Agzs
		pb.pbft.nullRequestTimeout = 3 * pb.pbft.requestTimeout / 2
		logger.Warningf("Configured null request timeout must be greater than request timeout, setting to %v", pb.pbft.nullRequestTimeout)
	}

	consensus.PBFTEngineFlag = true //=> it marks the PBFT consensus --Agzs 18.03.28
	return pb
}

type TestMsg struct {
	Str       string
	Signature *hibe.SIGBytes
	View      uint64
	Seq       uint64
	ReplicaID uint64
	NodeIndex uint32
}

type PrepareTestMsg struct {
	TestMsg *TestMsg
}

type CommitTestMsg struct {
	TestMsg *TestMsg
}

//test hibe
func (c *PBFT) TestHIBE(str string) error {
	fmt.Printf("test HIBE begin\n")
	node.Start = time.Now()
	//fmt.Println(node.NodeIndex, "start time:", node.Start)
	c.SealTest(str)
	return nil
}

//
func (c *PBFT) SealTest(str string) error {
	if c.pbft.primary(c.pbft.view) != c.pbft.id { /// copied from batch.go:submitToLeader ---Zhiguo
		fmt.Printf("not primary\n")
		return nil
	}

	//hibe := hibe.Hibe
	/*
		privateKey := hibe.GetPrivateKey()
		publicKey := hibe.GetPublicKey()
		signature := hibe.Sign(publicKey, privateKey, str)
	*/

	//start := time.Now()
	signature := hibe.ShadowSign(hibe.PrivateKey, hibe.MasterPubKey, []byte(str), hibe.Random)
	// end := time.Now()
	// if node.ResultFile != nil {
	// 	wt := bufio.NewWriter(node.ResultFile)
	// 	str := fmt.Sprintf("time for node %d ShadowSign  is :%v:\n", node.NodeIndex, end.Sub(start))
	// 	_, err := wt.WriteString(str)
	// 	if err != nil {
	// 		log.Error("write error")
	// 	}
	// 	wt.Flush()
	// }
	testMsg := &TestMsg{
		Str:       str,
		Signature: signature.SIGToBytes(),
		View:      c.pbft.view,
		ReplicaID: c.GetID(),
		NodeIndex: hibe.Index,
	}
	/*
		fmt.Println()
		fmt.Println()
		fmt.Println()
		fmt.Println(signature)
		fmt.Println(signature.SIGToBytes())
	*/
	c.pbft.recvRequestTestMsg(testMsg)
	return nil
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (c *PBFT) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, c.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *PBFT) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return c.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *PBFT) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *PBFT) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}
	// Checkpoint blocks need to enforce zero beneficiary
	checkpoint := (number % c.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return errInvalidCheckpointBeneficiary
	}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidVote
	}
	if checkpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidCheckpointVote
	}
	// Check that the extra-data contains both the vanity and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && signersBytes != 0 {
		return errExtraSigners
	}
	if checkpoint && signersBytes%common.AddressLength != 0 {
		return errInvalidCheckpointSigners
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}
	// All basic checks passed, verify cascading fields
	return c.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *PBFT) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time.Uint64()+c.config.Period > header.Time.Uint64() {
		return ErrInvalidTimestamp
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// If the block is a checkpoint block, verify the signer list
	if number%c.config.Epoch == 0 {
		signers := make([]byte, len(snap.Signers)*common.AddressLength)
		for i, signer := range snap.signers() {
			copy(signers[i*common.AddressLength:], signer[:])
		}
		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], signers) {
			return errInvalidCheckpointSigners
		}
	}
	// All basic checks passed, verify the seal and return
	return c.verifySeal(chain, header, parents)
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *PBFT) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *PBFT) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return c.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (c *PBFT) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// Resolve the authorization key and check against signers
	signer, err := ecrecover(header, c.signatures)
	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return errUnauthorized
	}
	// for seen, recent := range snap.Recents {
	// 	if recent == signer {
	// 		// Signer is among recents, only fail if the current block doesn't shift it out
	// 		if limit := uint64(len(snap.Signers)/2 + 1); seen > number-limit {
	// 			return errUnauthorized
	// 		}
	// 	}
	// }
	// Ensure that the difficulty corresponds to the turn-ness of the signer
	inturn := snap.inturn(header.Number.Uint64(), signer)
	if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
		return errInvalidDifficulty
	}
	if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
		return errInvalidDifficulty
	}
	return nil
}

//=> verifySignature used for verifying the signature of viewchange. --Agzs
func (instance *pbftCore) verifyViewChangeSig(viewchange *types.ViewChange) (bool, error) {
	signer, err := ecrecoverFromSignature(viewchange)
	if signer == viewchange.Signer {
		return true, nil
	}
	return false, err
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *PBFT) Prepare(chain consensus.ChainReader, header *types.Header) error {
	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()

	// Assemble the voting snapshot to check which votes make sense
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if number%c.config.Epoch != 0 {
		c.lock.RLock()

		// Gather all the proposals that make sense voting on
		addresses := make([]common.Address, 0, len(c.proposals))
		for address, authorize := range c.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		if len(addresses) > 0 {
			header.Coinbase = addresses[rand.Intn(len(addresses))]
			if c.proposals[header.Coinbase] {
				copy(header.Nonce[:], nonceAuthVote)
			} else {
				copy(header.Nonce[:], nonceDropVote)
			}
		}
		c.lock.RUnlock()
	}
	// Set the correct difficulty
	header.Difficulty = diffNoTurn
	if snap.inturn(header.Number.Uint64(), c.signer) {
		header.Difficulty = diffInTurn
	}
	// Ensure the extra data has all it's components
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	if number%c.config.Epoch == 0 {
		for _, signer := range snap.signers() {
			header.Extra = append(header.Extra, signer[:]...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(c.config.Period))
	if header.Time.Int64() < time.Now().Unix() {
		header.Time = big.NewInt(time.Now().Unix())
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (c *PBFT) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)
	// fmt.Printf("--------(c *PBFT) Finalize\n") ////xiaobei 1.10
	// fmt.Printf("------root is %x\n",header.Root) ////xiaobei 1.10
	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *PBFT) Authorize(signer common.Address, signFn SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn

	if c.id == DefaultPbftID { //=> add for ordinary node. --Agzs 12.13
		return
	}
	//=> add signer and signFn for pbftCore --Agzs
	c.pbft.signer = signer
	c.pbft.signFn = signFn
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (c *PBFT) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := c.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(c.config, c.signatures, c.db, hash); err == nil {
				log.Trace("Loaded voting snapshot form disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at block zero, make a snapshot
		if number == 0 {
			genesis := chain.GetHeaderByNumber(0)
			if err := c.VerifyHeader(chain, genesis, false); err != nil {
				return nil, err
			}
			signers := make([]common.Address, (len(genesis.Extra)-extraVanity-extraSeal)/common.AddressLength)
			for i := 0; i < len(signers); i++ {
				copy(signers[i][:], genesis.Extra[extraVanity+i*common.AddressLength:])
			}
			snap = newSnapshot(c.config, c.signatures, 0, genesis.Hash(), signers)
			if err := snap.store(c.db); err != nil {
				return nil, err
			}
			log.Trace("Stored genesis voting snapshot to disk")
			break
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	c.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *PBFT) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	if c.id == DefaultPbftID { //=> add for ordinary node. --Agzs 12.13
		return nil, errNotVP
	}
	fmt.Printf("view is %d,  %d\n", c.pbft.view, c.pbft.id)
	//=> ensure primary can seal and sign, others cann't. --Agzs
	if c.pbft.primary(c.pbft.view) != c.pbft.id { /// copied from batch.go:submitToLeader ---Zhiguo
		// Not primary, cannot initiate PBFT protocol and seal block.
		return nil, ErrNotPrimary
	}

	//<-c.finishedChan ////--xiaobei

	////xiaobei --12.15
	select {
	case <-c.finishedChan:
		log.Info("struct in finishedChan has been taken out!")
	default:

	}
	////
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	fmt.Println("block number", number)
	if number == 0 {
		return nil, errUnknownBlock
	}
	// Don't hold the signer fields for the entire sealing procedure
	c.lock.RLock()
	signer, signFn := c.signer, c.signFn
	c.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil, err
	}
	if _, authorized := snap.Signers[signer]; !authorized {
		return nil, errUnauthorized
	}

	//=> --Agzs
	// // If we're amongst the recent signers, wait for the next block
	// for seen, recent := range snap.Recents {
	// 	if recent == signer {
	// 		// Signer is among recents, only wait if the current block doesn't shift it out
	// 		if limit := uint64(len(snap.Signers)/2 + 1); number < limit || seen > number-limit {
	// 			log.Info("Signed recently, must wait for others")
	// 			<-stop
	// 			return nil, nil
	// 		}
	// 	}
	// }

	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Unix(header.Time.Int64(), 0).Sub(time.Now())
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Signers)/2+1) * wiggleTime
		delay += time.Duration(rand.Int63n(int64(wiggle)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))

	select {
	// case <-stop:
	// 	return nil, nil
	case <-time.After(delay):
	}
	// Sign all the things!
	sighash, err := signFn(accounts.Account{Address: signer}, sigHash(header, nil).Bytes()) //=> TODO. --Agzs
	if err != nil {
		return nil, err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)

	///        return block.WithSeal(header), nil
	///     TODO: start PBFT consensus with the signed candidate block. --Zhiguo
	// newBlock := block.WithSeal(header)
	// c.pbft.recvRequestBlock(newBlock) //=> this is starting PBFT. --Agzs
	//preprepare := blockToPrePrepare(newBlock)
	//c.pbft.sendPrePrepare(preprepare)

	////xiaobei 12.13
	var newBlock *types.Block
	select {
	case <-stop:
		log.Info("Stop PBFT algorithm!")
		return nil, nil
	default:
		newBlock = block.WithSeal(header)
		c.pbft.recvRequestBlock(newBlock)
	}
	////

	//=> c.pbft.sendPrePrepare(newBlock)

	/// TODO: wait until the commit messages are received by 2/3 PBFT nodes, then return the block --Zhiguo
	select {
	case <-stop:
		log.Info("Stop PBFT algorithm!")
		//<-c.finishedChan ////--xiaobei
		return nil, nil
	case <-c.finishedChan:
		//log.Info("finishChan is not nil")
		//c.pbft.LastExec = newBlock.Header().Number.Uint64() //=>TODO. LastExec. --Agzs
		return newBlock, nil
	}

	///        return nil, nil

}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *PBFT) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "pbft",
		Version:   "1.0",
		Service:   &API{chain: chain, pbft: c},
		Public:    false,
	}}
	//=>return nil // just like ethash PoW
}

// End of code copied from clique.go   ----Zhiguo Wan 21/09
//////////////////////////////////////////////

///var pluginInstance consensus.Consenter // singleton service

//=> --Agzs
func init() {
	configV = loadConfig()
}

/* // GetPlugin returns the handle to the Consenter singleton
func GetPlugin(c consensus.Stack) consensus.Consenter {
	if pluginInstance == nil {
		pluginInstance = New(c)
	}
	return pluginInstance
}
*/
/* // New creates a new Obc* instance that provides the Consenter interface.
// Internally, it uses an opaque pbft-core instance.
func New(stack consensus.Stack) consensus.Consenter {
	handle, _, _ := stack.GetNetworkHandles()
	id, _ := getValidatorID(handle)
	switch strings.ToLower(config.GetString("general.mode")) {
	case "batch":
		return newObcBatch(id, config, stack)
	default:
		panic(fmt.Errorf("Invalid PBFT mode: %s", config.GetString("general.mode")))
	}
}
*/
func loadConfig() (config *viper.Viper) {
	config = viper.New()

	// for environment variables
	config.SetEnvPrefix(configPrefix)
	config.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	config.SetEnvKeyReplacer(replacer)

	// config.SetConfigName("config")
	// config.AddConfigPath("./")
	// config.AddConfigPath("../pbft")
	// config.AddConfigPath("../../pbft")

	config.SetConfigName("config")
	config.AddConfigPath("./")
	config.AddConfigPath("../consensus/pbft")
	config.AddConfigPath("../../consensus/pbft") //=> copy from fabric. --Agzs

	//========================================================>
	// Path to look for the config file in based on HOME
	home := os.Getenv("HOME") //=>GOPATH -> HOME --Agzs
	for _, p := range filepath.SplitList(home) {
		pbftpath := filepath.Join(p, ".geth-pbft") //=>11.13 $HOME/.geth-pbft. path--Agzs
		config.AddConfigPath(pbftpath)
	}
	//=========================================================>
	// Path to look for the config file in based on GOPATH
	gopath := os.Getenv("GOPATH")
	for _, p := range filepath.SplitList(gopath) {
		pbftpath := filepath.Join(p, "src/github.com/ethereum/go-ethereum/consensus/pbft")
		config.AddConfigPath(pbftpath)
	}

	err := config.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Error reading %s plugin config: %s", configPrefix, err))
	}
	return
}

// // Returns the uint64 ID corresponding to a peer handle
// func getValidatorID(handle *pb.PeerID) (id uint64, err error) {
// 	// as requested here: https://github.com/hyperledger/fabric/issues/462#issuecomment-170785410
// 	if startsWith := strings.HasPrefix(handle.Name, "vp"); startsWith {
// 		id, err = strconv.ParseUint(handle.Name[2:], 10, 64)
// 		if err != nil {
// 			return id, fmt.Errorf("Error extracting ID from \"%s\" handle: %v", handle.Name, err)
// 		}
// 		return
// 	}

// 	err = fmt.Errorf(`For MVP, set the VP's peer.id to vpX,
// 		where X is a unique integer between 0 and N-1
// 		(N being the maximum number of VPs in the network`)
// 	return
// }

// // Returns the peer handle that corresponds to a validator ID (uint64 assigned to it for PBFT)
// func getValidatorHandle(id uint64) (handle *pb.PeerID, err error) {
// 	// as requested here: https://github.com/hyperledger/fabric/issues/462#issuecomment-170785410
// 	name := "vp" + strconv.FormatUint(id, 10)
// 	return &pb.PeerID{Name: name}, nil
// }

// // Returns the peer handles corresponding to a list of replica ids
// func getValidatorHandles(ids []uint64) (handles []*pb.PeerID) {
// 	handles = make([]*pb.PeerID, len(ids))
// 	for i, id := range ids {
// 		handles[i], _ = getValidatorHandle(id)
// 	}
// 	return
// }

/// commented, not used ---Zhiguo
/* type obcGeneric struct {
	stack consensus.Stack
	pbft  *pbftCore
}
func (op *obcGeneric) skipTo(seqNo uint64, id []byte, replicas []uint64) {
	info := &pb.BlockchainInfo{}
	err := proto.Unmarshal(id, info)
	if err != nil {
		logger.Error(fmt.Sprintf("Error unmarshaling: %s", err))
		return
	}
	op.stack.UpdateState(&checkpointMessage{seqNo, id}, info, getValidatorHandles(replicas))
}
func (op *obcGeneric) invalidateState() {
	op.stack.InvalidateState()
}
func (op *obcGeneric) validateState() {
	op.stack.ValidateState()
}
func (op *obcGeneric) getState() []byte {
	return op.stack.GetBlockchainInfoBlob()
}
func (op *obcGeneric) getLastSeqNo() (uint64, error) {
	raw, err := op.stack.GetBlockHeadMetadata()
	if err != nil {
		return 0, err
	}
*/

/// Copied from batch.go. for composing PBFT messages.

// func (c *PBFT) leaderProcReq(req *Request) events.Event {
// 	// XXX check req sig
// 	digest := hash(req)
// 	logger.Debugf("Batch primary %d queueing new request %s", op.pbft.id, digest)
// 	op.batchStore = append(op.batchStore, req)
// 	op.reqStore.storePending(req)

// 	if !op.batchTimerActive {
// 		op.startBatchTimer()
// 	}

// 	if len(op.batchStore) >= op.batchSize {
// 		return op.sendBatch()
// 	}

// 	return nil
// }

// func (c *PBFT) sendBatch() events.Event {
// 	op.stopBatchTimer()
// 	if len(op.batchStore) == 0 {
// 		logger.Error("Told to send an empty batch store for ordering, ignoring")
// 		return nil
// 	}

// 	reqBatch := &RequestBatch{Batch: op.batchStore}
// 	op.batchStore = nil
// 	logger.Infof("Creating batch with %d requests", len(reqBatch.Batch))
// 	return reqBatch
// }

/// Pack a candidate block into a PrePrepare message for sending by the primary node.
// func (c *PBFT) blockToPrePrepare(block *types.Block) *PrePrepare {
//         //now := time.Now()

// /*         headerMsg := &HeaderMsg{
//                 ParentHash: block.Header.ParentHash,
//                 UncleHash: block.Header.UncleHash,
//                 Coinbase: block.Header.Coinbase,
//                 Root: block.Header.,
//                 TxHash: block.Header.TxHash,
//                 ReceiptHash: block.Header.ReceiptHash,
//                 Bloom: block.Header.Bloom,
//                 Difficulty: block.Header.Difficulty,

//                 Number: block.Header.Number,
//                 GasLimit: block.Header.GasLimit,
//                 GasUsed: block.Header.GasUsed,
//                 Time: block.Header.Time,
//                 Extra: block.Header.Extra,
//                 MixDigest: block.Header.MixDigest,
//                 Nonce: block.Header.Nonce
//         }
//         for tx := range block.Transactions {

//         } */
//         blockMsg := &BlockMsg{
//                 HeaderMsg: block.Header,
//                 Transactions: block.Transactions
//         }
// 	pre := &PrePrepare{
// 		// Timestamp: &timestamp.Timestamp{
// 		// 	Seconds: now.Unix(),
// 		// 	Nanos:   int32(now.UnixNano() % 1000000000),
//                 // },
//                 View: c.pbft.view,
//                 SequenceNumber: c.pbft.seqNo,
//                 BlockHash: block.Hash(),
// 		BlockMsg:   blockMsg,
// 		ReplicaId: c.pbft.id,
// 	}
// 	// XXX sign req
// 	return pre
// }

//ProcessEvent allow the primary to send a batch when the timer expires
func (c *PBFT) ProcessEvent(event events.Event) events.Event {
	logger.Debugf("Replica %d batch main thread looping", c.pbft.id)
	// switch et := event.(type) {
	// case batchTimerEvent:
	//         logger.Infof("Replica %d batch timer expired", op.pbft.id)
	//         if op.pbft.activeView && (len(op.batchStore) > 0) {
	//                 return op.sendBatch()
	//         }
	// case *types.Commit:
	//         // TODO, this is extremely hacky, but should go away when batch and core are merged
	//         res := c.pbft.ProcessEvent(event)
	//         c.startTimerIfOutstandingRequests()
	//         return res
	// case viewChangedEvent:
	//         c.batchStore = nil
	//         // Outstanding reqs doesn't make sense for batch, as all the requests in a batch may be processed
	//         // in a different batch, but PBFT core can't see through the opaque structure to see this
	//         // so, on view change, clear it out
	//         c.pbft.outstandingReqBatches = make(map[string]*RequestBatch)

	//         logger.Debugf("Replica %d batch thread recognizing new view", c.pbft.id)
	//         if c.batchTimerActive {
	//                 c.stopBatchTimer()
	//         }

	//         if c.pbft.skipInProgress {
	//                 // If we're the new primary, but we're in state transfer, we can't trust ourself not to duplicate things
	//                 c.reqStore.outstandingRequests.empty()
	//         }

	//         c.reqStore.pendingRequests.empty()
	//         for i := c.pbft.h + 1; i <= c.pbft.h+c.pbft.L; i++ {
	//                 if i <= c.pbft.LastExec {
	//                         continue
	//                 }

	//                 cert, ok := c.pbft.certStore[msgID{v: op.pbft.view, n: i}]
	//                 if !ok || cert.prePrepare == nil {
	//                         continue
	//                 }

	//                 if cert.prePrepare.BatchDigest == "" {
	//                         // a null request
	//                         continue
	//                 }

	//                 if cert.prePrepare.RequestBatch == nil {
	//                         logger.Warningf("Replica %d found a non-null prePrepare with no request batch, ignoring")
	//                         continue
	//                 }

	//                 c.reqStore.storePendings(cert.prePrepare.RequestBatch.GetBatch())
	//         }

	//         return c.resubmitOutstandingReqs()
	// case stateUpdatedEvent:
	//         // When the state is updated, clear any outstanding requests, they may have been processed while we were gone
	//         c.reqStore = newRequestStore()
	//         return c.pbft.ProcessEvent(event)
	// default:
	//         return c.pbft.ProcessEvent(event)
	// }

	return c.pbft.ProcessEvent(event)
}

// //=>TODO. copy from fabric. --Agzs
// // UpdateState attempts to synchronize state to a particular target, implicitly calls rollback if needed
// func (c *PBFT) UpdateState(tag interface{}, target *types.BlockchainInfo, peers []*types.PeerID) {
// 	//events.SendEvent(PBFTCore, stateUpdateEvent{tag, target, peers}) ////xiaobei --12.18
// 	logger.Infof("-----updateState is called") ////xiaobei 1.5
// 	event := <-c.manager
// 	logger.Infof("---events is%+v", event.(type))
// 	c.manager.Queue() <- event
// 	c.manager.Queue() <- stateUpdateEvent{tag, target, peers}
// }

//=> create this func those can be called in other package to modify params in PBFT. --Agzs
func (c *PBFT) SetBlockChainHelper(bc *core.BlockChain) { c.pbft.helper.blockchainHelper = bc }

func (c *PBFT) GetCommChan() chan *types.PbftMessage { return c.commChan }

func (c *PBFT) GetManager() events.Manager { return c.manager }

func (c *PBFT) GetID() uint64 { return c.id } //=>test. --Agzs
