// Copyright 2015 The go-ethereum Authors
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

package eth

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/pbft"
	"github.com/ethereum/go-ethereum/consensus/util/events" //=> fabric -> gethpbft --Agzs
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/fetcher"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/hibe"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/pbc"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/synch" ////xiaobei 1.8
	"github.com/ethereum/go-ethereum/zktx"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header
)

var (
	daoChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

var keymap map[uint32]map[string]*hibe.SecretShadow

// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type privateKeys struct {
	Keys map[uint32]*hibe.SecretShadow
	lock sync.RWMutex
}

type ProtocolManager struct {
	networkId    uint64
	blockchainId uint64 //=>add for blockchain number --Agzs 12.25

	headers     map[common.Hash][]*types.HeaderTx
	headersMark map[common.Hash]interface{}

	headerTxLock      sync.Mutex
	headerTxChan      chan common.Hash
	masterPublickey   *hibe.MasterPublicKey
	masterPrivateKeys []*hibe.SecretShadow

	privateKey *hibe.SecretShadow

	Random     *pbc.Element
	Randoms    []*pbc.Element
	RandomFunc func(index int) *pbc.Element
	R1         []*pbc.Element
	R2         map[uint32]*pbc.Element
	R2Lock     sync.RWMutex
	R          *pbc.Element
	keys       privateKeys //ADD BY LIUWEI,local node's privatekeys piece from parent

	Address      string //ADD BY LIUWEI,local node's public key
	currentLevel uint32

	fastSync  uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	acceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      txPool
	blockchain  *core.BlockChain
	chaindb     ethdb.Database
	chainconfig *params.ChainConfig
	maxPeers    int

	downloader *downloader.Downloader
	fetcher    *fetcher.Fetcher
	peers      *peerSet ////xiaobei 1.9

	SubProtocols []p2p.Protocol

	eventMux      *event.TypeMux
	txSub         *event.TypeMuxSubscription
	minedBlockSub *event.TypeMuxSubscription
	headerTxSub   *event.TypeMuxSubscription

	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}

	commChan chan *types.PbftMessage //=> --Agzs

	////xiaobei 10.17
	pbftmanager   events.Manager
	RecvBlockChan chan *types.Block
	////
	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
}

func PID(id string) string {
	var pid string
	if len(id) > 0 {
		pid = id[:len(id)-4]
	}
	return pid
}

// NewProtocolManager returns a new ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the ethereum network.
func NewProtocolManager(config *params.ChainConfig, mode downloader.SyncMode, blockchainId, networkId uint64, maxPeers int, mux *event.TypeMux, txpool txPool, engine consensus.Engine, blockchain *core.BlockChain, chaindb ethdb.Database) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkId:     networkId,
		blockchainId:  blockchainId, //=>add for blockchain number --Agzs 12.25
		eventMux:      mux,
		txpool:        txpool,
		blockchain:    blockchain,
		chaindb:       chaindb,
		chainconfig:   config,
		maxPeers:      maxPeers,
		peers:         newPeerSet(),
		newPeerCh:     make(chan *peer),
		noMorePeers:   make(chan struct{}),
		txsyncCh:      make(chan *txsync),
		quitSync:      make(chan struct{}),
		RecvBlockChan: make(chan *types.Block, 1),
		currentLevel:  0xffffffff,
		headerTxChan:  make(chan common.Hash, 1024),
		headers:       make(map[common.Hash][]*types.HeaderTx),
		headersMark:   make(map[common.Hash]interface{}),
	}

	//=> add for initing commChan and pbftManager --Agzs
	if pb, ok := engine.(*pbft.PBFT); ok {
		if pb.GetID() != pbft.DefaultPbftID { //=> add for ordinary node --Agzs 12.13
			manager.commChan = pb.GetCommChan()         //=>'pb.commChan undefined (cannot refer to unexported field or method commChan)' --Agzs
			manager.pbftmanager = pb.GetManager()       //=> --Agzs
			manager.RecvBlockChan = pbft.CommittedBlock ////xiaobei 1.17
		}
		id := pb.GetID()                                                                       //=>test. --Agzs
		log.Info("init protocol manager and commChan in NewProtocolManager()!", "replica", id) //=>test. --Agzs
	}
	/*
		if node.NodeIndex == 1 {
			go func() {
				<-node.SetMN
				manager.Randoms = hibe.GenCoef(int(node.Mn.N))
				manager.Random = hibe.GenerateRandom()

				fmt.Println(manager.Randoms)
			}()
		}
	*/
	// Figure out whether to allow fast sync or not
	if mode == downloader.FastSync && blockchain.CurrentBlock().NumberU64() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = downloader.FullSync
	}
	if mode == downloader.FastSync {
		manager.fastSync = uint32(1)
	}
	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Skip protocol version if incompatible with the mode of operation
		if mode == downloader.FastSync && version < eth63 {
			continue
		}
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := manager.newPeer(int(version), p, rw)
				select {
				case manager.newPeerCh <- peer:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer)
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}
	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(mode, chaindb, manager.eventMux, blockchain, nil, manager.removePeer)

	validator := func(header *types.Header) error {
		return engine.VerifyHeader(blockchain, header, true)
	}
	heighter := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) (int, error) {
		// If fast sync is running, deny importing weird blocks
		if atomic.LoadUint32(&manager.fastSync) == 1 {
			log.Warn("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
			return 0, nil
		}
		atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import
		return manager.blockchain.InsertChain(blocks)
	}
	manager.fetcher = fetcher.New(blockchain.GetBlockByHash, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer)

	if consensus.PBFTEngineFlag { //=> --Agzs 18.03.28
		synch.Sync = manager ////xiaobei 1.8
	}
	return manager, nil
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	log.Debug("Removing Ethereum peer", "peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	pm.downloader.UnregisterPeer(id)
	if err := pm.peers.Unregister(id); err != nil {
		log.Error("Peer removal failed", "peer", id, "err", err)
	}
	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

func (pm *ProtocolManager) Start() {

	// broadcast transactions
	pm.txSub = pm.eventMux.Subscribe(core.TxPreEvent{})
	//fmt.Printf("-------(pm *ProtocolManager) Start()") ////xiaobei 1.10
	go pm.txBroadcastLoop()
	// broadcast mined blocks
	pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
	go pm.minedBroadcastLoop()

	pm.headerTxSub = pm.eventMux.Subscribe(core.HeaderTxEvent{})
	go pm.headerTxLoop()
	/////////////////////////////////////
	/// for consensus message processing. --Zhiguo 04/10
	go pm.processConsensusMsg()

	//=> for shared peers --Agzs 12.18
	go pm.processAddPeersMsg()
	go pm.processRemovePeersMsg()

	//--ADD BY LIUWEI 7.4
	go pm.processSetID()

	go pm.processRequestMN()
	go pm.processRequestParentMN()
	go pm.processRequestChildMN()

	go pm.processRequestRandoms()
	go pm.processRequestRandomPiece()

	go pm.processHibeFinished()
	//=> for shared peers --Agzs 11.16
	//go pm.processPeersMsg()
	if consensus.PBFTEngineFlag { //=> --Agzs 18.03.28
		////xiaobei 1.17
		go pm.GetCommittedBlock()
	}
	/////////////////////////////////////

	// start sync handlers
	go pm.syncer()
	go pm.txsyncLoop()

	go pm.addHeaderWithSigLoop()
	if node.ID == node.ROOTID {
		go pm.processRootChainBlock()
	}
}

func (pm *ProtocolManager) processRootChainBlock() {
	sub := pm.eventMux.Subscribe(core.RootChainBlock{})
	for obj := range sub.Chan() {

		block := obj.Data.(core.RootChainBlock)
		blockHash := block.Block.Hash()
		db := pm.chaindb
		db.Put(append(blockHash.Bytes(), core.RootChainBlockHashSuffix...), blockHash.Bytes())

		peers := pm.peers.PeersWithoutTx(blockHash)
		for _, peer := range peers {
			if peer.peerFlag == p2p.LowLevelPeer {
				fmt.Println("send RootChainBlockHash to lower level")
				p2p.Send(peer.rw, RootChainBlockHash, blockHash)
			}
		}

	}
}

func (pm *ProtocolManager) addHeaderWithSigLoop() {
	for hash := range pm.headerTxChan {
		pm.headerTxLock.Lock()
		txs := pm.headers[hash]
		pm.headerTxLock.Unlock()
		sigs := make([]*hibe.SIG, 0)
		index := make([]int, 0)
		for _, tx := range txs {
			sigs = append(sigs, tx.Tx.GetDhibeSig().CompressedBytesToSig())
			index = append(index, int(tx.Index))
		}

		start := time.Now()
		sigrecon := hibe.SignRecon(sigs, index)
		end := time.Now()

		sig := sigrecon.SigToCompressedBytes()
		sender := txs[0].Tx.Sender()
		nonce := txs[0].Tx.Nonce()

		newTx := types.NewHeaderTransaction(nonce, txs[0].Tx.Headers(), &sender, node.LocalLevel)
		recepient := txs[0].Tx.Recipient()
		newTx.SetRecipient(recepient)
		//nonceBytes, err := rlp.EncodeToBytes(nonce)
		//if err != nil {
		//	continue
		//}
		//db := pm.chaindb
		//db.Put(append(sender.Bytes(), core.AddressNonceSuffix...), nonceBytes)
		types.WithSignature(newTx, sig)
		//fmt.Println("new intact header tx", hash.Hex(), newTx.Headers()[0].Hex())

		end_headertime := time.Now()
		if node.ResultFile != nil {
			wt := bufio.NewWriter(node.ResultFile)
			str := fmt.Sprintf("SignRecon  %.3f\n", end.Sub(start).Seconds())
			str_headertx := fmt.Sprintf("SignHeaderTx time is :%v\n", end_headertime.Sub(node.NewHeaderTime).Seconds())
			s := str + str_headertx
			_, err := wt.WriteString(s)
			if err != nil {
				log.Error("write error")
			}
			wt.Flush()
		}
		if hibe.Verify(hibe.MasterPubKey, node.ID, types.HibeHash(newTx).Bytes(), int(node.LocalLevel), newTx.GetDhibeSig().CompressedBytesToSig()) {
			peers := pm.peers.PeersWithoutTx(hash)

			for _, peer := range peers {
				if peer.peerFlag == p2p.UpperLevelPeer {
					fmt.Println("send headerTx to upper level", newTx.Hash().Hex(), newTx.Headers()[0].Hex())
					peer.SendTransactions(types.Transactions{newTx})
				}
			}
		} else {
			fmt.Println("verify headerTx error", newTx.Hash().Hex(), newTx.Headers()[0].Hex())
		}

		//	types.WithSignature(newTx, sig)
		//
		//	fmt.Println(newTx)
	}
}
func (pm *ProtocolManager) Stop() {
	log.Info("Stopping Ethereum protocol")
	zktx.SNfile.Close()
	pm.txSub.Unsubscribe()         // quits txBroadcastLoop
	pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop
	pm.headerTxSub.Unsubscribe()
	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	log.Info("Ethereum protocol stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	if pm.peers.Len() >= pm.maxPeers {
		return p2p.DiscTooManyPeers
	}
	p.Log().Debug("Ethereum peer connected", "name", p.Name())

	//=>TODO. only CurrentLevelPeer and CurrentLevelOrdinaryPeer can handshake for head and genesis. --Agzs 12.12
	if p.peerFlag == p2p.CurrentLevelPeer || p.peerFlag == p2p.CurrentLevelOrdinaryPeer {
		// Execute the Ethereum handshake
		td, head, genesis := pm.blockchain.Status()
		//=> add pm.blockchainId for blockchain --Agzs 12.25
		if err := p.Handshake(pm.networkId, pm.blockchainId, td, head, genesis); err != nil {
			p.Log().Debug("Ethereum handshake failed", "err", err)
			return err
		}
	} else {
		p.td, _, _ = pm.blockchain.Status()
	}
	// Execute the Ethereum handshake
	// td, head, genesis := pm.blockchain.Status()
	// if err := p.Handshake(pm.networkId, td, head, genesis); err != nil {
	// 	p.Log().Debug("Ethereum handshake failed", "err", err)
	// 	return err
	// }
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}
	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {
		p.Log().Error("Ethereum peer registration failed", "err", err)
		return err
	}
	//log.Info("==============peers=====start==================") //=>test.12
	// for _, pp := range pm.peers.peers {
	// 	log.Info("peer infomation", "peer", pp.id, "peer flag", pp.peerFlag) //=>test. --Agzs
	// }
	//log.Info("==============peers=====end==================")
	defer pm.removePeer(p.id)

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.downloader.RegisterPeer(p.id, p.version, p); err != nil {
		fmt.Println("aaa remove")
		return err
	}
	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	pm.syncTransactions(p)

	// If we're DAO hard-fork aware, validate any remote peer with regard to the hard-fork
	if daoBlock := pm.chainconfig.DAOForkBlock; daoBlock != nil {
		// Request the peer's DAO fork header for extra-data validation
		if err := p.RequestHeadersByNumber(daoBlock.Uint64(), 1, 0, false); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		p.forkDrop = time.AfterFunc(daoChallengeTimeout, func() {
			p.Log().Debug("Timed out DAO fork-check, dropping")
			pm.removePeer(p.id)
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}
	log.Info("pm.handle(peer)-----------add peer done-------------") //=>test. --Agzs

	selfEnode := node.GetSelfEnode()
	if p.peerFlag == p2p.CurrentLevelPeer {
		p.SendAddPeerMsg(&node.URLFlag{Enode: &selfEnode, Flag: p2p.CurrentLevelPeer})
	}
	//=> check addPeerUrlArray, ensure addPeerUrlArray and removPeerUrlArray don't have same enode. --Agzs 12.18
	//node.PrintArray() //=>test.12
	//================================== end ==============>

	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			p.Log().Debug("Ethereum message handling failed", "err", err)
			fmt.Println("Ethereum message handling failed", "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	//log.Info("handleMsg()->readMsg()") //=>test. --Agzs
	msg, err := p.rw.ReadMsg()

	//log.Info("Read the next message from the remote peer in pm.handleMsg()") //=>test. --Agzs
	if err != nil {
		//=>log.Info("Read the next message from the remote peer in pm.handleMsg() returns error") //=>test. --Agzs
		return err
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	defer msg.Discard()
	// Handle the message depending on its contents
	switch {

	case msg.Code == RequestRandom:
		fmt.Printf("handleMsg() ---Receive RequestRandom piece-----------from %d\n", p.Index)
		if p.peerFlag != p2p.CurrentLevelPeer {
			log.Error("wrong node level for random")
			break
		}
		if len(pm.R1) == 0 {
			log.Info("local node has no random piece for others")
			break
		}
		if int(p.Index) > len(pm.R1)-1 {
			log.Error("peer index out of range ")
			break
		}
		if pm.R1[p.Index] == nil {
			log.Info(" pm.R1[p.Index] is nil")
			break
		}
		random := &hibe.RandomData{Random: pm.R1[p.Index], Randoms: pm.Randoms}
		err := p2p.Send(p.rw, ReceiveRandom, random.RandomToBigInt())
		//fmt.Println(random)
		//err := p2p.Send(p.rw, ReceiveRandom, mnData{})

		if err != nil {
			log.Error("reply RequestRandom piece error")
		}

	case msg.Code == ReceiveRandom:
		log.Info("handleMsg() ---Receive Random piece msg-----------")

		if p.peerFlag != p2p.CurrentLevelPeer {
			log.Error("wrong node level for random piece")
			break
		}
		if pm.R != nil {
			log.Info("local node already has a random R")
			break
		}
		pm.R2Lock.Lock()
		if len(pm.R2) == 0 {
			log.Info("local node is not ready for receiving random piece")
		}
		if pm.R2[p.Index] != nil {
			fmt.Println("local node already has a random piece from peer", p.Index)
		}
		var data hibe.RandomDataBigInt
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		randomdata := data.BigIntToRandom()
		pm.R2[p.Index] = randomdata.Random
		pm.R2Lock.Unlock()
		fmt.Println("add random piece from ", p.Index, randomdata.Random)
		pm.maybeMakeupRandom()

	case msg.Code == RequestRandoms:
		fmt.Printf("handleMsg() ---Receive RequestRandoms-----------from %d\n", p.Index)
		if p.peerFlag != p2p.CurrentLevelPeer {
			log.Error("wrong node level for randoms")
			break
		}
		if pm.Random == nil {
			log.Info("local node has no randoms data for others")
			break
		}
		//fmt.Println(pm.Random, pm.Randoms)
		random := &hibe.RandomData{Random: pm.Random, Randoms: pm.Randoms}
		err := p2p.Send(p.rw, ReceiveRandoms, random.RandomToBigInt())

		if err != nil {
			log.Error("reply RequestRandoms error")
		}

	case msg.Code == ReceiveRandoms:
		log.Info("handleMsg() ---Receive RandomsMsg-----------")
		if p.peerFlag != p2p.CurrentLevelPeer {
			log.Error("wrong node level for randoms")
			break
		}
		if pm.Random != nil && pm.Randoms != nil {
			break
		}
		var data hibe.RandomDataBigInt
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		random := data.BigIntToRandom()
		pm.Random = random.Random
		pm.Randoms = random.Randoms
		//fmt.Println("receive randoms\n")
		//fmt.Println(pm.Randoms)

	case msg.Code == MasterShadowMsg: //the upppest level node receive a private key
		fmt.Println("handleMsg() ---Receive shadowmsg from", p.Index)
		var data ShadowData
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		if data.Index != node.NodeIndex {

			log.Error("wrong node index")
		}
		if pm.GetPrivateKey() != nil {
			log.Info("already has a privatekey!!!")
			break
		}

		masterPubkey := data.MasterPubKey.BytesToMasterPubkey()
		shadow := data.Shadow.BytesToShadow()

		//	fmt.Println("shadow bytes", data.MasterPubKey)

		pm.SetMasterPubkey(masterPubkey)
		pm.SetPrivateKey(shadow)

		fmt.Printf("node[%d]receive master shadow piece from node[%d] \n", node.NodeIndex, p.Index)

	case msg.Code == RequestMNMsg:
		log.Info("handleMsg() ---RequestMNMsg-----------")

		if node.Mn.M == 0 || node.Mn.N == 0 {
			//log.Info("local node has no mn for others")
			break
		}
		if p.peerFlag == p2p.CurrentLevelPeer { //receive a request for mn from other same level nodes
			err := p2p.Send(p.rw, ReceiveMNMsg, mnData{M: node.Mn.M, N: node.Mn.N})
			if err != nil {
				log.Error("reply Mn to currentlevel nodes error")
			}
		} else if p.peerFlag == p2p.LowLevelPeer { //receive a request for mn from lower level nodes

			err := p2p.Send(p.rw, ReceiveParentMNMsg, mnData{M: node.Mn.M, N: node.Mn.N})
			if err != nil {
				log.Error("reply Mn to lowerlevel nodes error")
			}
		} else if p.peerFlag == p2p.UpperLevelPeer {
			err := p2p.Send(p.rw, ReceiveChildMNMsg, mnData{M: node.Mn.M, N: node.Mn.N})
			if err != nil {
				log.Error("reply Mn to upperlevel nodes error")
			}
		}

	case msg.Code == ReceiveMNMsg: //receive a reply for mn from other same level nodes
		log.Info("handleMsg() ---ReceiveMNMsg from same level-----------")

		if node.Mn.M != 0 || node.Mn.N != 0 {
			break
		}
		var data mnData
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		if p.peerFlag != p2p.CurrentLevelPeer {
			log.Error("receive mnmsg from wrong level node")
			break
		}

		node.Mn.M = data.M
		node.Mn.N = data.N
		fmt.Printf("m,n %d %d\n", data.M, data.N)

	case msg.Code == ReceiveParentMNMsg: //receive a reply for mn from parent nodes
		log.Info("handleMsg() ---ReceiveParentMNMsg-----------")
		if node.ParentMn.M != 0 && node.ParentMn.N != 0 {
			break
		}

		var data mnData
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}

		if p.peerFlag != p2p.UpperLevelPeer {
			log.Error("receive mnmsg from wrong level node")
		}
		fmt.Printf("receive mn from parent ,m:%d   n:%d  \n", data.M, data.N)

		node.ParentMn.M = data.M
		node.ParentMn.N = data.N

	case msg.Code == ReceiveChildMNMsg: //receive a reply for mn from parent nodes
		log.Info("handleMsg() ---ReceiveChildMNMsg-----------")
		if node.ChildrenMn.M != 0 && node.ChildrenMn.N != 0 {
			break
		}

		var data mnData
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}

		if p.peerFlag != p2p.LowLevelPeer {
			log.Error("receive mnmsg from wrong level node")
		}
		fmt.Printf("receive mn from child ,m:%d   n:%d  \n", data.M, data.N)

		node.ChildrenMn.M = data.M
		node.ChildrenMn.N = data.N
		if pm.RandomFunc == nil {
			log.Info("generate randomFunc")
			pm.RandomFunc = hibe.VSS(int(data.N))

		}
		if node.NodeIndex == 1 {
			if len(pm.Randoms) == 0 {
				pm.Randoms = hibe.GenCoef(int(data.N))
				pm.Random = hibe.GenerateRandom()
			}
		}

	case msg.Code == PrePrepareTestMsg: //test hibe
		log.Info("handleMsg() ---PrePrepareTestMsg-----------")
		var data prePrepareTestData
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		pbftmessage := &types.PbftMessage{
			Sender:      data.Sender,
			PayloadCode: data.PayloadCode,
			Payload:     data.PrePrePareTest,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		pm.pbftmanager.Queue() <- pbftmessage

	case msg.Code == PrepareTestMsg: //test hibe
		log.Info("handleMsg() ---PrepareTestMsg-----------")
		var data PrepareTestData
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		pbftmessage := &types.PbftMessage{
			Sender:      data.Sender,
			PayloadCode: data.PayloadCode,
			Payload:     data.PrePare,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		pm.pbftmanager.Queue() <- pbftmessage
	case msg.Code == CommitTestMsg: //test hibe

		log.Info("handleMsg() ---CommitTestMsg-----------")
		var data CommitTestData
		if err := msg.Decode(&data); err != nil {
			log.Info("Decode exists error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		str := data.Commit.TestMsg.Str
		log.Info(str)
		pbftmessage := &types.PbftMessage{
			Sender:      data.Sender,
			PayloadCode: data.PayloadCode,
			Payload:     data.Commit,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		pm.pbftmanager.Queue() <- pbftmessage

	case msg.Code == PrepareTestMsg:
		log.Info("handleMsg() ---PrePrepareMsg-----------") //=>test. --Agzs

		var requestPrePrepare prePrepareData
		if err := msg.Decode(&requestPrePrepare); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//=> add for knownMsg. --Agzs
		pbftmessage := &types.PbftMessage{
			Sender:      requestPrePrepare.Sender,
			PayloadCode: requestPrePrepare.PayloadCode,
			Payload:     requestPrePrepare.PrePrePare,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		log.Info("send preprepare_message to pm.pbftmanager.Queue()") //=>test.--Agzs
		pm.pbftmanager.Queue() <- pbftmessage
		// PrePrepareMsg = 0x11 //=>add --Agzs
	case msg.Code == PrePrepareMsg:
		log.Info("handleMsg() ---PrePrepareMsg-----------") //=>test. --Agzs

		var requestPrePrepare prePrepareData
		if err := msg.Decode(&requestPrePrepare); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//=> add for knownMsg. --Agzs
		pbftmessage := &types.PbftMessage{
			Sender:      requestPrePrepare.Sender,
			PayloadCode: requestPrePrepare.PayloadCode,
			Payload:     requestPrePrepare.PrePrePare,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		log.Info("send preprepare_message to pm.pbftmanager.Queue()") //=>test.--Agzs
		pm.pbftmanager.Queue() <- pbftmessage

	// PrepareMsg    = 0x12
	case msg.Code == PrepareMsg:
		log.Info("handleMsg() ---PrepareMsg-----------") //=>test. --Agzs

		var requestPrepare prepareData
		if err := msg.Decode(&requestPrepare); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//=> add for knownMsg. --Agzs
		pbftmessage := &types.PbftMessage{
			Sender:      requestPrepare.Sender,
			PayloadCode: requestPrepare.PayloadCode,
			Payload:     requestPrepare.PrePare,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		log.Info("send prepare_message to pm.pbftmanager.Queue()") //=>test.--Agzs
		pm.pbftmanager.Queue() <- pbftmessage
	// CommitMsg     = 0x13
	case msg.Code == CommitMsg:
		log.Info("handleMsg() ---CommitMsg-----------") //=>test. --Agzs

		var requestCommit commitData

		if err := msg.Decode(&requestCommit); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//=> add for knownMsg. --Agzs
		pbftmessage := &types.PbftMessage{
			Sender:      requestCommit.Sender,
			PayloadCode: requestCommit.PayloadCode,
			Payload:     requestCommit.Commit,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		log.Info("send commit_message to pm.pbftmanager.Queue()") //=>test.--Agzs
		pm.pbftmanager.Queue() <- pbftmessage
	// CheckpointMsg = 0x14
	case msg.Code == CheckpointMsg:
		log.Info("handleMsg() ---CheckpointMsg-----------") //=>test. --Agzs

		var requestCheckpoint checkpointData

		if err := msg.Decode(&requestCheckpoint); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//=> add for knownMsg. --Agzs
		pbftmessage := &types.PbftMessage{
			Sender:      requestCheckpoint.Sender,
			PayloadCode: requestCheckpoint.PayloadCode,
			Payload:     requestCheckpoint.Checkpoint,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		log.Info("send checkpoint_message to pm.pbftmanager.Queue()") //=>test.--Agzs
		pm.pbftmanager.Queue() <- pbftmessage
	// ViewChangeMsg = 0x15
	case msg.Code == ViewChangeMsg:
		log.Info("handleMsg() ---ViewChangeMsg-----------") //=>test. --Agzs

		var requestViewChange viewChangeData

		if err := msg.Decode(&requestViewChange); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//=> add for knownMsg. --Agzs
		pbftmessage := &types.PbftMessage{
			Sender:      requestViewChange.Sender,
			PayloadCode: requestViewChange.PayloadCode,
			Payload:     requestViewChange.ViewChange,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		log.Info("send viewchange_message to pm.pbftmanager.Queue()") //=>test.--Agzs
		pm.pbftmanager.Queue() <- pbftmessage
	// NewViewMsg    = 0x16
	case msg.Code == NewViewMsg:
		log.Info("handleMsg() ---NewViewMsg-----------") //=>test. --Agzs

		var requestNewView newViewData
		if err := msg.Decode(&requestNewView); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//=> add for knownMsg. --Agzs
		pbftmessage := &types.PbftMessage{
			Sender:      requestNewView.Sender,
			PayloadCode: requestNewView.PayloadCode,
			Payload:     requestNewView.NewView,
		}
		pbftMsgHash := types.Hash(pbftmessage)
		p.MarkMsg(pbftMsgHash)
		log.Info("send newview_message to pm.pbftmanager.Queue()") //=>test.--Agzs
		pm.pbftmanager.Queue() <- pbftmessage

	case msg.Code == AddPeerMsg:
		log.Info("handleMsg() ---AddPeerMsg-----------") //=>test. --Agzs
		var requestAddPeerMsg node.URLFlag               //=>--Agzs 12.5
		if err := msg.Decode(&requestAddPeerMsg); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//log.Info("recvAddPeerMsg", "AddPeerMsg", *requestAddPeerMsg) //=>test. --Agzs
		addPeerMsgHash := types.Hash(requestAddPeerMsg)
		p.MarkAddPeerMsg(addPeerMsgHash)
		node.GetPrivateAdminAPI().OutCallAddPeer(requestAddPeerMsg)
	case msg.Code == RemovePeerMsg:
		log.Info("handleMsg() ---RemovePeerMsg-----------") //=>test. --Agzs
		var requestRemovePeerMsg node.URLFlag               //=>--Agzs 12.5
		if err := msg.Decode(&requestRemovePeerMsg); err != nil {
			log.Info("Decode exists error!!!") //=>test. --Agzs
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		//log.Info("recvAddPeerMsg", "RemovePeerMsg", *requestRemovePeerMsg) //=>test. --Agzs
		removePeerMsgHash := types.Hash(requestRemovePeerMsg)
		p.MarkRemovePeerMsg(removePeerMsgHash)
		log.Info("handleMsg will call RemovePeers") //=>test.--Agzs
		node.GetPrivateAdminAPI().OutCallRemovePeer(requestRemovePeerMsg)

	//=================================================>end<=========================== --Agzs
	case msg.Code == StatusMsg:
		log.Info("handleMsg() ---StatusMsg-----------") //=>test. --Agzs
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")

	// Block header query, collect the requested headers and reply
	case msg.Code == GetBlockHeadersMsg:
		log.Info("handleMsg() ---GetBlockHeadersMsg-----------") //=>test. --Agzs
		// Decode the complex header query
		var query getBlockHeadersData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		hashMode := query.Origin.Hash != (common.Hash{})

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Header
			unknown bool
		)
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Header
			if hashMode {
				origin = pm.blockchain.GetHeaderByHash(query.Origin.Hash)
			} else {
				origin = pm.blockchain.GetHeaderByNumber(query.Origin.Number)
			}
			if origin == nil {
				break
			}
			number := origin.Number.Uint64()
			headers = append(headers, origin)
			bytes += estHeaderRlpSize

			// Advance to the next header of the query
			switch {
			case query.Origin.Hash != (common.Hash{}) && query.Reverse:
				// Hash based traversal towards the genesis block
				for i := 0; i < int(query.Skip)+1; i++ {
					if header := pm.blockchain.GetHeader(query.Origin.Hash, number); header != nil {
						query.Origin.Hash = header.ParentHash
						number--
					} else {
						unknown = true
						break
					}
				}
			case query.Origin.Hash != (common.Hash{}) && !query.Reverse:
				// Hash based traversal towards the leaf block
				var (
					current = origin.Number.Uint64()
					next    = current + query.Skip + 1
				)
				if next <= current {
					infos, _ := json.MarshalIndent(p.Peer.Info(), "", "  ")
					p.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
					unknown = true
				} else {
					if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
						if pm.blockchain.GetBlockHashesFromHash(header.Hash(), query.Skip+1)[query.Skip] == query.Origin.Hash {
							query.Origin.Hash = header.Hash()
						} else {
							unknown = true
						}
					} else {
						unknown = true
					}
				}
			case query.Reverse:
				// Number based traversal towards the genesis block
				if query.Origin.Number >= query.Skip+1 {
					query.Origin.Number -= (query.Skip + 1)
				} else {
					unknown = true
				}

			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += (query.Skip + 1)
			}
		}
		return p.SendBlockHeaders(headers)

	case msg.Code == BlockHeadersMsg:
		// A batch of headers arrived to one of our previous requests
		var headers []*types.Header
		if err := msg.Decode(&headers); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// If no headers were received, but we're expending a DAO fork check, maybe it's that
		if len(headers) == 0 && p.forkDrop != nil {
			// Possibly an empty reply to the fork header checks, sanity check TDs
			verifyDAO := true

			// If we already have a DAO header, we can check the peer's TD against it. If
			// the peer's ahead of this, it too must have a reply to the DAO check
			if daoHeader := pm.blockchain.GetHeaderByNumber(pm.chainconfig.DAOForkBlock.Uint64()); daoHeader != nil {
				if _, td := p.Head(); td.Cmp(pm.blockchain.GetTd(daoHeader.Hash(), daoHeader.Number.Uint64())) >= 0 {
					verifyDAO = false
				}
			}
			// If we're seemingly on the same chain, disable the drop timer
			if verifyDAO {
				p.Log().Debug("Seems to be on the same side of the DAO fork")
				p.forkDrop.Stop()
				p.forkDrop = nil
				return nil
			}
		}
		// Filter out any explicitly requested headers, deliver the rest to the downloader
		filter := len(headers) == 1
		if filter {
			// If it's a potential DAO fork check, validate against the rules
			if p.forkDrop != nil && pm.chainconfig.DAOForkBlock.Cmp(headers[0].Number) == 0 {
				// Disable the fork drop timer
				p.forkDrop.Stop()
				p.forkDrop = nil

				// Validate the header and either drop the peer or continue
				if err := misc.VerifyDAOHeaderExtraData(pm.chainconfig, headers[0]); err != nil {
					p.Log().Debug("Verified to be on the other side of the DAO fork, dropping")
					return err
				}
				p.Log().Debug("Verified to be on the same side of the DAO fork")
				return nil
			}
			// Irrelevant of the fork checks, send the header to the fetcher just in case
			headers = pm.fetcher.FilterHeaders(headers, time.Now())
		}
		if len(headers) > 0 || !filter {
			err := pm.downloader.DeliverHeaders(p.id, headers)
			if err != nil {
				log.Debug("Failed to deliver headers", "err", err)
			}
		}

	case msg.Code == GetBlockBodiesMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			bodies []rlp.RawValue
		)
		for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block body, stopping if enough was found
			if data := pm.blockchain.GetBodyRLP(hash); len(data) != 0 {
				bodies = append(bodies, data)
				bytes += len(data)
			}
		}
		return p.SendBlockBodiesRLP(bodies)

	case msg.Code == BlockBodiesMsg:
		// A batch of block bodies arrived to one of our previous requests
		var request blockBodiesData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver them all to the downloader for queuing
		trasactions := make([][]*types.Transaction, len(request))
		uncles := make([][]*types.Header, len(request))

		for i, body := range request {
			trasactions[i] = body.Transactions
			uncles[i] = body.Uncles
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		filter := len(trasactions) > 0 || len(uncles) > 0
		if filter {
			trasactions, uncles = pm.fetcher.FilterBodies(trasactions, uncles, time.Now())
		}
		if len(trasactions) > 0 || len(uncles) > 0 || !filter {
			err := pm.downloader.DeliverBodies(p.id, trasactions, uncles)
			if err != nil {
				log.Debug("Failed to deliver bodies", "err", err)
			}
		}

	case p.version >= eth63 && msg.Code == GetNodeDataMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash  common.Hash
			bytes int
			data  [][]byte
		)
		for bytes < softResponseLimit && len(data) < downloader.MaxStateFetch {
			// Retrieve the hash of the next state entry
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested state entry, stopping if enough was found
			if entry, err := pm.chaindb.Get(hash.Bytes()); err == nil {
				data = append(data, entry)
				bytes += len(entry)
			}
		}
		return p.SendNodeData(data)

	case p.version >= eth63 && msg.Code == NodeDataMsg:
		// A batch of node state data arrived to one of our previous requests
		var data [][]byte
		if err := msg.Decode(&data); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverNodeData(p.id, data); err != nil {
			log.Debug("Failed to deliver node state data", "err", err)
		}

	case p.version >= eth63 && msg.Code == GetReceiptsMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash     common.Hash
			bytes    int
			receipts []rlp.RawValue
		)
		for bytes < softResponseLimit && len(receipts) < downloader.MaxReceiptFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			results := core.GetBlockReceipts(pm.chaindb, hash, core.GetBlockNumber(pm.chaindb, hash))
			if results == nil {
				if header := pm.blockchain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
					continue
				}
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(results); err != nil {
				log.Error("Failed to encode receipt", "err", err)
			} else {
				receipts = append(receipts, encoded)
				bytes += len(encoded)
			}
		}
		return p.SendReceiptsRLP(receipts)

	case p.version >= eth63 && msg.Code == ReceiptsMsg:
		// A batch of receipts arrived to one of our previous requests
		var receipts [][]*types.Receipt
		if err := msg.Decode(&receipts); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverReceipts(p.id, receipts); err != nil {
			log.Debug("Failed to deliver receipts", "err", err)
		}

	case msg.Code == NewBlockHashesMsg:
		if consensus.PBFTEngineFlag == false { //=> --Agzs 18.03.28
			log.Info("handleMsg() ---NewBlockHashesMsg-----------") //=>test. --Agzs
			var announces newBlockHashesData
			if err := msg.Decode(&announces); err != nil {
				return errResp(ErrDecode, "%v: %v", msg, err)
			}
			// Mark the hashes as present at the remote node
			for _, block := range announces {
				p.MarkBlock(block.Hash)
			}
			// Schedule all the unknown hashes for retrieval
			unknown := make(newBlockHashesData, 0, len(announces))
			for _, block := range announces {
				if !pm.blockchain.HasBlock(block.Hash) {
					unknown = append(unknown, block)
				}
			}
			for _, block := range unknown {
				pm.fetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestOneHeader, p.RequestBodies)
			}
		}

	case msg.Code == NewBlockMsg:
		if consensus.PBFTEngineFlag == false { //=> --Agzs 18.03.28
			log.Info("handleMsg() ---NewBlockMsg-----------") //=>test. --Agzs
			// Retrieve and decode the propagated block
			var request newBlockData
			if err := msg.Decode(&request); err != nil {
				return errResp(ErrDecode, "%v: %v", msg, err)
			}
			// request.Block.ReceivedAt = msg.ReceivedAt
			// request.Block.ReceivedFrom = p

			// Mark the peer as owning the block and schedule it for import
			p.MarkBlock(request.Block.Hash())
			pm.fetcher.Enqueue(p.id, request.Block)

			// Assuming the block is importable by the peer, but possibly not yet done so,
			// calculate the head hash and TD that the peer truly must have.
			var (
				trueHead = request.Block.ParentHash()
				trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
			)
			// Update the peers total difficulty if better than the previous
			if _, td := p.Head(); trueTD.Cmp(td) > 0 {
				p.SetHead(trueHead, trueTD)

				// Schedule a sync if above ours. Note, this will not fire a sync for a gap of
				// a singe block (as the true TD is below the propagated block), however this
				// scenario should easily be covered by the fetcher.
				currentBlock := pm.blockchain.CurrentBlock()
				if trueTD.Cmp(pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64())) > 0 {
					go pm.Synchronise(p)
				}
			}
		}

	case msg.Code == TxMsg:
		log.Info("handleMsg() ---TxMsg-----------") //=>test. --Agzs
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		atomic.StoreUint32(&pm.acceptTxs, 1) //TBD
		if atomic.LoadUint32(&pm.acceptTxs) == 0 {
			break
		}
		// Transactions can be processed, parse all of them and deliver to the pool
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			fmt.Printf("------ err := msg.Decode(&txs)") ////xiaobei 1.10
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		for i, tx := range txs {
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			if tx.TxType() == types.TxHeader && p.peerFlag == p2p.CurrentLevelPeer {
				fmt.Println("receive txheader")
				if hibe.MasterPubKey == nil || hibe.PrivateKey == nil || hibe.Random == nil {
					return errResp(ErrHeaderTx, "dhibe key does not exist")
				}
				if node.ID != node.ROOTID && tx.ID() != node.ID {
					//fmt.Println("receive headertx from other chain")
					return errResp(ErrHeaderTx, "receive headertx from other chain")
				}
				types.DHibeSignTx(tx)
				//	sig := hibe.Sign(hibe.PrivateKey, hibe.MasterPubKey, types.HibeHash(tx).Bytes(), hibe.Random)
				//	tx.SetDhibeSig(&sig)
				if p.peerFlag != p2p.CurrentLevelPeer {
					log.Error("receive txheader from wrong level peer")
					return errResp(ErrHeaderTx, "receive txheader from wrong level peer")
				}
				err := p2p.Send(p.rw, HeaderTxWithSig, &types.HeaderTx{Index: node.NodeIndex, Tx: tx})
				fmt.Println("send txheader with sig")
				if err != nil {
					log.Error("send txheader with sig error")
				}

				nonce := tx.Nonce()

				nonceBytes, err := rlp.EncodeToBytes(nonce)
				if err != nil {
					return nil
				}
				db := pm.chaindb
				db.Put(append(tx.Sender().Bytes(), core.AddressNonceSuffix...), nonceBytes)
				fmt.Println("put nonce", nonce)

				return nil

			} else if recepient := tx.Recipient(); tx.TxType() == types.TxCrossChain && PID(recepient.ID()) == node.ID {
				err := core.ValidateCrossChainTx(tx, core.DB)
				if err != nil {
					return err
				}
			}
			p.MarkTransaction(tx.Hash())
		}
		//fmt.Printf("------txs is %+v", txs) ////xiaobei 1.10
		pm.txpool.AddRemotes(txs)

	case msg.Code == HeaderTxWithSig:
		log.Info("handleMsg() ---HeaderTxWithSig-----------")

		// Transactions can be processed, parse all of them and deliver to the pool
		var headertx *types.HeaderTx
		if err := msg.Decode(&headertx); err != nil {
			fmt.Printf("------ err := msg.Decode(&tx)")
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if headertx.Tx.TxType() != types.TxHeader {
			log.Error("wrong tx type")
			return nil
		}
		if headertx.Index > node.Mn.M {
			log.Error("index out of range")
			return nil
		}

		//	pm.headerTxChan <- headertx

		hash := types.HashTxCommon(headertx.Tx)
		fmt.Println("receive headertxwithsig from", headertx.Index, headertx.Tx.Headers()[0].Hex())
		pm.headerTxLock.Lock()
		//	var txs []*types.Transaction
		if _, ok := pm.headers[hash]; !ok {
			fmt.Println("no hash before", hash)
			pm.headerTxLock.Unlock()
			return nil
		}
		if _, ok := pm.headersMark[headertx.Tx.RLPHash()]; ok {
			pm.headerTxLock.Unlock()
			fmt.Println("already has header")
			return nil
		}
		pm.headersMark[headertx.Tx.RLPHash()] = struct{}{}
		pm.headers[hash] = append(pm.headers[hash], headertx)
		fmt.Println("headertxwithsig count", hash.Hex(), len(pm.headers[hash]), headertx.Tx.Headers()[0].Hex())
		if uint32(len(pm.headers[hash])) >= node.Mn.M {
			pm.headerTxChan <- hash
		}
		pm.headerTxLock.Unlock()

	case msg.Code == RequestPrivateKey:
		log.Info("handleMsg ----RequestPrivateKey------")

		var data RequestPrivateKeyData
		if err := msg.Decode(&data); err != nil {
			log.Error("Decode data error!!!")
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		if p.peerFlag != p2p.LowLevelPeer {
			log.Error("receive RequestPrivateKey from wrong level peer")
			break
		}

		if pm.masterPublickey == nil || pm.privateKey == nil {
			log.Error("generating private key for lower level nodes error,because publickey and privatekey don not exist")
			return nil
		}

		if pm.Randoms == nil || node.NodeIndex == 0xffffffff {
			log.Error("randoms does not exist or index error")
			break
		}
		if node.Mn.M == 0 || node.Mn.N == 0 {
			log.Error("local node has no MN,can not generate randomfunc")
			break
		}

		if pm.R == nil {
			log.Error("R does not exist ")
			break
		}
		start := time.Now()
		//	fmt.Println(pm.privateKey, pm.masterPublickey, pm.Randoms, pm.R, data.Address, int(data.Index), int(data.Level))

		privateKey := hibe.ShadowGen(pm.privateKey, pm.masterPublickey, pm.Randoms, pm.R, data.Address, int(data.Index), int(data.Level))
		end := time.Now()
		if node.ResultFile != nil {
			wt := bufio.NewWriter(node.ResultFile)
			str := fmt.Sprintf("ShadowGen %d %.3f:\n", node.NodeIndex, end.Sub(start).Seconds())
			_, err := wt.WriteString(str)
			if err != nil {
				log.Error("write error")
			}
			wt.Flush()
		}
		err := p2p.Send(p.rw, KeyMsg, ShadowData{Index: node.NodeIndex, MasterPubKey: pm.masterPublickey.MasterPubkeyToBytes(), Shadow: privateKey.ShadowToBytes()})

		//fmt.Printf("send private key piece to %d\n", data.Index)
		//	fmt.Println(pm.masterPublickey)
		//fmt.Println(privateKey)

		if err != nil {
			log.Error("send key to lower level nodes error")
		}
		if node.LocalLevel == node.TotalLevel-1 {

			ID2Key := make(map[string]*hibe.ShadowBytes)
			var keys []hibe.KeyAndID
			id := data.Address
			baseid := id[0 : len(id)-2]
			var i uint16
			for i = 1; i < 200; i++ {
				var b1, b2 byte
				b1 = byte(i >> 8)
				b2 = byte(i)
				if b1 == byte(0) {
					b1 = byte(1)
				}
				if b2 == byte(0) {
					b2 = byte(1)
				}
				bs := []byte{b1, b2}
				tempid := baseid + string(bs[:])
				pk := hibe.ShadowGen(pm.privateKey, pm.masterPublickey, pm.Randoms, pm.R, tempid, int(data.Index), int(data.Level))
				ID2Key[tempid] = pk.ShadowToBytes()
			}
			for id, key := range ID2Key {
				keys = append(keys, hibe.KeyAndID{key, id})
			}
			sd := BatchData{Index: node.NodeIndex, Keys: keys}
			err := p2p.Send(p.rw, ReplyBatch, sd)
			if err != nil {
				log.Error("send batchkey to lower level nodes error")
				fmt.Println(err)
			}

		}

		log.Info("handleMsg ----SetAddressMsg------end")

	case msg.Code == ReplyBatch:
		pm.keys.lock.Lock()
		log.Info("handleMsg ----ReplyBatch------")
		var key BatchData
		if err := msg.Decode(&key); err != nil {
			log.Error("Decode BatchData error!!!")
			fmt.Println(err)
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		if key.Index != p.Index {
			log.Error("reveive privatekey from wrong index")
		}
		if len(keymap) == 0 {
			keymap = make(map[uint32]map[string]*hibe.SecretShadow)
		}
		id2key := make(map[string]*hibe.SecretShadow)
		for _, item := range key.Keys {
			id2key[item.ID] = item.Key.BytesToShadow()
		}
		keymap[key.Index] = id2key
		var count uint32
		if len(keymap) >= int(node.ParentMn.N) && node.KeyCount == 0 {
			if len(hibe.IDKey) == 0 {
				hibe.IDKey = make(map[string]*hibe.SecretShadow)
			}
			if hibe.Random == nil {
				hibe.Random = hibe.GenerateRandom()
			}
			ids := reflect.ValueOf(id2key).MapKeys()
			for _, id := range ids {
				idss := id.String()
				var indexs []int
				var keys []*hibe.SecretShadow

				for index, id2key := range keymap {
					if _, ok := id2key[idss]; ok {
						indexs = append(indexs, int(index))
						keys = append(keys, id2key[idss])
					}
				}
				tmpkey := hibe.KeyRecon(keys, indexs)
				//fmt.Println(tmpkey, hibe.MasterPubKey, []byte("helloworld"), hibe.Random)
				sig := hibe.ShadowSign(tmpkey, hibe.MasterPubKey, []byte("helloworld"), hibe.Random)
				t := hibe.Verify(hibe.MasterPubKey, idss, []byte("helloworld"), int(hibe.Level), sig)
				if t {
					//count++
					hibe.IDKey[idss] = hibe.KeyRecon(keys, indexs)
					//	fmt.Println("sig valid", idss)
					count = count + 1
					node.KeyCount = uint32(count)
					//fmt.Println(node.KeyCount)

				} else {
					fmt.Println("sig invalid", idss)
				}
			}
			fmt.Println("total success", count)

		}
		pm.keys.lock.Unlock()
		//ADD BY LIUWEI
	case msg.Code == KeyMsg:
		log.Info("handleMsg ----PrivateKeyMsg------")
		var key ShadowData
		if err := msg.Decode(&key); err != nil {
			log.Error("Decode keyData error!!!")
			fmt.Println(err)
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		if key.Index != p.Index {
			log.Error("reveive privatekey from wrong index")
		}
		log.Info(" receive PrivateKey piece from parent")

		masterPubkey := key.MasterPubKey.BytesToMasterPubkey()
		shadow := key.Shadow.BytesToShadow()

		//fmt.Println(masterPubkey)
		//fmt.Println(shadow)
		pm.SetMasterPubkey(masterPubkey)
		pm.AddPrivateKeyPiece(p, shadow)
		log.Info("handleMsg ----PrivateKeyMsg------end")

	case msg.Code == HibeFinishedMsg:
		log.Info("lower level has submit a hibefinished msg")
		var data HibeData
		if err := msg.Decode(&data); err != nil {
			log.Error("Decode HibeData error!!!")
			fmt.Println(err)
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		node.TestHIBE <- data.Str

	case msg.Code == RootChainBlockHash:
		log.Info("handleMsg ----RootChainBlockHash------")
		var BlockHash common.Hash
		if err := msg.Decode(&BlockHash); err != nil {
			log.Error("Decode t error!!!")
			fmt.Println(err)
			return errResp(ErrDecode, "%v: %v", msg, err)
		}

		if node.LocalLevel == node.TotalLevel-1 {
			fmt.Println("storing rootchainblock hash", BlockHash.Hex())
			db := pm.chaindb
			db.Put(append(BlockHash.Bytes(), core.RootChainBlockHashSuffix...), BlockHash.Bytes())
			return nil
		}

		peers := pm.peers.PeersWithoutTx(BlockHash)
		for _, peer := range peers {
			if peer.peerFlag == p2p.LowLevelPeer {
				fmt.Println("send RootChainBlockHash to lower level", BlockHash.Bytes())

				p2p.Send(peer.rw, RootChainBlockHash, BlockHash)
			}
		}

	default:
		log.Info("handleMsg() ---default-----------") //=>test. --Agzs
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
		//fmt.Println()
	}
	return nil
}

//ADD BY LIUWEI
//store private key in local node
func (pm *ProtocolManager) AddPrivateKeyPiece(p *peer, key *hibe.SecretShadow) {
	pm.keys.lock.Lock()
	defer pm.keys.lock.Unlock()
	if pm.keys.Keys == nil {
		pm.keys.Keys = make(map[uint32]*hibe.SecretShadow)
	}
	if _, ok := pm.keys.Keys[p.Index]; ok {
		log.Info("private key exists")
		return
	}
	pm.keys.Keys[p.Index] = key
	fmt.Printf("add private key piece from %d\n", p.Index)
	//fmt.Println(key)
	pm.maybeMakeupPrivateKey()

}

//
func (pm *ProtocolManager) maybeMakeupRandom() {
	if pm.R != nil {
		return
	}
	if len(pm.R2) < int(node.Mn.M) {
		return
	}
	rs := make([]*pbc.Element, 0)
	pm.R2Lock.Lock()
	for _, r := range pm.R2 {
		rs = append(rs, r)
	}
	pm.R2Lock.Unlock()
	pm.R = hibe.VSSValueSum(rs)
	fmt.Println("local node make up a complete random")
	fmt.Println(pm.R)
}

//
func (pm *ProtocolManager) maybeMakeupPrivateKey() {

	if pm.privateKey != nil {
		fmt.Println("already has a complete private key")
		return
	}
	if node.ParentMn.N == 0 || uint32(len(pm.keys.Keys)) < node.ParentMn.N {
		return
	}
	var indexs []int
	var keys []*hibe.SecretShadow

	for index, key := range pm.keys.Keys {

		indexs = append(indexs, int(index))
		keys = append(keys, key)
	}
	start := time.Now()
	pm.privateKey = hibe.KeyRecon(keys, indexs)
	end := time.Now()
	if node.LocalLevel != 0 {
		if node.ResultFile != nil {
			wt := bufio.NewWriter(node.ResultFile)
			str := fmt.Sprintf("KeyRecon %d %d %d %.3f\n", node.NodeIndex, node.Mn.M, node.Mn.N, end.Sub(start).Seconds())
			str_kengen := fmt.Sprintf("KeyGen %d %d %d %.3f\n", node.NodeIndex, node.ParentMn.M, node.ParentMn.N, end.Sub(node.KeyRequestTime).Seconds())
			s := str + str_kengen
			_, err := wt.WriteString(s)
			if err != nil {
				log.Error("write error")
			}
			wt.Flush()
			//fmt.Println(node.NodeIndex, "genereate key at time:", node.KeyGenerateTime)
			fmt.Println(node.NodeIndex, "total time for generating privatekey:", node.KeyGenerateTime.Sub(node.KeyRequestTime))
		}

	}

	hibe.PrivateKey = pm.privateKey
	node.KeyStat = true
	// if pm.privateKey != nil {

	// 	node.KeyGenerateTime = time.Now()
	// 	if node.LocalLevel != 0 {
	// 		wt := bufio.NewWriter(node.ResultFile)
	// 		str := fmt.Sprintf("time for node %d generating privatekey is:%v\n", node.NodeIndex, node.KeyGenerateTime.Sub(node.KeyRequestTime))
	// 		_, err := wt.WriteString(str)
	// 		if err != nil {
	// 			log.Error("write error")
	// 		}
	// 		wt.Flush()
	// 		//fmt.Println(node.NodeIndex, "genereate key at time:", node.KeyGenerateTime)
	// 		fmt.Println(node.NodeIndex, "total time for generating privatekey:", node.KeyGenerateTime.Sub(node.KeyRequestTime))
	// 	}
	// 	//fmt.Println(pm.privateKey)
	// }

}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			td = new(big.Int).Add(block.Difficulty(), pm.blockchain.GetTd(block.ParentHash(), block.NumberU64()-1))
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		// Send the block to a subset of our peers
		transfer := peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range transfer {
			if peer.peerFlag == p2p.CurrentLevelPeer || peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
				// just send block to Current level peer include ordinary peer. --Agzs
				peer.SendNewBlock(block, td)
			}
			//=>peer.SendNewBlock(block, td)
		}
		log.Trace("Propagated block", "hash", hash, "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
	// Otherwise if the block is indeed in out own chain, announce it
	if pm.blockchain.HasBlock(hash) {
		for _, peer := range peers {
			if peer.peerFlag == p2p.CurrentLevelPeer || peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
				// just send block to Current level peer include ordinary peer. --Agzs
				peer.SendNewBlockHashes([]common.Hash{hash}, []uint64{block.NumberU64()})
			}
			//=>peer.SendNewBlockHashes([]common.Hash{hash}, []uint64{block.NumberU64()})
		}
		log.Trace("Announced block", "hash", hash, "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}

// BroadcastTx will propagate a transaction to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTx(hash common.Hash, tx *types.Transaction) {
	txtype := tx.TxType()
	peers := pm.peers.PeersWithoutTx(hash)
	//fmt.Println(peers)
	// Broadcast transaction to a batch of peers not knowing about it
	switch txtype {
	case types.TxNormal:
		//FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
		for _, peer := range peers {
			if peer.peerFlag == p2p.CurrentLevelPeer || peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
				// just send Tx to Current level peer include ordinary peer. --Agzs
				peer.SendTransactions(types.Transactions{tx})
			}
			//=>peer.SendTransactions(types.Transactions{tx})
		}
		log.Trace("Broadcast transaction", "hash", hash, "recipients", len(peers))
	case types.TxDhibe, types.TxCrossChain:
		//	if node.ID != node.ROOTID && tx.ID() == node.ID {
		if node.ID != node.ROOTID {
			for _, peer := range peers {
				if peer.peerFlag == p2p.UpperLevelPeer {
					peer.SendTransactions(types.Transactions{tx})
				}
			}
		}
		/*
			case types.TxHeader:
				for _, peer := range peers {
					if peer.peerFlag == p2p.CurrentLevelPeer {
						fmt.Println("send headerTx")
						peer.SendTransactions(types.Transactions{tx})
					}
				}
		*/

	case types.TxZK:
		//	if node.ID != node.ROOTID && tx.ID() == node.ID {
		if node.ID != node.ROOTID {
			for _, peer := range peers {
				if peer.peerFlag == p2p.UpperLevelPeer {
					peer.SendTransactions(types.Transactions{tx})
				}
			}
		}
	}

}

func (pm *ProtocolManager) RequestHeaderTxWithPartSig(hash common.Hash, tx *types.Transaction) {

	peers := pm.peers.PeersWithoutTx(hash)
	for _, peer := range peers {
		if peer.peerFlag == p2p.CurrentLevelPeer {
			fmt.Println("Request for HeaderTx With Part Sig", tx.Headers()[0].Hex())
			peer.SendTransactions(types.Transactions{tx})
		}
	}
}

// Mined broadcast loop
func (self *ProtocolManager) minedBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.minedBlockSub.Chan() {
		switch ev := obj.Data.(type) {
		case core.NewMinedBlockEvent:
			log.Info("-----------NewMinedBlockEvent is called----------------")
			self.BroadcastBlock(ev.Block, true)  // First propagate block to peers
			self.BroadcastBlock(ev.Block, false) // Only then announce to the rest

		}
	}
}

//////////////////////////////////////////////////////
/// Process consensus messages. Zhiguo 04/10
/// Broadcast any consensus message from commChan, which is
/// used by pbft engine to pass the messages to ProtocolManager for broadcast.
func (self *ProtocolManager) processConsensusMsg() {
	//fmt.Println("-----Get message from commChan,processConsensusMsg-----") ////test--xiaobei 10.31
	/// Get message from commChan, which is sent by PBFT consensus algorithm.
	log.Info("protocolManager process consensus msg!") //=>test. --Agzs
	for msg := range self.commChan {
		log.Info("protocolManager.processConsensusMsg() process commChan!") //=>test. --Agzs
		self.BroadcastMsg(msg)                                              //=> m -> msg --Agzs

	}
}

// BroadcastMsg will propagate a pbftmessage to all peers which are not known to
// already have the given pbftMessage.
func (pm *ProtocolManager) BroadcastMsg(msg *types.PbftMessage) {
	log.Info("pm.BroadcastMsg() start------------") //=>test. --Agzs
	//=> add PeerWithoutMsg() start. --Agzs
	hash := types.Hash(msg)
	//	peers := pm.peers.peers
	peers := pm.peers.PeersWithoutMsg(hash)
	//
	//fmt.Println(len(peers))
	//=> add PeerWithoutMsg() end. --Agzs

	//=>log.Info("preprep1", "view", msg.GetPrePrepare().GetView(), "hash", common.BytesToHash(msg.GetPrePrepare().GetBlockHash()), "ReplicaId", msg.GetPrePrepare().GetReplicaId()) //=>test.

	//=>for _, peer := range pm.peers.peers { //=> peer=>peers=>peerSet=>pm, change pm.peers to pm.peerSet.peers? --Agzs
	for _, peer := range peers {
		//log.Info("peer broadcast msg", "peer", peer.id, "send msg's hash:", hash) //=>test. --Agzs
		if peer.peerFlag == p2p.CurrentLevelPeer {
			// just send PbftMessage to Current level peer except ordinary peer, since ordinary peer is not signer. --Agzs
			peer.SendMsg(msg)
		}
		//=>peer.SendMsg(msg)
	}
	//log.Info("pm.BroadcastMsg() end------------") //=>test. --Agzs

	log.Trace("Broadcast pbftMsg", "hash", hash, "recipients", len(pm.peers.peers)) //=> peers ->  pm.peers.peers --Agzs
}

//
func (pm *ProtocolManager) SetPrivateKey(pk *hibe.SecretShadow) {
	if pm.privateKey != nil {
		return
	}
	pm.privateKey = pk
	node.KeyStat = true
	fmt.Println("local node set private key", pk)
}

//
func (pm *ProtocolManager) GetPrivateKey() *hibe.SecretShadow {
	return pm.privateKey
}

//
func (pm *ProtocolManager) GetMasterPubkey() *hibe.MasterPublicKey {
	return pm.masterPublickey
}

//
func (pm *ProtocolManager) SetMasterPubkey(master *hibe.MasterPublicKey) {
	if pm.masterPublickey != nil {
		return
	}
	pm.masterPublickey = master
	hibe.MasterPubKey = master
	fmt.Println("add masterpubkey", pm.masterPublickey)
}

//ADD BY LIUWEI 7.4
func (self *ProtocolManager) processRequestRandoms() {
	if node.NodeIndex == 0xffffffff {
		return
	}
	fmt.Println(node.TotalLevel, node.LocalLevel)

	t := time.NewTimer(5 * time.Second)
	for {
		<-t.C
		t.Reset(5 * time.Second)

		if node.TotalLevel == 0xffffffff {
			continue
		}
		if self.Randoms != nil {
			t.Stop()
			return
		}

		if node.LocalLevel == node.TotalLevel {
			fmt.Println(node.TotalLevel, node.LocalLevel)
			t.Stop()
			return
		}

		peers := self.peers.peers
		for _, peer := range peers {
			if peer.peerFlag == p2p.CurrentLevelPeer {
				err := p2p.Send(peer.rw, RequestRandoms, struct{}{})
				fmt.Println("request randoms from ", peer.Index)
				if err != nil {
					log.Error("send randomRequest error")
				}
			}
		}
	}
}

func (self *ProtocolManager) processRequestRandomPiece() {

	t := time.NewTimer(6 * time.Second)
	for {
		<-t.C

		t.Reset(6 * time.Second)
		if node.LocalLevel == 0xffffffff {
			continue
		}

		if node.Mn.M == 0 || node.Mn.N == 0 {
			continue
		}

		if self.RandomFunc == nil {
			continue
		}

		if self.R != nil {
			t.Stop()
			return
		}

		if len(self.R1) == 0 {
			self.R1 = make([]*pbc.Element, node.Mn.M+1)
			//fmt.Println("make r1", len(self.R1))
			f := self.RandomFunc
			for i := 1; i <= int(node.Mn.M); i++ {
				self.R1[i] = f(i)
			}

			self.R2 = make(map[uint32]*pbc.Element)
			self.R2Lock.Lock()
			self.R2[node.NodeIndex] = self.R1[node.NodeIndex]
			self.R2Lock.Unlock()
		}
		if node.Mn.M == 1 {
			self.maybeMakeupRandom()
		}
		peers := self.peers.peers
		for _, peer := range peers {
			if peer.peerFlag == p2p.CurrentLevelPeer {
				self.R2Lock.Lock()
				if _, ok := self.R2[peer.Index]; !ok {
					err := p2p.Send(peer.rw, RequestRandom, struct{}{})
					fmt.Println("send RequestRandom piece request to brothers index:", peer.Index)
					if err != nil {
						log.Error("send RequestRandom error")
					}
				}
				self.R2Lock.Unlock()
			}
		}
	}

}

//ADD BY LIUWEI 7.4
func (self *ProtocolManager) processRequestMN() {
	t := time.NewTimer(6 * time.Second)
	for {
		<-t.C
		t.Reset(6 * time.Second)

		if node.Mn.M != 0 && node.Mn.N != 0 {
			t.Stop()
			return
		}
		peers := self.peers.peers
		for _, peer := range peers {
			if peer.peerFlag == p2p.CurrentLevelPeer {
				err := p2p.Send(peer.rw, RequestMNMsg, struct{}{})
				//log.Info("send MNRequest to others")
				if err != nil {
					log.Error("send MNRequest error")
				}
			}
		}
	}
}

//ADD BY LIUWEI 7.4
func (self *ProtocolManager) processRequestParentMN() {
	t := time.NewTimer(6 * time.Second)
	for {
		<-t.C

		t.Reset(6 * time.Second)
		if node.LocalLevel == 0xffffffff {
			continue
		}
		if node.LocalLevel == 0 {
			t.Stop()
			return
		}
		if node.ParentMn.M != 0 && node.ParentMn.N != 0 {
			t.Stop()
			return
		}
		peers := self.peers.peers
		for _, peer := range peers {
			if peer.peerFlag == p2p.UpperLevelPeer {
				err := p2p.Send(peer.rw, RequestMNMsg, struct{}{})
				log.Info("send MNRequest to parent")
				if err != nil {
					log.Error("send MNRequest error")
				}
			}
		}
	}
}

//ADD BY LIUWEI 7.4
func (self *ProtocolManager) processRequestChildMN() {
	t := time.NewTimer(6 * time.Second)
	for {
		<-t.C

		t.Reset(6 * time.Second)
		if node.LocalLevel == 0xffffffff {
			continue
		}
		if node.ChildrenMn.M != 0 && node.ChildrenMn.N != 0 {
			t.Stop()
			return
		}
		peers := self.peers.peers
		for _, peer := range peers {
			if peer.peerFlag == p2p.LowLevelPeer {
				err := p2p.Send(peer.rw, RequestMNMsg, struct{}{})
				log.Info("send MNRequest to child")
				if err != nil {
					log.Error("send MNRequest error")
				}
			}
		}
	}
}

//ADD BY LIUWEI 7.4
func (self *ProtocolManager) processSetID() {
	for address := range node.LocalAddress {
		node.KeyRequestTime = time.Now()
		//	fmt.Println(node.NodeIndex, "request key start at time:", node.KeyRequestTime)
		currentLevel := node.LocalLevel
		totalLevel := node.TotalLevel
		self.currentLevel = currentLevel

		if currentLevel == 0xffffffff || totalLevel == 0xffffffff {
			continue
		}
		if currentLevel != 0 && node.ParentMn.N == 0 {
			log.Info("parent m does not exist")
			continue
		}

		m, n := node.Mn.M, node.Mn.N

		if self.currentLevel == 0 && node.NodeIndex == 1 {
			if m == 0 || n == 0 {
				continue
			}
			start := time.Now()
			masterPubkey, masterKeys, err := hibe.Setup(int(totalLevel), int(m), int(n))
			end := time.Now()
			diff := end.Sub(start)
			if node.ResultFile != nil {
				wt := bufio.NewWriter(node.ResultFile)
				str := fmt.Sprintf("setup %d %d %.3f\n", node.LocalLevel, node.NodeIndex, diff.Seconds())
				_, err = wt.WriteString(str)
				wt.Flush()
			}
			//	masterPubkey, masterKeys, err := hibe.Setup(4, 4, 4)
			if err != nil {
				log.Error("setup error")
			}
			self.masterPrivateKeys = masterKeys
			self.SetMasterPubkey(masterPubkey)
			self.SetPrivateKey(masterKeys[node.NodeIndex-1])

			go self.SendShadow()
			break
		}

		peers := self.peers.peers
		for _, peer := range peers {
			if peer.peerFlag == p2p.UpperLevelPeer {
				//index := self.GetParentIndex()
				err := p2p.Send(peer.rw, RequestPrivateKey, RequestPrivateKeyData{Address: address, Level: self.currentLevel, Index: node.NodeIndex, N: node.Mn.N})
				if err != nil {
					log.Error("RequestPrivateKey error")
				}
			}
		}
	}

}

func (self *ProtocolManager) processHibeFinished() {
	str := <-node.HibeFinished

	peers := self.peers.peers
	for _, peer := range peers {
		if peer.peerFlag == p2p.UpperLevelPeer && peer.Index == 1 {

			err := p2p.Send(peer.rw, HibeFinishedMsg, HibeData{Str: str})
			if err != nil {
				log.Error("RequestPrivateKey error")
			}
		}
	}
}

//
func (self *ProtocolManager) GetParentIndex() []uint32 {
	var index []uint32
	keys := self.keys
	var Count uint32

	if keys.Keys != nil {
		Count = uint32(len(keys.Keys))
	}

	for i := uint32(1); i <= node.ParentMn.M && Count < node.ParentMn.N; i++ {
		if _, ok := keys.Keys[i]; !ok {
			index = append(index, i)
			Count++
		}
	}
	return index
}

//
func (self *ProtocolManager) SendShadow() {
	peers := self.peers.peers
	for _, peer := range peers {
		if peer.peerFlag == p2p.CurrentLevelPeer {
			shadows := self.masterPrivateKeys
			if shadows == nil {
				log.Info("mastershadows is empty")
				return
			}
			index := peer.Index

			if int(index) > len(shadows) || shadows[index-1] == nil {
				log.Info("index error")
				return
			}

			err := p2p.Send(peer.rw, MasterShadowMsg, ShadowData{Shadow: shadows[index-1].ShadowToBytes(), MasterPubKey: self.masterPublickey.MasterPubkeyToBytes(), Index: index})

			fmt.Println("send shadow to", index)
			//fmt.Println("shadow bytes", shadows[index-1].ShadowToBytes())
			if err != nil {
				log.Error("send shadow error")
			}

		}
	}
}

func (self *ProtocolManager) processAddPeersMsg() { //=> --Agzs 12.18
	/// Get message from commChan, which is sent by node/api.go.
	log.Info("protocolManager process AddPeersMsg!") //=>test. --Agzs

	for addPeerMsg := range node.AddPeerComm {
		self.BroadcastAddPeers(addPeerMsg)
	}
}
func (self *ProtocolManager) processRemovePeersMsg() { //=> --Agzs 12.18
	/// Get message from commChan, which is sent by node/api.go.
	log.Info("protocolManager process RemovePeerMsg!") //=>test. --Agzs
	for removePeerMsg := range node.RemovePeerComm {
		self.BroadcastRemovePeers(removePeerMsg)
	}
}

// BroadcastAddPeers will propagate a addPeerMsg to all peers which are not known to
// already have the given addPeerMsg.
//=>--Agzs 11.15
func (pm *ProtocolManager) BroadcastAddPeers(addPeerMsg *node.URLFlag) {
	hash := types.Hash(addPeerMsg)
	peers := pm.peers.PeersWithoutAddPeerMsg(hash)
	log.Info("addPeerMsg information", "enode", *addPeerMsg.Enode, "flag", addPeerMsg.Flag) //=>tes.12
	for _, peer := range peers {
		log.Info("peer broadcast addPeerMsg", "peer", peer.id, "send msg's hash:", hash) //=>test. --Agzs

		// receive LowLevelPeer's enode, just broadcast msg to current level peer. --Agzs
		// receive CurrentLevelPeer's enode, roadcast msg to all level peer. --Agzs
		// receive UpperLevelPeer's enode, just broadcast msg to current level peer. --Agzs
		// receive CurrentLevelOrdinaryPeer's enode, just broadcast msg to currentLevelPeer and CurrentLevelOrdinaryPeer. --Agzs

		if addPeerMsg.Flag == p2p.CurrentLevelPeer {
			if peer.peerFlag == p2p.CurrentLevelPeer {
				peer.SendAddPeerMsg(addPeerMsg)
			}
		}

		// if addPeerMsg.Flag == p2p.UpperLevelPeer { //=>addPeerMsg means adding a upper level peer --Agzs
		// 	if peer.peerFlag == p2p.CurrentLevelPeer { //=> only broadcast addPeerMsg to current level peer --Agzs
		// 		peer.SendAddPeerMsg(addPeerMsg)
		// 	}
		// } else if addPeerMsg.Flag == p2p.CurrentLevelPeer { //=>addPeerMsg means adding a current level peer --Agzs
		// 	if peer.peerFlag == p2p.LowLevelPeer {
		// 		//=>From this peer, currentLevePeer is it's parent, change Flag to UpperLevelPeer and broadcast msg. --Agzs
		// 		peer.SendAddPeerMsg(&node.URLFlag{Enode: addPeerMsg.Enode, Flag: p2p.UpperLevelPeer})
		// 	} else if peer.peerFlag == p2p.CurrentLevelPeer {
		// 		//=>From this peer, currentLevePeer is it's brother, just broadcast msg. --Agzs
		// 		peer.SendAddPeerMsg(addPeerMsg)
		// 	} else if peer.peerFlag == p2p.UpperLevelPeer {
		// 		//=>From this peer, currentLevePeer is child, change Flag LowLevelPeer to and broadcast msg. --Agzs
		// 		peer.SendAddPeerMsg(&node.URLFlag{Enode: addPeerMsg.Enode, Flag: p2p.LowLevelPeer})
		// 	} else if peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
		// 		peer.SendAddPeerMsg(&node.URLFlag{Enode: addPeerMsg.Enode, Flag: p2p.CurrentLevelOrdinaryPeer})
		// 	}
		// } else if addPeerMsg.Flag == p2p.LowLevelPeer { //=>addPeerMsg means adding a low level peer --Agzs
		// 	if peer.peerFlag == p2p.CurrentLevelPeer { //=> only broadcast addPeerMsg to current level peer --Agzs
		// 		peer.SendAddPeerMsg(addPeerMsg)
		// 	}
		// } else if addPeerMsg.Flag == p2p.CurrentLevelOrdinaryPeer {
		// 	if peer.peerFlag == p2p.CurrentLevelPeer || peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
		// 		//=> only broadcast addPeerMsg to currentLevelPeer and CurrentLevelOrdinaryPeer --Agzs
		// 		peer.SendAddPeerMsg(addPeerMsg)
		// 	}
		// }
	}

	log.Trace("Broadcast addPeersMsg", "hash", hash, "recipients", len(pm.peers.peers)) //=> peers ->  pm.peers.peers --Agzs
}

// BroadcastRemovePeers will propagate a removePeerMsg to all peers which are not known to
// already have the given removePeerMsg.
//=>--Agzs 11.15
func (pm *ProtocolManager) BroadcastRemovePeers(removePeerMsg *node.URLFlag) {
	log.Info("pm.BroadcastRemovePeers() start------------") //=>test. --Agzs
	//=> add PeerWithoutMsg() start. --Agzs

	hash := types.Hash(removePeerMsg)
	peers := pm.peers.PeersWithoutRemovePeerMsg(hash)

	for _, peer := range peers {
		log.Info("peer broadcast removePeerMsg", "peer", peer.id, "send msg's hash:", hash) //=>test. --Agzs
		// receive LowLevelPeer's enode, just broadcast msg to current level peer. --Agzs
		// receive CurrentLevelPeer's enode, roadcast msg to all level peer. --Agzs
		// receive UpperLevelPeer's enode, just broadcast msg to current level peer. --Agzs
		// receive CurrentLevelOrdinaryPeer's enode, just broadcast msg to currentLevelPeer and CurrentLevelOrdinaryPeer. --Agzs

		if removePeerMsg.Flag == p2p.UpperLevelPeer { //=>addPeerMsg means adding a upper level peer --Agzs
			if peer.peerFlag == p2p.CurrentLevelPeer { //=> only broadcast addPeerMsg to current level peer --Agzs
				peer.SendRemovePeerMsg(removePeerMsg)
			}
		} else if removePeerMsg.Flag == p2p.CurrentLevelPeer { //=>addPeerMsg means adding a current level peer --Agzs
			if peer.peerFlag == p2p.LowLevelPeer {
				//=>From this peer, currentLevePeer is it's parent, change Flag to UpperLevelPeer and broadcast msg. --Agzs
				peer.SendRemovePeerMsg(&node.URLFlag{Enode: removePeerMsg.Enode, Flag: p2p.UpperLevelPeer})
			} else if peer.peerFlag == p2p.CurrentLevelPeer {
				//=>From this peer, currentLevePeer is it's brother, just broadcast msg. --Agzs
				peer.SendRemovePeerMsg(removePeerMsg)
			} else if peer.peerFlag == p2p.UpperLevelPeer {
				//=>From this peer, currentLevePeer is child, change Flag LowLevelPeer to and broadcast msg. --Agzs
				peer.SendRemovePeerMsg(&node.URLFlag{Enode: removePeerMsg.Enode, Flag: p2p.LowLevelPeer})
			} else if peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
				peer.SendRemovePeerMsg(&node.URLFlag{Enode: removePeerMsg.Enode, Flag: p2p.CurrentLevelOrdinaryPeer})
			}
		} else if removePeerMsg.Flag == p2p.LowLevelPeer { //=>addPeerMsg means adding a low level peer --Agzs
			if peer.peerFlag == p2p.CurrentLevelPeer { //=> only broadcast addPeerMsg to current level peer --Agzs
				peer.SendRemovePeerMsg(removePeerMsg)
			}
		} else if removePeerMsg.Flag == p2p.CurrentLevelOrdinaryPeer {
			if peer.peerFlag == p2p.CurrentLevelPeer || peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
				//=> only broadcast addPeerMsg to currentLevelPeer and CurrentLevelOrdinaryPeer --Agzs
				peer.SendRemovePeerMsg(removePeerMsg)
			}
		} else if removePeerMsg.Flag == p2p.CurrentLevelOrdinaryPeer {
			if peer.peerFlag == p2p.CurrentLevelPeer || peer.peerFlag == p2p.CurrentLevelOrdinaryPeer {
				//=> only broadcast addPeerMsg to currentLevelPeer and CurrentLevelOrdinaryPeer --Agzs
				peer.SendRemovePeerMsg(removePeerMsg)
			}
		}
	}

	log.Trace("Broadcast removePeersMsg", "hash", hash, "recipients", len(pm.peers.peers)) //=> peers ->  pm.peers.peers --Agzs
}

//////////////////////////////////////////////////////

func (self *ProtocolManager) txBroadcastLoop() {
	// automatically stops if unsubscribe
	for obj := range self.txSub.Chan() {
		//fmt.Printf("--------txBroadcastLoop") ////xiaobei 1.10
		event := obj.Data.(core.TxPreEvent)
		self.BroadcastTx(event.Tx.Hash(), event.Tx)
	}
}

func (self *ProtocolManager) headerTxLoop() {
	// automatically stops if unsubscribe
	for obj := range self.headerTxSub.Chan() {
		event := obj.Data.(core.HeaderTxEvent)
		hash := types.HashTxCommon(event.Tx)
		self.headerTxLock.Lock()
		//	var txs []*types.Transaction
		if _, ok := self.headers[hash]; !ok {
			self.headers[hash] = make([]*types.HeaderTx, 0)
		}
		if _, ok := self.headersMark[event.Tx.Hash()]; !ok {
			self.headersMark[event.Tx.Hash()] = struct{}{}
			headerTx := &types.HeaderTx{Tx: event.Tx, Index: node.NodeIndex}
			self.headers[hash] = append(self.headers[hash], headerTx)
		}
		self.headerTxLock.Unlock()
		if uint32(len(self.headers[hash])) >= node.Mn.M {
			self.headerTxChan <- hash
		}

		self.RequestHeaderTxWithPartSig(event.Tx.Hash(), event.Tx)
	}
}

// EthNodeInfo represents a short summary of the Ethereum sub-protocol metadata known
// about the host peer.
type EthNodeInfo struct {
	Network      uint64      `json:"network"`    // Ethereum network ID (1=Frontier, 2=Morden, Ropsten=3)
	BlockchainId uint64      `json:blockchainid` // Ethereum blockchainID //=> --Agzs 12.25
	Difficulty   *big.Int    `json:"difficulty"` // Total difficulty of the host's blockchain
	Genesis      common.Hash `json:"genesis"`    // SHA3 hash of the host's genesis block
	Head         common.Hash `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (self *ProtocolManager) NodeInfo() *EthNodeInfo {
	currentBlock := self.blockchain.CurrentBlock()
	return &EthNodeInfo{
		Network:      self.networkId,
		BlockchainId: self.blockchainId, //=> --Agzs 12.25
		Difficulty:   self.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64()),
		Genesis:      self.blockchain.Genesis().Hash(),
		Head:         currentBlock.Hash(),
	}
}

/////======================================>xiaobei 1.17

// insert spawns a new goroutine to run a block insertion into the chain. If the
// block's number is at the same height as the current import phase, if updates
// the phase states accordingly.
func (pm *ProtocolManager) Insert(block *types.Block) {
	log.Info("--------pm insert is called!")
	hash := block.Hash()

	// Run the import on a new thread
	log.Debug("Importing propagated block", "number", block.Number(), "hash", hash)
	go func() {
		defer func() { pm.fetcher.Done <- hash }()

		// If the parent's unknown, abort insertion
		parent := pm.fetcher.GetBlock(block.ParentHash())
		if parent == nil {
			fmt.Println("Unknown parent of propagated block", "number", block.Number(), "hash", hash, "parent", block.ParentHash())
			log.Debug("Unknown parent of propagated block", "number", block.Number(), "hash", hash, "parent", block.ParentHash())
			return
		}
		// Quickly validate the header and propagate the block if it passes
		switch err := pm.fetcher.VerifyHeader(block.Header()); err {
		case nil:
			// All ok, quickly propagate to our peers
			fetcher.PropBroadcastOutTimer.UpdateSince(block.ReceivedAt)
			go pm.fetcher.BroadcastBlock(block, true)

		case consensus.ErrFutureBlock:
			fmt.Println("errfuture")
			// Weird future block, don't fail, but neither propagate

		default:
			// Something went very wrong, drop the peer
			fmt.Println("Propagated block verification failed", "number", block.Number(), "hash", hash, "err", err)
			log.Debug("Propagated block verification failed", "number", block.Number(), "hash", hash, "err", err)
			//f.dropPeer(peer)
			return
		}
		fetcher.FetcherFlag = true ////xiaobei 1.18
		// Run the actual import and log any issues

		if node.ResultFile != nil {
			wt := bufio.NewWriter(node.ResultFile)
			str := fmt.Sprintf(" block %d  before write is :%v:\n", block.Number(), time.Now())
			_, err := wt.WriteString(str)
			if err != nil {
				log.Error("write error")
			}
			wt.Flush()
		}
		if _, err := pm.fetcher.InsertChain(types.Blocks{block}); err != nil {
			fmt.Println("Propagated block import failed", "number", block.Number(), "hash", hash, "err", err)
			log.Debug("Propagated block import failed", "number", block.Number(), "hash", hash, "err", err)
			return
		}
		if node.ResultFile != nil {
			wt := bufio.NewWriter(node.ResultFile)
			str := fmt.Sprintf(" block %d  written time is :%v:\n", block.Number(), time.Now())
			_, err := wt.WriteString(str)
			if err != nil {
				log.Error("write error")
			}
			wt.Flush()
		}

		// If import succeeded, broadcast the block
		fetcher.PropAnnounceOutTimer.UpdateSince(block.ReceivedAt)
		go pm.BroadcastBlock(block, false)

	}()
}

func (pm *ProtocolManager) GetCommittedBlock() {
	log.Info("protocolManager get CommittedBlock!")
	if node.ResultFile == nil {
		filename := fmt.Sprintf("result%d", node.NodeIndex)
		var err error
		node.ResultFile, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fmt.Println("Open file error")
		}
	}

	for block := range pm.RecvBlockChan {
		log.Info("----protocolManager get block from RecvBlockChan!")
		if node.ResultFile != nil {
			wt := bufio.NewWriter(node.ResultFile)
			str := fmt.Sprintf(" block %d  consensus confirm time is :%v:\n", block.Number(), time.Now())
			_, err := wt.WriteString(str)
			if err != nil {
				log.Error("write error")
			}
			wt.Flush()
		}
		pm.Insert(block)
	}
}
func Good() bool {
	return true
}

////===========================>
