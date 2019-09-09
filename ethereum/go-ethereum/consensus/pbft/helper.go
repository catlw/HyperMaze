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

//=>add this file for viewchange, since this file contain pset and qset. --Agzs
*/

package pbft

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/consensus/util/events"
	"github.com/ethereum/go-ethereum/core" //=> for Ethereum --Agzs
	"github.com/ethereum/go-ethereum/core/types"
)

//=>TODO. --Agzs
type Helper struct {
	// consenter    consensus.Consenter
	// coordinator  peer.MessageHandlerCoordinator
	// secOn        bool
	valid   bool           // Whether we believe the state is up to date
	manager events.Manager //=> helper.manager == pbft.manager == protocolManager.pbftManager
	// secHelper    crypto.Peer
	// curBatch     []*pb.Transaction       // TODO, remove after issue 579
	// curBatchErrs []*pb.TransactionResult // TODO, remove after issue 579
	databaseHelper //=> replaced persist.Helper --Agzs

	blockchainHelper *core.BlockChain //=> add ethHelper for get blockchain info --Agzs

	//executor *CoordinatorImpl ////xiaobei 1.8
}

//=> init Helper
func NewHelper() *Helper {
	h := &Helper{
		valid: true, //Assume our state is consistent util we are told otherwise, actual consensus(pbft) will invalidate this immediately
		//=> manager: events.NewManagerImpl(),
		//=> manager inited in pbft.go New() --Agzs
		//=> blockchainHelper inited in eth/backend.go New() --Agzs
		//executor: NewImpl(), ////xiaobei 1.8
	}
	//h.executor.Start() ////xiaobei 1.8
	return h
}

//=> rewrite InvalidateState(). --Agzs
//=> instance.consumer.invalidateState()==obcGeneric.invalidateState() >> op.stack.InvalidateState()==Helper.InvalidateState() --Agzs
func (helper *Helper) InvalidateState() {
	logger.Debug("Invalidating the current state")
	helper.valid = false
}

//=> rewrite ValidateState(). --Agzs
func (helper *Helper) ValidateState() {
	logger.Debug("Validating the current state")
	helper.valid = true
}

//=> called by instance.retryStateTransfer(). --Agzs
//=> instance.cosumer.skipTo()==obcGeneric.skipTo(). --Agzs
func (helper *Helper) skipTo(seqNo uint64, id []byte, replicas []uint64) {
	info := &types.BlockchainInfo{}
	err := json.Unmarshal(id, info)
	if err != nil {
		logger.Error(fmt.Sprintf("Error unmarshaling: %s", err))
		return
	}
	//logger.Infof("-----skipto is called") ////xiaobei 1.5
	helper.UpdateState(&checkpointMessage{seqNo, id}, info, getValidatorHandles(replicas))
}

//=>TODO. copy from fabric. --Agzs
// UpdateState attempts to synchronize state to a particular target, implicitly calls rollback if needed
func (helper *Helper) UpdateState(tag interface{}, target *types.BlockchainInfo, peers []*types.PeerID) {
	//logger.Infof("-----updateState is called") ////xiaobei 1.5
	if helper.valid {
		logger.Warning("State transfer is being called for, but the state has not been invalidated")
	}
	//events.ManagerImpl.Queue() <- stateUpdateEvent{tag, target, peers}
	events.SendEvent(PBFTCore, stateUpdateEvent{tag, target, peers}) ////xiaobei 1.8
}

// StateUpdated is a signal from the stack that it has fast-forwarded its state
////copy from fabric.--xiaobei
func (helper *Helper) StateUpdated(tag interface{}, target *types.BlockchainInfo) {
	events.ManagerImpl.Queue() <- stateUpdatedEvent{
		chkpt:  tag.(*checkpointMessage),
		target: target,
	} ////xiaobei --1.2
	// events.SendEvent(PBFTCore, stateUpdatedEvent{
	// 	chkpt:  tag.(*checkpointMessage),
	// 	target: target,
	// }) ////xiaobei --12.18
}

//=>copy from fabric. --Agzs
// Returns the peer handle that corresponds to a validator ID (uint64 assigned to it for PBFT)
func getValidatorHandle(id uint64) (handle *types.PeerID, err error) {
	// as requested here: https://github.com/hyperledger/fabric/issues/462#issuecomment-170785410
	name := "vp" + strconv.FormatUint(id, 10)
	//logger.Infof("------name is %s", name) /////xiaobei 1.5
	return &types.PeerID{Name: name}, nil
}

//=>copy from fabric. --Agzs
// Returns the peer handles corresponding to a list of replica ids
func getValidatorHandles(ids []uint64) (handles []*types.PeerID) {
	//logger.Infof("------getValidatorHandles is called") ////xiaobei 1.5
	handles = make([]*types.PeerID, len(ids))
	for i, id := range ids {
		handles[i], _ = getValidatorHandle(id)
	}
	return
}

//=>rewrite getState() for ethereum.Blockchain. --Agzs
func (helper *Helper) getState() []byte {
	//get BlockchainInfo
	// ledger, _ := ledger.GetLedger() //=>?
	// info, _ := ledger.GetBlockchainInfo()
	// rawInfo, _ := proto.Marshal(info)
	info, _ := helper.blockchainHelper.GetBlockchainInfo()
	rawInfo, _ := json.Marshal(info)

	return rawInfo
}
