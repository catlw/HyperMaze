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

package pbft

import (
	"github.com/ethereum/go-ethereum/core/types"
)

// --------------------------------------------------------------
//
// external contains all of the functions which
// are intended to be called from outside of the pbft package
//
// --------------------------------------------------------------

//=>TODO. --Agzs

// Event types
type stateUpdateEvent struct {
	tag            interface{}
	BlockchainInfo *types.BlockchainInfo
	peers          []*types.PeerID
}

// stateUpdatedEvent is sent when state transfer completes
type stateUpdatedEvent struct {
	chkpt  *checkpointMessage
	target *types.BlockchainInfo
}

// ////===========================>xiaobei 1.8
// type CoordinatorImpl struct {
// 	manager events.Manager // Maintains event thread and sends events to the coordinator
// }

// var Coor *CoordinatorImpl

// // NewCoordinatorImpl creates a new executor.Coordinator
// func NewImpl() *CoordinatorImpl {
// 	logger.Infof("-----CoordinatorImpl is called") ////xiaobei 1.8
// 	Coor = &CoordinatorImpl{
// 		manager: events.NewManagerImpl(),
// 	}
// 	Coor.manager.SetReceiver(Coor)
// 	return Coor
// }

// // ProcessEvent is the main event loop for the executor.Coordinator
// func (co *CoordinatorImpl) ProcessEvent(event events.Event) events.Event {
// 	switch et := event.(type) {
// 	case stateUpdateEvent:
// 		logger.Debug("Executor is processing a stateUpdateEvent")
// 	default:
// 		logger.Errorf("Unknown event type %s", et)
// 	}
// 	return nil
// }

// // UpdateState uses the state transfer subsystem to attempt to progress to a target
// func (co *CoordinatorImpl) UpdateState(tag interface{}, target *types.BlockchainInfo, peers []*types.PeerID) {
// 	logger.Infof("-----(co *CoordinatorImpl) UpdateState is called") ////xiaobei 1.8
// 	co.manager.Queue() <- stateUpdateEvent{tag, target, peers}
// }

// // Start must be called before utilizing the Coordinator
// func (co *CoordinatorImpl) Start() {
// 	co.manager.Start()
// }

// // Halt should be called to clean up resources allocated by the Coordinator
// func (co *CoordinatorImpl) Halt() {
// 	co.manager.Halt()
// }

// ////===========================>xiaobei 1.8
