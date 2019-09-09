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
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/consensus/util/events"
	"github.com/ethereum/go-ethereum/core/types"
)

// viewChangeQuorumEvent is returned to the event loop when a new ViewChange message is received which is part of a quorum cert
type viewChangeQuorumEvent struct{}

var flag = false ////using for recvViewchange. xiaobei 11.9

func (instance *pbftCore) correctViewChange(vc *types.ViewChange) bool {
	for _, p := range append(vc.Pset, vc.Qset...) {
		if !(p.View < vc.View && p.SequenceNumber > vc.H && p.SequenceNumber <= vc.H+instance.L) {
			logger.Debugf("Replica %d invalid p entry in view-change: vc(v:%d h:%d) p(v:%d n:%d)",
				instance.id, vc.View, vc.H, p.View, p.SequenceNumber)
			return false
		}
	}

	for _, c := range vc.Cset {
		// PBFT: the paper says c.n > vc.h
		if !(c.SequenceNumber >= vc.H && c.SequenceNumber <= vc.H+instance.L) {
			logger.Debugf("Replica %d invalid c entry in view-change: vc(v:%d h:%d) c(n:%d)",
				instance.id, vc.View, vc.H, c.SequenceNumber)
			return false
		}
	}

	return true
}

func (instance *pbftCore) calcPSet() map[uint64]*types.ViewChange_PQ {
	pset := make(map[uint64]*types.ViewChange_PQ)

	for n, p := range instance.pset {
		pset[n] = p
	}

	// P set: requests that have prepared here
	//
	// "<n,d,v> has a prepared certificate, and no request
	// prepared in a later view with the same number"

	for idx, cert := range instance.certStore {
		if cert.prePrepare == nil {
			continue
		}

		digest := common.StringToHash(cert.digest) ////change from cert.digest. --xiaobei 11.21
		if !instance.prepared(cert.digest, idx.v, idx.n) {
			continue
		}

		if p, ok := pset[idx.n]; ok && p.View > idx.v {
			continue
		}

		pset[idx.n] = &types.ViewChange_PQ{
			SequenceNumber: idx.n,
			BlockHash:      digest,
			View:           idx.v,
		}
		//logger.Infof("calcPSet(),digest is %x", digest) ////test--xiaobei 11.20
	}

	return pset
}

func (instance *pbftCore) calcQSet() map[qidx]*types.ViewChange_PQ {
	qset := make(map[qidx]*types.ViewChange_PQ)

	for n, q := range instance.qset {
		qset[n] = q
	}

	// Q set: requests that have pre-prepared here (pre-prepare or
	// prepare sent)
	//
	// "<n,d,v>: requests that pre-prepared here, and did not
	// pre-prepare in a later view with the same number"

	for idx, cert := range instance.certStore {
		if cert.prePrepare == nil {
			continue
		}

		digest := common.StringToHash(cert.digest) ////change from cert.digest. --xiaobei 11.21
		if !instance.prePrepared(cert.digest, idx.v, idx.n) {
			continue
		}

		qi := qidx{cert.digest, idx.n}
		if q, ok := qset[qi]; ok && q.View > idx.v {
			continue
		}

		qset[qi] = &types.ViewChange_PQ{
			SequenceNumber: idx.n,
			BlockHash:      digest,
			View:           idx.v,
		}
		//logger.Infof("calcQSet(),digest is %x", digest) ////test--xiaobei 11.20
	}

	return qset
}

func (instance *pbftCore) sendViewChange() events.Event {
	////xiaobei 1.21
	SendViewChangeFlag = true
	////
	instance.stopTimer()

	delete(instance.newViewStore, instance.view)
	instance.view++
	instance.activeView = false

	instance.pset = instance.calcPSet()
	instance.qset = instance.calcQSet()

	// clear old messages
	for idx := range instance.certStore {
		if idx.v < instance.view {
			delete(instance.certStore, idx)
		}
	}
	for idx := range instance.viewChangeStore {
		if idx.v < instance.view {
			delete(instance.viewChangeStore, idx)
		}
	}

	vc := &types.ViewChange{
		View:      instance.view,
		H:         instance.h,
		ReplicaId: instance.id,
	}

	for n, id := range instance.chkpts {
		vc.Cset = append(vc.Cset, &types.ViewChange_C{
			SequenceNumber: n,
			Id:             id,
		})
	}

	for _, p := range instance.pset {
		if p.SequenceNumber < instance.h {
			logger.Errorf("BUG! Replica %d should not have anything in our pset less than h, found %+v", instance.id, p)
		}
		vc.Pset = append(vc.Pset, p)
	}

	for _, q := range instance.qset {
		if q.SequenceNumber < instance.h {
			logger.Errorf("BUG! Replica %d should not have anything in our qset less than h, found %+v", instance.id, q)
		}
		vc.Qset = append(vc.Qset, q)
	}

	//=> instance.sign(vc)
	//=> sign for viewchange.  start --Agzs
	// if instance.primary(instance.view-1) == instance.id { //=> Primary node in previous view cannot sign --Agzs
	// 	// Not primary, cannot initiate PBFT protocol and seal block.
	// 	return nil
	// }////--xiaobei 11.7

	signer, signFn := instance.signer, instance.signFn
	vc.Signer = signer

	if signFn == nil {
		logger.Info("SignFn is nil piont========")
	}
	
	vc.Signature, _ = signFn(accounts.Account{Address: signer}, sigHash(nil, vc).Bytes())
	//=> sign for viewchange.  end --Agzs

	logger.Infof("Replica %d sending view-change, v:%d, h:%d, |C|:%d, |P|:%d, |Q|:%d",
		instance.id, vc.View, vc.H, len(vc.Cset), len(vc.Pset), len(vc.Qset))

	///instance.innerBroadcast(&Message{Payload: &Message_ViewChange{ViewChange: vc}})
	//=>instance.commChan <- &types.PbftMessage{Payload: &types.PbftMessage_ViewChange{ViewChange: vc}} --Agzs
	msg := types.PbftMessage{
		// PrePrepare: nil,
		// Prepare:    nil,
		// Commit:     nil,
		// Checkpoint: nil,
		// ViewChange: vc,
		// NewView:    nil,
		//FetchBlockMsg: nil,
		Sender:      instance.id,
		PayloadCode: types.ViewChangeMsg,
		Payload:     vc,
	}
	//instance.innerBroadcast(&msg) //=> --Agzs
	err := instance.innerBroadcast(&msg)
	if err != nil { ////test--xiaobei 11.7
		logger.Warningf("Replica %d send view change meet err,err is %s", instance.id, err)
	} else {
		logger.Infof("Replica %d send view change successed!", instance.id)
	}

	instance.vcResendTimer.Reset(instance.vcResendTimeout, viewChangeResendTimerEvent{})

	return instance.recvViewChange(vc)
}

func (instance *pbftCore) recvViewChange(vc *types.ViewChange) events.Event {
	logger.Infof("Replica %d received view-change from replica %d, v:%d, h:%d, |C|:%d, |P|:%d, |Q|:%d",
		instance.id, vc.ReplicaId, vc.View, vc.H, len(vc.Cset), len(vc.Pset), len(vc.Qset))

	//=> overwrite verify(), change it to verifyViewChangeSig(vc) --Agzs
	// if err := instance.verify(vc); err != nil {
	// 	logger.Warningf("Replica %d found incorrect signature in view-change message: %s", instance.id, err)
	// 	return nil
	// }
	//=>be proved. verify viewchange signature. start --Agzs
	equalSignerFlag, err := instance.verifyViewChangeSig(vc)
	if !equalSignerFlag || err != nil {
		logger.Warningf("Replica %d found incorrect signature in view-change message: %s", instance.id, err)
		return nil
	}
	//=> verify viewchange signature. end --Agzs

	if vc.View < instance.view {
		logger.Warningf("Replica %d found view-change message for old view", instance.id)
		return nil
	}

	if !instance.correctViewChange(vc) {
		logger.Warningf("Replica %d found view-change message incorrect", instance.id)
		return nil
	}

	if _, ok := instance.viewChangeStore[vcidx{vc.View, vc.ReplicaId}]; ok {
		logger.Warningf("Replica %d already has a view change message for view %d from replica %d", instance.id, vc.View, vc.ReplicaId)
		/////////
		////--xiaobei 11.9
		if !flag && instance.nullRequestTimeout > 0 {
			timeout := instance.nullRequestTimeout
			if instance.primary(instance.view) != instance.id {
				// we're waiting for the primary to deliver a null request - give it a bit more time
				timeout += instance.requestTimeout
			}
			instance.nullRequestTimer.Reset(timeout, nullRequestEvent{})
			flag = true
		}
		/////////
		return nil
	}

	instance.viewChangeStore[vcidx{vc.View, vc.ReplicaId}] = vc

	// PBFT TOCS 4.5.1 Liveness: "if a replica receives a set of
	// f+1 valid VIEW-CHANGE messages from other replicas for
	// views greater than its current view, it sends a VIEW-CHANGE
	// message for the smallest view in the set, even if its timer
	// has not expired"
	replicas := make(map[uint64]bool)
	minView := uint64(0)
	for idx := range instance.viewChangeStore {
		if idx.v <= instance.view {
			continue
		}

		replicas[idx.id] = true
		if minView == 0 || idx.v < minView {
			minView = idx.v
		}
	}

	// We only enter this if there are enough view change messages _greater_ than our current view
	if len(replicas) >= instance.f+1 {
		logger.Infof("Replica %d received f+1 view-change messages, triggering view-change to view %d",
			instance.id, minView)
		// subtract one, because sendViewChange() increments
		instance.view = minView - 1
		return instance.sendViewChange()
	}

	quorum := 0
	for idx := range instance.viewChangeStore {
		if idx.v == instance.view {
			quorum++
		}
	}
	logger.Debugf("Replica %d now has %d view change requests for view %d", instance.id, quorum, instance.view)

	if !instance.activeView && vc.View == instance.view && quorum >= instance.allCorrectReplicasQuorum() {
		instance.vcResendTimer.Stop()
		instance.startTimer(instance.lastNewViewTimeout, "new view change")
		instance.lastNewViewTimeout = 2 * instance.lastNewViewTimeout
		return viewChangeQuorumEvent{}
	}

	return nil
}

func ConvertMapToStruct(msgList map[uint64]string) []*types.XSet {
	//var xset []*types.XSet
	xset := make([]*types.XSet, len(msgList)) ////xiaobei 11.9

	i := 0

	for id, hash := range msgList {
		xset[i] = &types.XSet{Seq: id, Hash: hash}
		i++
	}

	//logger.Debugf("xset is %+v", xset) ////test--xiaobei 11.20
	return xset
}

func (instance *pbftCore) sendNewView() events.Event {

	if _, ok := instance.newViewStore[instance.view]; ok {
		logger.Debugf("Replica %d already has new view in store for view %d, skipping", instance.id, instance.view)
		return nil
	}

	vset := instance.getViewChanges()  //=> vset <=> instance.viewChangeStore --Agzs
	logger.Debugf("vset is %+v", vset) ////test--xiaobei 11.20
	cp, ok, _ := instance.selectInitialCheckpoint(vset)
	if !ok {
		logger.Infof("Replica %d could not find consistent checkpoint: %+v", instance.id, instance.viewChangeStore)
		return nil
	}
	//logger.Infof("---sendNewView() assignSequenceNumbers() is called")                                   ////--xiaobei 11.13
	msgList := instance.assignSequenceNumbers(vset, cp.SequenceNumber) //=> msgList == (seqNo, blockHash) --Agzs
	//logger.Infof("---sendNewView() msgList:{nv.vset:%+v,cp.sequenceNumber:%d}", vset, cp.SequenceNumber) ////--xiaobei 11.13

	if msgList == nil {
		logger.Infof("Replica %d could not assign sequence numbers for new view", instance.id)
		return nil
	}

	//logger.Debugf("msglist is %+v", msgList)
	// for key, val := range msgList { ////--xiaobei
	// 	fmt.Printf("map[%d]=%x ", key, val)
	// }
	// logger.Debugf("msgList lenth is %d", len(msgList))
	nv := &types.NewView{
		View:      instance.view,
		Vset:      vset,
		Xset:      ConvertMapToStruct(msgList), //Xset:      msgList,
		ReplicaId: instance.id,
	}
    
	logger.Infof("Replica %d is new primary, sending new-view, v:%d, X:%+v",
		instance.id, nv.View, nv.Xset)
	//logger.Infof("send new-view, v:%d, X:%+v", nv.View, nv.Xset) ////--xiaobei 11.13
	//logger.Infof("sendNewView() msglist is %+v", nv.Xset)        ////--xiaobei 11.14
	// for key, value := range msgList { ////--xiaobei 11.14
	// 	logger.Infof("sendNewView msgList[%d]=%x", key, value)
	// }
	for key2, value2 := range nv.Xset { ////--xiaobei 11.14
		logger.Infof("sendNewView xset[%d]={Seq:%d,Hash:%x}", key2, value2.Seq, value2.Hash)
	}
	msg := types.PbftMessage{
		// PrePrepare: nil,
		// Prepare:    nil,
		// Commit:     nil,
		// Checkpoint: nil,
		// ViewChange: nil,
		// NewView:    nv,
		//FetchBlockMsg: nil,
		Sender:      instance.id,
		PayloadCode: types.NewViewMsg,
		Payload:     nv,
	} //=> --Agzs
	instance.innerBroadcast(&msg)

	instance.newViewStore[instance.view] = nv
	return instance.processNewView()
}

func (instance *pbftCore) recvNewView(nv *types.NewView) events.Event {
	logger.Infof("Replica %d received new-view %d",
		instance.id, nv.View)

	if !(nv.View > 0 && nv.View >= instance.view && instance.primary(nv.View) == nv.ReplicaId && instance.newViewStore[nv.View] == nil) {
		logger.Infof("Replica %d rejecting invalid new-view from %d, v:%d",
			instance.id, nv.ReplicaId, nv.View)
		return nil
	}
	// logger.Infof("---recvNewView() msgList:{nv.vset:%+v}", nv.Vset) ////test--xiaobei 11.13
	// logger.Infof("receive new-view, v:%d, X:%+v", nv.View, nv.Xset) ////--xiaobei 11.13
	for _, vc := range nv.Vset {
		// if err := instance.verify(vc); err != nil {
		// 	logger.Warningf("Replica %d found incorrect view-change signature in new-view message: %s", instance.id, err)
		// 	return nil
		// }
		//=>TODO can't be prove. verify viewchange signature. start --Agzs
		equalSignerFlag, err := instance.verifyViewChangeSig(vc)
		if !equalSignerFlag || err != nil {
			logger.Warningf("Replica %d found incorrect view-change signature in new-view message: %s", instance.id, err)
			return nil
		}
		//=> verify viewchange signature. end --Agzs
	}

	instance.newViewStore[nv.View] = nv
	return instance.processNewView()
}

func (instance *pbftCore) processNewView() events.Event {
	var newReqBatchMissing bool
	nv, ok := instance.newViewStore[instance.view]
	if !ok {
		logger.Debugf("Replica %d ignoring processNewView as it could not find view %d in its newViewStore", instance.id, instance.view)
		return nil
	}

	if instance.activeView {
		logger.Infof("Replica %d ignoring new-view from %d, v:%d: we are active in view %d",
			instance.id, nv.ReplicaId, nv.View, instance.view)
		return nil
	}

	cp, ok, replicas := instance.selectInitialCheckpoint(nv.Vset)
	if !ok {
		logger.Warningf("Replica %d could not determine initial checkpoint: %+v",
			instance.id, instance.viewChangeStore)
		return instance.sendViewChange()
	}

	speculativeLastExec := *instance.LastExec
	if instance.currentExec != nil {
		speculativeLastExec = *instance.currentExec
	}

	// If we have not reached the sequence number, check to see if we can reach it without state transfer
	// In general, executions are better than state transfer
	if speculativeLastExec < cp.SequenceNumber {
		canExecuteToTarget := true
	outer:
		for seqNo := speculativeLastExec + 1; seqNo <= cp.SequenceNumber; seqNo++ {
			found := false
			for idx, cert := range instance.certStore {
				if idx.n != seqNo {
					continue
				}

				quorum := 0
				for _, p := range cert.commit {
					// Was this committed in the previous view
					if p.View == idx.v && p.SequenceNumber == seqNo {
						quorum++
					}
				}

				if quorum < instance.intersectionQuorum() {
					logger.Debugf("Replica %d missing quorum of commit certificate for seqNo=%d, only has %d of %d", instance.id, quorum, instance.intersectionQuorum())
					continue
				}

				found = true
				break
			}

			if !found {
				canExecuteToTarget = false
				logger.Debugf("Replica %d missing commit certificate for seqNo=%d", instance.id, seqNo)
				break outer
			}

		}

		if canExecuteToTarget {
			logger.Debugf("Replica %d needs to process a new view, but can execute to the checkpoint seqNo %d, delaying processing of new view", instance.id, cp.SequenceNumber)
			return nil
		}

		logger.Infof("Replica %d cannot execute to the view change checkpoint with seqNo %d", instance.id, cp.SequenceNumber)
	}
	//logger.Infof("---processNewView() assignSequenceNumbers() is called") ////--xiaobei 11.13
	msgList := instance.assignSequenceNumbers(nv.Vset, cp.SequenceNumber)
	//logger.Infof("---processNewView() msgList:{nv.vset:%+v,cp.sequenceNumber:%d}", nv.Vset, cp.SequenceNumber) ////--xiaobei 11.13

	if msgList == nil {
		logger.Warningf("Replica %d could not assign sequence numbers: %+v",
			instance.id, instance.viewChangeStore)
		return instance.sendViewChange()
	}
	msglist := ConvertMapToStruct(msgList) ////--xiaobei 11.9
	//logger.Infof("processNewView() msglist is %+v", msglist) ////--xiaobei 11.14
	// for key, value := range msgList { ////--xiaobei 11.14
	// 	logger.Infof("processNewView msgList[%d]=%x", key, value)
	// }

	//////////////--xiaobei 11.14
	l := len(msgList)
	msglist2 := make([]*types.XSet, l)
	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			if nv.Xset[i].Seq == msglist[j].Seq {
				msglist2[i] = msglist[j]
				break
			}
		}
	}
	//////////////

	if !(len(msgList) == 0 && len(nv.Xset) == 0) && !reflect.DeepEqual(msglist2, nv.Xset) {
		logger.Warningf("Replica %d failed to verify new-view Xset: computed %+v, received %+v",
			instance.id, msglist, nv.Xset)
		return instance.sendViewChange()
	}

	if instance.h < cp.SequenceNumber {
		instance.moveWatermarks(cp.SequenceNumber)
	}

	if speculativeLastExec < cp.SequenceNumber {
		logger.Warningf("Replica %d missing base checkpoint %d (%s), our most recent execution %d", instance.id, cp.SequenceNumber, cp.Id, speculativeLastExec)

		snapshotID, err := base64.StdEncoding.DecodeString(cp.Id)
		if nil != err {
			err = fmt.Errorf("Replica %d received a view change whose hash could not be decoded (%s)", instance.id, cp.Id)
			logger.Error(err.Error())
			return nil
		}

		target := &stateUpdateTarget{
			checkpointMessage: checkpointMessage{
				seqNo: cp.SequenceNumber,
				id:    snapshotID,
			},
			replicas: replicas,
		}

		instance.updateHighStateTarget(target)
		instance.stateTransfer(target)
	}
	// for key2, value2 := range msglist2 { ////--xiaobei 11.14
	// 	logger.Infof("processNewView xset[%d]={Seq:%d,Hash:%x}", key2, value2.Seq, value2.Hash)
	// }
	for _, xset := range nv.Xset {
		n, d := xset.Seq, xset.Hash
		// PBFT: why should we use "h ≥ min{n | ∃d : (<n,d> ∈ X)}"?
		// "h ≥ min{n | ∃d : (<n,d> ∈ X)} ∧ ∀<n,d> ∈ X : (n ≤ h ∨ ∃m ∈ in : (D(m) = d))"
		if n <= instance.h {
			continue
		} else {
			if d == "" {
				// NULL request; skip
				continue
			}
			if _, ok := instance.blockStore[d]; !ok { //=> reqBatchStore -> blockStore --Agzs
				logger.Warningf("Replica %d missing assigned, non-checkpointed block %x",
					instance.id, d)
				fmt.Println("ok is", ok)
				if _, ok := instance.missingReqBatches[d]; !ok {
					logger.Warningf("Replica %v requesting to fetch block %x",
						instance.id, d)
					newReqBatchMissing = true
					instance.missingReqBatches[d] = true
				}
			}
		}
	}

	if len(instance.missingReqBatches) == 0 {
		return instance.processNewView2(nv)
	} else if newReqBatchMissing {
		logger.Warningf("Replica %v miss requesting to fetch blocks", instance.id)
		//=>instance.fetchBlockMsges() --Agzs
	}

	return nil
}

func (instance *pbftCore) processNewView2(nv *types.NewView) events.Event {
	logger.Infof("Replica %d accepting new-view to view %d", instance.id, instance.view)

	instance.stopTimer()
	instance.nullRequestTimer.Stop()

	instance.activeView = true
	delete(instance.newViewStore, instance.view-1)

	instance.seqNo = instance.h
	//for n, d := range nv.Xset {
	for _, xset := range nv.Xset {
		n, d := xset.Seq, xset.Hash
		if n <= instance.h {
			continue
		}
		////xiaobei --1.29
        if d == "" {
			logger.Info("------block digest is nil")
			continue
		}
		////
		block, ok := instance.blockStore[d] //=> change reqBatch to block --Agzs
		if !ok{
			logger.Info("------get block from blockStore fail!")
		}
		
		if !ok && d != "" {
			logger.Criticalf("Replica %d is missing request batch for seqNo=%d with digest '%s' for assigned prepare after fetching, this indicates a serious bug", instance.id, n, d)
		}
		preprep := &types.PrePrepare{ //=> add types --Agzs
			View:           instance.view,
			SequenceNumber: n,
			BlockHash:      block.Hash().Bytes(), //=> BatchDigest -> BlockHash    --Agzs
			Block:          block,                //=> RequestBatch -> Block
			ReplicaId:      instance.id,
		}
		cert := instance.getCert(instance.view, n)
		cert.prePrepare = preprep
		cert.digest = d
		if n > instance.seqNo { //=> save max --Agzs
			instance.seqNo = n
		}
		instance.persistQSet() //=> saved in database. --Agzs
	}

	instance.updateViewChangeSeqNo()

	if instance.primary(instance.view) != instance.id {
		//for n, d := range nv.Xset {
		for _, xset := range nv.Xset {
			n, d := xset.Seq, xset.Hash
			////xiaobei 1.29
			if d == "" {
				logger.Info("------block digest is nil")
				continue
			}
			////
			prep := &types.Prepare{ //=> add types --Agzs
				View:           instance.view,
				SequenceNumber: n,
				BlockHash:      instance.blockStore[d].Hash().Bytes(), //=> BatchDigest -> BlockHash    --Agzs
				ReplicaId:      instance.id,
			}
			if n > instance.h {
				cert := instance.getCert(instance.view, n)
				cert.sentPrepare = true
				instance.recvPrepare(prep)
			}
			msg := &types.PbftMessage{
				// PrePrepare: nil,
				// Prepare:    prep,
				// Commit:     nil,
				// Checkpoint: nil,
				// ViewChange: nil,
				// NewView:    nil,
				//FetchBlockMsg: nil,
				Sender:      instance.id,
				PayloadCode: types.PrepareMsg,
				Payload:     prep,
			} //=> --Agzs
			instance.innerBroadcast(msg)
		}
	} else {
		logger.Debugf("Replica %d is now primary, attempting to resubmit requests", instance.id)
		instance.resubmitBlockMsges()
	}

	instance.startTimerIfOutstandingBlocks() ////change from startTimerIfOutstandingRequests. --xiaobei

	logger.Debugf("Replica %d done cleaning view change artifacts, calling into consumer", instance.id)

	return viewChangedEvent{}
}

func (instance *pbftCore) getViewChanges() (vset []*types.ViewChange) {
	for _, vc := range instance.viewChangeStore {
		vset = append(vset, vc)
	}

	return
}

func (instance *pbftCore) selectInitialCheckpoint(vset []*types.ViewChange) (checkpoint types.ViewChange_C, ok bool, replicas []uint64) {
	checkpoints := make(map[types.ViewChange_C][]*types.ViewChange)
	for _, vc := range vset {
		for _, c := range vc.Cset { // TODO, verify that we strip duplicate checkpoints from this set
			checkpoints[*c] = append(checkpoints[*c], vc) //=> get the viewchanges of the same checkpoint. --Agzs
			logger.Debugf("Replica %d appending checkpoint from replica %d with seqNo=%d, h=%d, and checkpoint digest %s", instance.id, vc.ReplicaId, vc.H, c.SequenceNumber, c.Id)
		}
	}
	//logger.Debugf("double for had been finished.")////test--xiaobei 11.20
	if len(checkpoints) == 0 {
		logger.Debugf("Replica %d has no checkpoints to select from: %d %s",
			instance.id, len(instance.viewChangeStore), checkpoints)
		return
	}

	for idx, vcList := range checkpoints {
		// need weak certificate for the checkpoint
		if len(vcList) <= instance.f { // type casting necessary to match types
			logger.Debugf("Replica %d has no weak certificate for n:%d, vcList was %d long",
				instance.id, idx.SequenceNumber, len(vcList))
			continue
		}

		quorum := 0
		// Note, this is the whole vset (S) in the paper, not just this checkpoint set (S') (vcList)
		// We need 2f+1 low watermarks from S below this seqNo from all replicas
		// We need f+1 matching checkpoints at this seqNo (S')
		for _, vc := range vset {
			if vc.H <= idx.SequenceNumber {
				quorum++
			}
		}

		if quorum < instance.intersectionQuorum() {
			logger.Debugf("Replica %d has no quorum for n:%d", instance.id, idx.SequenceNumber)
			continue
		}

		replicas = make([]uint64, len(vcList))
		for i, vc := range vcList {
			replicas[i] = vc.ReplicaId
		}

		if checkpoint.SequenceNumber <= idx.SequenceNumber { //=> find the maximal sequenceNumber's checkpoint. --Agzs
			checkpoint = idx
			ok = true
		}
	}

	return
}

func (instance *pbftCore) assignSequenceNumbers(vset []*types.ViewChange, h uint64) (msgList map[uint64]string) {
	msgList = make(map[uint64]string)

	maxN := h + 1
	//logger.Infof("maxN is %d", maxN) ////test--xiaobei  11.13
	// "for all n such that h < n <= h + L"
nLoop:
	for n := h + 1; n <= h+instance.L; n++ {
		// "∃m ∈ S..."
		for _, m := range vset {
			// "...with <n,d,v> ∈ m.P"
			for _, em := range m.Pset {
				//logger.Infof("vset.Pset is %+v", em) ////test--xiaobei 11.13
				quorum := 0
				// "A1. ∃2f+1 messages m' ∈ S"
			mpLoop:
				for _, mp := range vset {
					if mp.H >= n {
						continue
					}
					// "∀<n,d',v'> ∈ m'.P"
					for _, emp := range mp.Pset { //=> BatchDigest -> BlockHash --Agzs
						if n == emp.SequenceNumber && !(emp.View < em.View || (emp.View == em.View && emp.BlockHash == em.BlockHash)) {
							continue mpLoop
						}
					}
					quorum++
				}
				//logger.Infof("quorum = %d", quorum) ////test--xiaobei 11.13
				if quorum < instance.intersectionQuorum() {
					continue
				}

				quorum = 0
				// "A2. ∃f+1 messages m' ∈ S"
				for _, mp := range vset {
					// "∃<n,d',v'> ∈ m'.Q"
					for _, emp := range mp.Qset {
						//logger.Infof("vset.Qset is %+v", emp) ////test--xiaobei 11.13
						if n == emp.SequenceNumber && emp.View >= em.View && emp.BlockHash == em.BlockHash {
							quorum++
						}
					}
				}

				if quorum < instance.f+1 {
					continue
				}
				//logger.Infof("quorum2 is %d", quorum) ////test--xiaobei 11.13
				// "then select the request with digest d for number n"
				msgList[n] = em.BlockHash.Str() ////--xiaobei 11.21
				maxN = n
				//logger.Infof("n is %d", n) ////test--xiaobei 11.13
				continue nLoop
			}
		}

		quorum := 0
		// "else if ∃2f+1 messages m ∈ S"
	nullLoop:
		for _, m := range vset {
			// "m.P has no entry"
			for _, em := range m.Pset {
				//logger.Infof("nullLoop's Pset is %+v", em) ////test--xiaobei 11.13
				if em.SequenceNumber == n {
					continue nullLoop
				}
			}
			quorum++
		}
		//logger.Infof("nullLoop's quorum is %d", quorum) ////test--xiaobei 11.13
		if quorum >= instance.intersectionQuorum() {
			// "then select the null request for number n"
			msgList[n] = ""

			continue nLoop
		}

		logger.Warningf("Replica %d could not assign value to contents of seqNo %d, found only %d missing P entries", instance.id, n, quorum)
		return nil
	}

	// prune top null requests
	for n, msg := range msgList {
		if n > maxN && msg == "" {
			delete(msgList, n)
		}
		//logger.Infof("delete n is %d", n) ////test--xiaobei 11.13
	}

	return
}
