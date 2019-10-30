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
	"encoding/base64"
	"encoding/json" //=> for json.  change proto to json. --Agzs
	"fmt"

	"github.com/ethereum/go-ethereum/core/types" //=> for ViewChange_PQ --Agzs
)

var N uint64 ////xiaobei 1.4
func (instance *pbftCore) persistQSet() {
	var qset []*types.ViewChange_PQ

	for _, q := range instance.calcQSet() {
		qset = append(qset, q)
	}
	// for key, value := range qset { ////test--xiaobei 11.20
	// 	logger.Infof("before persistQSet() qset[%d].digest is %x", key, value.BlockHash)
	// }
	instance.persistPQSet("qset", qset)
}

func (instance *pbftCore) persistPSet() {
	var pset []*types.ViewChange_PQ

	for _, p := range instance.calcPSet() {
		pset = append(pset, p)
	}
	// for key, value := range pset { ////test--xiaobei 11.20
	// 	logger.Infof("before persistPSet() pset[%d].digest is %x,seqNo=%d", key, value.BlockHash, value.SequenceNumber)
	// }
	instance.persistPQSet("pset", pset)
}

//=> overwrite persistPQset by reading snapshot.store() --Agzs
func (instance *pbftCore) persistPQSet(key string, set []*types.ViewChange_PQ) {
	// var s common.Hash
	// for key, _ := range set {
	// 	s = common.StringToHash(set[key].BlockHash)
	// 	fmt.Println("string to hash", s)
	// }
	raw, err := json.Marshal(&types.PQset{Set: set})
	//logger.Infof("persistPQSet %s is %s", key, string(raw)) ////--xiaobei 11.20
	////////////////
	// val2 := &types.Test{
	// 	//Valuea: s1,
	// 	Valueb: set[0].BlockHash,
	// 	Seq:    set[0].SequenceNumber,
	// }
	// raw2, err := json.Marshal(val2)
	// logger.Infof("set[0].BlockHash is %s,json.Marshal for Test %s", set[0].BlockHash, string(raw2)) ////--xiaobei 11.20
	// val3 := &types.Test{}
	// err = json.Unmarshal(raw2, val3)
	// logger.Infof("json.Unmarshal for set[0].BlockHash %x,seqNo %d", val3.Valueb, val3.Seq)
	////////////////
	// val := &types.PQset{}
	// err = json.Unmarshal(raw, val)
	// for key2, value := range val.Set {
	// 	logger.Infof("json.unmarshal %s[%d].blockhash=%x seqNo=%d view=%d", key, key2, value.BlockHash, value.SequenceNumber, value.View)
	// }
	// for key2, value := range raw.Set {
	// 	logger.Infof("persistPQSet %s[%d]=%x ", key, key2, value.BlockHash)
	// }
	if err != nil {
		logger.Warningf("Replica %d could not persist pqset: %s: error: %s", instance.id, key, err)
		return
	}
	err = instance.helper.StoreState(key, raw)
	if err != nil {
		logger.Warningf("Replica %d could not persist pqset: %s: error: %s", instance.id, key, err)
	}
}

//=> overwrite restorePQSet by reading snapshot.loadSnapshot() --Agzs
func (instance *pbftCore) restorePQSet(key string) []*types.ViewChange_PQ {
	raw, err := instance.helper.ReadState(key)
	logger.Infof("restorePQSet %s is %s", key, string(raw)) ////test--xiaobei 11.20
	if err != nil {
		logger.Debugf("Replica %d could not restore state %s: %s", instance.id, key, err)
		return nil
	}
	val := &types.PQset{}
	err = json.Unmarshal(raw, val)
	for key2, value := range val.Set { ////test--xiaobei 11.20
		logger.Infof("restorePQSet %s[%d].blockhash=%x seqNo=%d view=%d", key, key2, value.BlockHash, value.SequenceNumber, value.View)
	}

	if err != nil {
		logger.Errorf("Replica %d could not unmarshal %s - local state is damaged: %s", instance.id, key, err)
		return nil
	}
	return val.GetSet()
}

//=> overwrite persistRequestBlock. --Agzs
func (instance *pbftCore) persistRequestBlock(digest string) {
	reqBock := instance.blockStore[digest]
	//logger.Infof("persistRequestBlock(digest string)---reqBock is %+v,digest is %x", reqBock, digest) ////test--xiaobei 11.20
	//reqBlockPacked, err := json.Marshal(reqBock)
	reqBlockPacked, err := reqBock.MarshalJSON() ////--xiaobei 11.22
	//test, err := json.Marshal(reqBock.Hheader)
	//logger.Infof("reqBlockPacked byte is %x", reqBlockPacked)
	//fmt.Println("reqBlockPacked is", string(reqBlockPacked))
	if err != nil {
		logger.Warningf("Replica %d could not persist block %s: %s", instance.id, digest, err)
		return
	}
	err = instance.helper.StoreState("reqBlock."+digest, reqBlockPacked)
	if err != nil {
		logger.Warningf("Replica %d could not persist block %s: %s", instance.id, digest, err)
	} else {
		logger.Warningf("Replica %d persist block %x", instance.id, digest) ////test--xiaobei 11.20
	}
}

//=> overwrite persistDelRequestBlock. --Agzs
func (instance *pbftCore) persistDelRequestBlock(digest string) {
	//instance.dbHelper.DelState("reqBlock." + digest)
	instance.helper.DelState("reqBlock." + digest)

}

//=> overwrite persistDelAllRequestBlockes. --Agzs
func (instance *pbftCore) persistDelAllRequestBlockes() {
	reqBlockes, err := instance.helper.ReadStateSet("reqBlock.")
	if err == nil {
		for k := range reqBlockes {
			instance.helper.DelState(k)
		}
	}
}

func (instance *pbftCore) persistCheckpoint(seqNo uint64, id []byte) {
	key := fmt.Sprintf("chkpt.%d", seqNo)
	err := instance.helper.StoreState(key, id)
	if err != nil {
		logger.Warningf("Could not persist Checkpoint %s: %s", key, err)
	}
}

func (instance *pbftCore) persistDelCheckpoint(seqNo uint64) {
	key := fmt.Sprintf("chkpt.%d", seqNo)
	instance.helper.DelState(key)
}

func (instance *pbftCore) restoreState() {
	updateSeqView := func(set []*types.ViewChange_PQ) {
		for _, e := range set {
			if instance.view < e.View {
				instance.view = e.View
			}
			if instance.seqNo < e.SequenceNumber {
				instance.seqNo = e.SequenceNumber
			}
		}
	}

	set := instance.restorePQSet("pset")
	for _, e := range set {
		instance.pset[e.SequenceNumber] = e
	}
	// for _, e1 := range set { ////--xiaobei 11.20
	// 	logger.Infof("pset--block digest is %x", e1.BlockHash)
	// }
	updateSeqView(set)

	set = instance.restorePQSet("qset")
	for _, e := range set {
		instance.qset[qidx{e.BlockHash.Str(), e.SequenceNumber}] = e //=> BatchDigest -> BlockHash --Agzs  --xiaobei 11.21
	}
	// for _, e1 := range set { ////--xiaobei 11.20
	// 	logger.Infof("qset--block digest is %x", e1.BlockHash)
	// }
	updateSeqView(set)

	reqBlockesPacked, err := instance.helper.ReadStateSet("reqBlock.")
	logger.Infof("reqBlockesPacked's length is %d", len(reqBlockesPacked)) ////--xiaobei 11.16
	if err == nil {
		for k, v := range reqBlockesPacked {
			reqBlock := &types.Block{} //=>RequestBatch -> BLock. --Agzs
			//err = json.Unmarshal(v, reqBlock)
			err = reqBlock.UnmarshalJSON(v) ////--xiaobei 11.22
			if err != nil {
				logger.Warningf("Replica %d could not restore request batch %s", instance.id, k)
			} else {
				instance.blockStore[reqBlock.Hash().Str()] = reqBlock                  //=> hash(reqBlock) -> reqBlock.Hash().Str()
				logger.Infof("restore blockstore digest is %x", reqBlock.Hash().Str()) ////test--xiaobei 11.16
			}
		}
	} else {
		logger.Warningf("Replica %d could not restore blockStore: %s", instance.id, err)
	}

	instance.restoreLastSeqNo()

	chkpts, err := instance.helper.ReadStateSet("chkpt.")
	if err == nil {
		lowWatermark := *instance.LastExec // This is safe because we will round down in moveWatermarks
		for key, id := range chkpts {
			var seqNo uint64
			if _, err = fmt.Sscanf(key, "chkpt.%d", &seqNo); err != nil {
				logger.Warningf("Replica %d could not restore checkpoint key %s", instance.id, key)
			} else {
				idAsString := base64.StdEncoding.EncodeToString(id) //=>TODO. --Agzs
				logger.Debugf("Replica %d found checkpoint %s for seqNo %d", instance.id, idAsString, seqNo)
				instance.chkpts[seqNo] = idAsString
				if seqNo < lowWatermark {
					lowWatermark = seqNo
				}
			}
		}
		instance.moveWatermarks(lowWatermark)
	} else {
		logger.Warningf("Replica %d could not restore checkpoints: %s", instance.id, err)
	}

	logger.Infof("Replica %d restored state: view: %d, seqNo: %d, pset: %d, qset: %d, blockStore: %d, chkpts: %d h: %d",
		instance.id, instance.view, instance.seqNo, len(instance.pset), len(instance.qset), len(instance.blockStore), len(instance.chkpts), instance.h)
}

//=> overwrite restoreLastSeqNo() --Agzs
func (instance *pbftCore) restoreLastSeqNo() {
	var err error
	//=> LastExec = LastBlockNumber --Agzs
	// if instance.LastExec, err = instance.helper.getLastSeqNo(); err != nil {
	// 	logger.Warningf("Replica %d could not restore LastExec: %s", instance.id, err)
	// 	instance.LastExec = 0
	// }
	N = instance.seqNo     ////xiaobei 1.3
	instance.LastExec = &N ////--xiaobei 1.3

	if *instance.LastExec == 0 {
		logger.Warningf("Replica %d could not restore LastExec: %s", instance.id, err)
	}

	logger.Infof("Replica %d restored LastExec: %d", instance.id, *instance.LastExec)
}
