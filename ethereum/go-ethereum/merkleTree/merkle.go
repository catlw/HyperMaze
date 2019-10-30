package merkle

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_convert -lzk_redeem  -lzk_deposit -lzk_withdraw -lff  -lsnark -lstdc++  -lgmp -lgmpxx
#include "merkle.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

var TxMerkleNODES = 32
var ZkfundsMerkleNODES = 256
var emptynode = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

func GenTxRoot(nodes []common.Hash) common.Hash {
	//fmt.Println(len(nodes))
	appendNodes := make([]*common.Hash, 0)
	if len(nodes) > TxMerkleNODES {
		fmt.Println("too much nodes for merkle tree ")
		return common.Hash{}
	}
	for i := 0; i < len(nodes); i++ {
		appendNodes = append(appendNodes, &nodes[i])
	}
	for len(appendNodes) < TxMerkleNODES {
		appendNodes = append(appendNodes, &emptynode)
	}
	return GenRT(appendNodes)
}

func GenZKfundsRoot(nodes []common.Hash) common.Hash {
	//fmt.Println(len(nodes))
	appendNodes := make([]*common.Hash, 0)
	if len(nodes) > ZkfundsMerkleNODES {
		fmt.Println("too much zkfunds nodes for merkle tree ")
		return common.Hash{}
	}
	for i := 0; i < len(nodes); i++ {
		appendNodes = append(appendNodes, &nodes[i])
	}
	for len(appendNodes) < ZkfundsMerkleNODES {
		appendNodes = append(appendNodes, &emptynode)
	}
	return GenRT(appendNodes)
}

//GenRT 返回merkel树的hash  --zy
func GenRT(CMTSForMerkle []*common.Hash) common.Hash {
	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	rtC := C.genRoot(cmtsM, C.int(len(CMTSForMerkle))) //--zy
	rtGo := C.GoString(rtC)

	res, _ := hex.DecodeString(rtGo)   //返回32长度 []byte  一个byte代表两位16进制数
	reshash := common.BytesToHash(res) //32长度byte数组
	return reshash
}
