package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func main() {
	fmt.Println(123)
	tx := types.NewTransaction(uint64(0), common.HexToAddress("ffffffffffffffffffffffffffffffffffffffff"), big.NewInt(1), big.NewInt(1), big.NewInt(1), []byte{1})
	//fmt.Println(tx)
	tx.SetZKSN(common.HexToHash("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"))
	_ = types.ZKHashTx(tx)
	fmt.Println(len(types.Transactions{tx}))
	root := types.DeriveShaTx(types.Transactions{tx})
	fmt.Println(root.Hex())
	test := []common.Hash{common.StringToHash("test zkfunds")}
	zkfundsroot := types.DeriveShaZkfunds(test)
	fmt.Println("zkfunds root", zkfundsroot.Hex())

}
