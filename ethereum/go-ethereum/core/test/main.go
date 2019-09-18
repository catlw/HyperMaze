package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
)

func main() {
	// fmt.Println(123)
	// tx := types.NewTransaction(uint64(0), common.HexToAddress("ffffffffffffffffffffffffffffffffffffffff"), big.NewInt(1), big.NewInt(1), big.NewInt(1), []byte{1})
	// //fmt.Println(tx)
	// tx.SetZKSN(common.HexToHash("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"))
	// _ = types.ZKHashTx(tx)
	// fmt.Println(len(types.Transactions{tx}))
	// root := types.DeriveShaTx(types.Transactions{tx})
	// fmt.Println(root.Hex())
	// test := []common.Hash{common.StringToHash("test zkfunds")}
	// zkfundsroot := types.DeriveShaZkfunds(test)
	// fmt.Println("zkfunds root", zkfundsroot.Hex())
	str := "2cc5a1873bcd7e2c4564b57c474a12576a27315dd26d21bb28ed60ec6a9b6e29db0c1139b2666b0f87f23a902a91c834338c11f058b1575419bed06e574720e994ee6728f4446ef5ce6ac4704cfa55c74a1c9e450d68c998033b62079e0ee8760300000000000000"
	hash := types.TestHash(str)
	fmt.Println(hash.Hex())

}
