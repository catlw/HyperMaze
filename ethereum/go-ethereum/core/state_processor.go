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

package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/zktx"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, *big.Int, error) {
	fmt.Println("stateprocessor start")
	var (
		receipts     types.Receipts
		totalUsedGas = big.NewInt(0)
		header       = block.Header()
		allLogs      []*types.Log
		gp           = new(GasPool).AddGas(block.GasLimit())
		funds        []common.Hash
	)
	// Mutate the the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, _, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, totalUsedGas, cfg)
		if err != nil {
			return nil, nil, nil, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
		if tx.TxCode() == types.TxDeposit {
			funds = append(funds, tx.ZKCMTfd())
		}

	}
	fundsinblock := block.Header().ZKFunds
	if len(funds) != len(fundsinblock) {
		fmt.Println("inconsistent zkfunds count in a block")
		return nil, nil, nil, errors.New("inconsistent zkfunds count in a block")
	}
	for i := 0; i < len(funds); i++ {
		if funds[i].String() != fundsinblock[i].String() {
			fmt.Println("inconsistent zkfunds content in a block")
		}
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), receipts, funds)

	return receipts, allLogs, totalUsedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc *BlockChain, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int, cfg vm.Config) (*types.Receipt, *big.Int, error) {
	var signer types.Signer
	switch tx.TxType() {
	case types.TxNormal:
		signer = types.MakeSigner(config, header.Number)
	case types.TxDhibe, types.TxHeader, types.TxCrossChain:
		signer = types.NewDHibeSigner()
	case types.TxZK:
		signer = types.NewZKSigner()
	}
	msg, err := tx.AsMessage(signer)
	if err != nil {
		return nil, nil, err
	}
	if tx.TxType() == types.TxZK {
		if tx.TxCode() == types.TxConvert {
			if exist := statedb.Exist(common.BytesToAddress(tx.ZKSN().Bytes())); exist == true && ((tx.ZKSN()) != common.Hash{}) { //if sn is already exist,
				return nil, big.NewInt(0), errors.New("sn is already used ")
			}
			cmtbalance := statedb.GetCMTBalance(msg.From())
			if err = zktx.VerifyConvertProof(cmtbalance, tx.ZKSN(), tx.ZKCMTbal(), tx.ZKValue(), tx.ZKProof()); err != nil {
				fmt.Println("invalid zk convert proof: ", err)
				return nil, big.NewInt(0), err
			}
			statedb.CreateAccount(common.BytesToAddress(tx.ZKSN().Bytes()))
			statedb.SetNonce(common.BytesToAddress(tx.ZKSN().Bytes()), 1)
		}
		if tx.TxCode() == types.TxRedeem {
			if exist := statedb.Exist(common.BytesToAddress(tx.ZKSN().Bytes())); exist == true && ((tx.ZKSN()) != common.Hash{}) { //if sn is already exist,
				return nil, big.NewInt(0), errors.New("sn is already used ")
			}
			cmtbalance := statedb.GetCMTBalance(msg.From())
			if err = zktx.VerifyRedeemProof(cmtbalance, tx.ZKSN(), tx.ZKCMTbal(), tx.ZKValue(), tx.ZKProof()); err != nil {
				fmt.Println("invalid zk redeem proof: ", err)
				return nil, big.NewInt(0), err
			}
			statedb.CreateAccount(common.BytesToAddress(tx.ZKSN().Bytes()))
			statedb.SetNonce(common.BytesToAddress(tx.ZKSN().Bytes()), 1)
		}
		if tx.TxCode() == types.TxDeposit {
			if exist := statedb.Exist(common.BytesToAddress(tx.ZKSN().Bytes())); exist == true && ((tx.ZKSN()) != common.Hash{}) { //if sn is already exist,
				return nil, big.NewInt(0), errors.New("sn is already used ")
			}
			cmtbalance := statedb.GetCMTBalance(msg.From())
			if err = zktx.VerifyDepositProof(tx.ZKSN(), tx.ZKCMTfd(), tx.ZKProof(), cmtbalance, tx.ZKCMTbal()); err != nil {
				fmt.Println("invalid zk send proof: ", err)
				return nil, big.NewInt(0), err
			}
			statedb.CreateAccount(common.BytesToAddress(tx.ZKSN().Bytes()))
			statedb.SetNonce(common.BytesToAddress(tx.ZKSN().Bytes()), 1)
		}

		// else if tx.TxCode() == types.TxWithdraw {
		// 	if exist := statedb.Exist(common.BytesToAddress(tx.ZKSN().Bytes())); exist == true && (*(tx.ZKSN()) != common.Hash{}) { //if sn is already exist,
		// 		return nil, 0, errors.New("sn is already used ")
		// 	}
		// 	cmtbalance := statedb.GetCMTBalance(msg.From())
		// 	if err = zktx.VerifyRedeemProof(&cmtbalance, tx.ZKSN(), tx.ZKCMT(), tx.ZKValue(), tx.ZKProof()); err != nil {
		// 		fmt.Println("invalid zk redeem proof: ", err)
		// 		return nil, 0, err
		// 	}
		// 	statedb.CreateAccount(common.BytesToAddress(tx.ZKSN().Bytes()))
		// 	statedb.SetNonce(common.BytesToAddress(tx.ZKSN().Bytes()), 1)
		// }

		//else if tx.TxCode() == types.TxRedeem {
		// 	cmtbalance := statedb.GetCMTBalance(msg.From())
		// 	if exist := statedb.Exist(common.BytesToAddress(tx.ZKSN().Bytes())); exist == true && ((tx.ZKSN()) != common.Hash{}) { //if sn is already exist,
		// 		return nil, big.NewInt(0), errors.New("sn is already used ")
		// 	}
		// 	if err = zktx.VerifySendProof(tx.ZKSN(), tx.ZKCMTS(), tx.ZKProof(), &cmtbalance, tx.ZKCMT()); err != nil {
		// 		fmt.Println("invalid zk send proof: ", err)
		// 		return nil, big.NewInt(0), err
		// 	}
		// 	statedb.CreateAccount(common.BytesToAddress(tx.ZKSN().Bytes()))
		// 	statedb.SetNonce(common.BytesToAddress(tx.ZKSN().Bytes()), 1)
		// 	// } else if tx.TxCode() == types.UpdateTx {
		// 	// 	cmtbalance := statedb.GetCMTBalance(msg.From())
		// 	// 	if err = zktx.VerifyUpdateProof(&cmtbalance, tx.RTcmt(), tx.ZKCMT(), tx.ZKProof()); err != nil {
		// 	// 		fmt.Println("invalid zk update proof: ", err)
		// 	// 		return nil, 0, err
		// 	// 	}
		// } else if tx.TxCode() == types.TxDeposit {
		// 	if exist := statedb.Exist(common.BytesToAddress(tx.ZKSN().Bytes())); exist == true && (*(tx.ZKSN()) != common.Hash{}) { //if sn is already exist,
		// 		return nil, 0, errors.New("sn in deposit tx has been already used")
		// 	}
		// 	cmtbalance := statedb.GetCMTBalance(msg.From())
		// 	addr1, err := types.ExtractPKBAddress(types.HomesteadSigner{}, tx) //tbd
		// 	ppp := ecdsa.PublicKey{crypto.S256(), tx.X(), tx.Y()}
		// 	addr2 := crypto.PubkeyToAddress(ppp)
		// 	if err != nil || addr1 != addr2 {
		// 		return nil, 0, errors.New("invalid depositTx signature ")
		// 	}
		// 	if err = zktx.VerifyDepositProof(&ppp, tx.RTcmt(), &cmtbalance, tx.ZKSN(), tx.ZKCMT(), tx.ZKProof()); err != nil {
		// 		fmt.Println("invalid zk deposit proof: ", err)
		// 		return nil, 0, err
		// 	}
		// 	statedb.CreateAccount(common.BytesToAddress(tx.ZKSN().Bytes()))
		// 	statedb.SetNonce(common.BytesToAddress(tx.ZKSN().Bytes()), 1)
		// } else if tx.TxCode() == types.TxWithdraw {
		// 	if exist := statedb.Exist(common.BytesToAddress(tx.ZKSN().Bytes())); exist == true && (*(tx.ZKSN()) != common.Hash{}) { //if sn is already exist,
		// 		return nil, 0, errors.New("sn is already used ")
		// 	}
		// 	cmtbalance := statedb.GetCMTBalance(msg.From())
		// 	if err = zktx.VerifyRedeemProof(&cmtbalance, tx.ZKSN(), tx.ZKCMT(), tx.ZKValue(), tx.ZKProof()); err != nil {
		// 		fmt.Println("invalid zk redeem proof: ", err)
		// 		return nil, 0, err
		// 	}
		// 	statedb.CreateAccount(common.BytesToAddress(tx.ZKSN().Bytes()))
		// 	statedb.SetNonce(common.BytesToAddress(tx.ZKSN().Bytes()), 1)
		// }
	}

	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	_, gas, err := ApplyMessage(vmenv, msg, gp)
	if err != nil {
		return nil, nil, err
	}

	// Update the state with pending changes
	usedGas.Add(usedGas, gas)
	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	root := statedb.IntermediateRoot(config.IsEIP158(header.Number))
	receipt := types.NewReceipt(root.Bytes(), usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = new(big.Int).Set(gas)
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}
