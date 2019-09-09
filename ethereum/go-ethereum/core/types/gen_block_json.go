// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package types

import (
	"encoding/json"
	"math/big"
	"sync/atomic"
	"time"
)

func (b Block) MarshalJSON() ([]byte, error) {
	type BlockJson struct {
		Hheader       *Header
		Uuncles       []*Header
		Ttransactions Transactions

		// caches
		Hhash atomic.Value
		Ssize atomic.Value

		// Td is used by package core to store the total difficulty
		// of the chain up to and including the block.
		Ttd *big.Int

		// These fields are used by package eth to track
		// inter-peer block relay.
		ReceivedAt   time.Time
		ReceivedFrom interface{}
	}
	var enc BlockJson

	enc.Hheader = b.header
	enc.Uuncles = b.uncles
	enc.Ttransactions = b.transactions
	enc.Hhash = b.hash
	enc.Ssize = b.size
	enc.Ttd = b.td
	enc.ReceivedAt = b.ReceivedAt
	enc.ReceivedFrom = b.ReceivedFrom

	return json.Marshal(&enc)
}

func (b *Block) UnmarshalJSON(input []byte) error {
	type BlockJson struct {
		Hheader       *Header
		Uuncles       []*Header
		Ttransactions Transactions

		// caches
		Hhash atomic.Value
		Ssize atomic.Value

		// Td is used by package core to store the total difficulty
		// of the chain up to and including the block.
		Ttd *big.Int

		// These fields are used by package eth to track
		// inter-peer block relay.
		ReceivedAt   time.Time
		ReceivedFrom interface{}
	}
	var dec BlockJson
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	b.header = dec.Hheader
	b.uncles = dec.Uuncles
	b.transactions = dec.Ttransactions
	b.hash = dec.Hhash
	b.size = dec.Ssize
	b.td = dec.Ttd
	b.ReceivedAt = dec.ReceivedAt
	b.ReceivedFrom = dec.ReceivedFrom

	return nil
}
