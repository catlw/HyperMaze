////xiaobei 1.9
package peerapi

import (
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

type PeerInterface interface{
	Head() (hash common.Hash, td *big.Int)
	Handshake(network, blockchainId uint64, td *big.Int, head common.Hash, genesis common.Hash) error
}

type PeerImpl struct{
	PEER PeerInterface
	ID string
}

var Peer PeerImpl
////