////xiaobei 1.8
package synch

import (
	"github.com/ethereum/go-ethereum/peerapi"
)



type SYNC interface{
	Synchronise2(peer *peerapi.PeerImpl) 
	RetryHandShake(peer *peerapi.PeerImpl) error
}

var Sync SYNC
////
