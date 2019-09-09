////xiaobei --12.13
package minerapi

type MinerApi interface {
	Start(threads *int) error
	Stop() bool
}

var Minerapi MinerApi
