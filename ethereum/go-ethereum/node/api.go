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

package node

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/hibe"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
)

// PrivateAdminAPI is the collection of administrative API methods exposed only
// over a secure RPC channel.
type PrivateAdminAPI struct {
	node *Node // Node interfaced by this API
}

//=======================================================>
type URLFlag struct {
	Enode *string // url <=> enode
	Flag  uint64  // mark node and peer
}

func (url *URLFlag) SetURLFlagFlag(flag uint64) { url.Flag = flag }

var privateAdminAPI *PrivateAdminAPI //=>add --Agzs 11.15

var AddPeerComm chan *URLFlag = make(chan *URLFlag)    // trigger to BroadcastAddPeerMsg()
var RemovePeerComm chan *URLFlag = make(chan *URLFlag) // trigger to BroadcastRemovePeerMsg()

var AddPeerUrlArray []*URLFlag    // maintain a current active url table added peers.
var RemovePeerUrlArray []*URLFlag // maintain a current active url table removed peers.

var LocalAddress chan string = make(chan string, 1) //ADD BY LIUWEI
var LocalLevel uint32 = 0xffffffff                  //ADD BY LIUWEI,set local node's default level
var TotalLevel uint32 = 0xffffffff                  //ADD BY LIUWEI

var NodeIndex uint32 = 0xffffffff

var SetMN = make(chan struct{}, 1)
var HibeFinished = make(chan string, 1)
var Start time.Time
var End time.Time

var KeyRequestTime time.Time
var KeyGenerateTime time.Time
var KeyStatus = make(chan bool, 10)
var KeyCount uint32

type MN struct { //ADD BY LIUWEI
	M, N uint32
	Mux  sync.RWMutex
}

var Mn = MN{}
var ParentMn = MN{}
var ChildrenMn = MN{}
var ID string
var ROOTID string = ""
var TestHIBE = make(chan string, 1)
var ResultFile *os.File

// GetPrivateAdminAPI for getting api to call AddPeer() --Agzs 11.15
func GetPrivateAdminAPI() *PrivateAdminAPI {
	return privateAdminAPI
}

// IsSelfENode judge whether a url(enode) is self or not.
func IsSelfENode(url string) bool {
	node, _ := discover.ParseNode(url)
	selfNode, _ := discover.ParseNode(GetSelfEnode())
	return node.ID == selfNode.ID
}

// GetSelfEnode return self enode
func GetSelfEnode() string {
	return *p2p.IsSelfNode
}

// OutCallAddPeer will call AddPeer to add peer
func (api *PrivateAdminAPI) OutCallAddPeer(url URLFlag) {
	if IsSelfENode(*url.Enode) && CheckItemInArray() == nil { // is self or existed in AddPeerUrlArray?
		return
	}
	flag, err := api.AddPeer(*url.Enode, url.Flag)
	if !flag {
		log.Warn("Add peers faild", "error", err, "url", url.Enode)
	} else {
		// delete new url from RemovePeerUrlArray, if it existed in RemovePeerUrlArray
		// ensure a url can reuse, ex(a url add, then remove, and add now)
		RemovePeerUrlArray = deleteItemInArray(RemovePeerUrlArray, url)
	}
}

// OutCallAddPeer will call RemovePeer to remove peer
func (api *PrivateAdminAPI) OutCallRemovePeer(url URLFlag) {
	if IsSelfENode(*url.Enode) && CheckItemInArray() == nil { // is self or existed in RemovePeerUrlArray?
		return
	}

	flag, err := api.RemovePeer(*url.Enode, url.Flag)
	if !flag {
		log.Warn("remove Peers faild", "error", err, "url", url.Enode)
	} else {
		// delete new url from AddPeerUrlArray, if it existed in AddPeerUrlArray
		// ensure a url can reuse, ex(a url add, then remove, and add now)
		AddPeerUrlArray = deleteItemInArray(AddPeerUrlArray, url)
	}
}

// judgeItemInArray judge a enode is self or in array
func JudgeItemInArray(urlArray []*URLFlag, url URLFlag) bool {
	if IsSelfENode(*url.Enode) || findItemInArray(urlArray, url) { // is self or existed in UrlArray?
		return true
	}
	return false
}

// PrintArray for testing.
func PrintArray() {
	log.Info("=============AddPeerUrlArray===========")
	for i, u := range AddPeerUrlArray {
		log.Info("AddPeerUrlArray:", "index", i, "url", *u.Enode, "flag", u.Flag)
	}
	log.Info("=============RemovePeerUrlArray===========")
	for i, u := range RemovePeerUrlArray {
		log.Info("RemovePeerUrlArray:", "index", i, "url", *u.Enode, "flag", u.Flag)
	}
}

// CheckItemInArray check item between AddPeerUrlArray and RemovePeerUrlArray
func CheckItemInArray() *URLFlag {
	for _, addPeerURL := range AddPeerUrlArray {
		if JudgeItemInArray(RemovePeerUrlArray, *addPeerURL) {
			return addPeerURL
		}
	}
	return nil
}

// findItemInArray finds whether a url is in urlArray or not.
func findItemInArray(urlArray []*URLFlag, url URLFlag) bool {
	for _, u := range urlArray {
		if *u.Enode == *url.Enode && u.Flag == url.Flag {
			return true
		}
	}
	return false
}

func deleteItemInArray(urlArray []*URLFlag, url URLFlag) []*URLFlag {
	var list []*URLFlag
	for _, u := range urlArray {
		if *u.Enode == *url.Enode && u.Flag == url.Flag {
			continue
		}
		list = append(list, u)
	}
	return list
}

//=======================================================>

// NewPrivateAdminAPI creates a new API definition for the private admin methods
// of the node itself.
func NewPrivateAdminAPI(node *Node) *PrivateAdminAPI {
	//=>return &PrivateAdminAPI{node: node} --Agzs 11.15
	//=>change. --Agzs
	privateAdminAPI = &PrivateAdminAPI{node: node}
	return privateAdminAPI
}

//--ADD BY LIUWEI 7.4
//SetAddress sets up a string standing for local node's public key.And the string will be sent to upper level nodes to get
//local node's private key.
func (api *PrivateAdminAPI) SetID(address string) (bool, error) {
	LocalAddress <- address
	ID = address
	return true, nil
}
func (api *PrivateAdminAPI) ID() (string, error) {
	return ID, nil
}
func (api *PrivateAdminAPI) KeyStatus() (bool, error) {
	select {
	case b := <-KeyStatus:
		return b, nil
	default:
		return false, nil
	}

}

func (api *PrivateAdminAPI) RequestID(ID string, count uint32) ([]*hibe.SecretShadow, error) {
	return nil, nil
}

//--test hibe
func (api *PrivateAdminAPI) SetLevel(totalLevel, currentLevel uint32) (bool, error) {
	LocalLevel = currentLevel
	TotalLevel = totalLevel
	return true, nil
}

//test hibe
func (api *PrivateAdminAPI) SetNumber(m, n uint32) (bool, error) {
	Mn.M = m
	Mn.N = n
	SetMN <- struct{}{}
	return true, nil
}

//test hibe
func (api *PrivateAdminAPI) Testhibe(str string) (bool, error) {
	TestHIBE <- str
	return true, nil
}

func (api *PrivateAdminAPI) AddPeerFromFile(file string) (bool, error) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("open file error")
		panic(err)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {

		line, err := rd.ReadString('\n') //
		if err != nil || io.EOF == err {
			break
		}
		line = line[0 : len(line)-1]
		strs := strings.Split(line, ",")
		url := strs[0]
		flag, err := strconv.Atoi(strs[1])
		if err != nil {
			panic(err)
		}
		api.AddPeer(url, uint64(flag))
	}
	return true, nil
}

// AddPeer requests connecting to a remote node, and also maintaining the new
// connection at all times, even reconnecting if it is lost.
//=> If it is a single blockchain, there don't need nodeFlag, and can set nodeFlag = 0 //=> --Agzs 2018.03.28
func (api *PrivateAdminAPI) AddPeer(url string, nodeFlag uint64) (bool, error) { //=>add nodeFlag using for node and peer. --Agzs 12.5
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to add the url as a static peer and return
	node, err := discover.ParseNode(url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	//if nodeFlag != 0 { //=>set nodeFlag. --Agzs 12.5
	node.SetNodeFlag(nodeFlag)
	//}

	server.AddPeer(node)
	//=================================>start<========== --Agzs 11.15
	urlflag := URLFlag{Enode: &url, Flag: nodeFlag}
	if !findItemInArray(AddPeerUrlArray, urlflag) {
		AddPeerUrlArray = append(AddPeerUrlArray, &urlflag)
	}
	AddPeerComm <- &urlflag

	// for i, u := range AddPeerUrlArray {
	// 	log.Info("AddPeerUrlArray:", "index", i, "url", *u.Enode, "flag", u.Flag)
	// }
	//==================================>end<===========
	return true, nil
}

// RemovePeer disconnects from a a remote node if the connection exists
//=> If it is a single blockchain, there don't need nodeFlag, and can set nodeFlag = 0 //=> --Agzs 2018.03.28
func (api *PrivateAdminAPI) RemovePeer(url string, nodeFlag uint64) (bool, error) {
	// Make sure the server is running, fail otherwise
	//log.Info("PrivateAdminAPI.RemovePeer()=======", "url", url) //=>test. --Agzs 11.15
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to remove the url as a static peer and return
	node, err := discover.ParseNode(url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	//if nodeFlag != 0 { //=>set nodeFlag. --Agzs 12.5
	node.SetNodeFlag(nodeFlag)
	//}

	server.RemovePeer(node)
	//=================================>start<========== --Agzs 11.15
	urlflag := URLFlag{Enode: &url, Flag: nodeFlag}
	if !findItemInArray(RemovePeerUrlArray, urlflag) {
		RemovePeerUrlArray = append(RemovePeerUrlArray, &urlflag)
	}
	RemovePeerComm <- &urlflag
	//==================================>end<===========
	return true, nil
}

// StartRPC starts the HTTP RPC API server.
func (api *PrivateAdminAPI) StartRPC(host *string, port *int, cors *string, apis *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.httpHandler != nil {
		return false, fmt.Errorf("HTTP RPC already running on %s", api.node.httpEndpoint)
	}

	if host == nil {
		h := DefaultHTTPHost
		if api.node.config.HTTPHost != "" {
			h = api.node.config.HTTPHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.HTTPPort
	}

	allowedOrigins := api.node.config.HTTPCors
	if cors != nil {
		allowedOrigins = nil
		for _, origin := range strings.Split(*cors, ",") {
			allowedOrigins = append(allowedOrigins, strings.TrimSpace(origin))
		}
	}

	modules := api.node.httpWhitelist
	if apis != nil {
		modules = nil
		for _, m := range strings.Split(*apis, ",") {
			modules = append(modules, strings.TrimSpace(m))
		}
	}

	if err := api.node.startHTTP(fmt.Sprintf("%s:%d", *host, *port), api.node.rpcAPIs, modules, allowedOrigins); err != nil {
		return false, err
	}
	return true, nil
}

// StopRPC terminates an already running HTTP RPC API endpoint.
func (api *PrivateAdminAPI) StopRPC() (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.httpHandler == nil {
		return false, fmt.Errorf("HTTP RPC not running")
	}
	api.node.stopHTTP()
	return true, nil
}

// StartWS starts the websocket RPC API server.
func (api *PrivateAdminAPI) StartWS(host *string, port *int, allowedOrigins *string, apis *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.wsHandler != nil {
		return false, fmt.Errorf("WebSocket RPC already running on %s", api.node.wsEndpoint)
	}

	if host == nil {
		h := DefaultWSHost
		if api.node.config.WSHost != "" {
			h = api.node.config.WSHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.WSPort
	}

	origins := api.node.config.WSOrigins
	if allowedOrigins != nil {
		origins = nil
		for _, origin := range strings.Split(*allowedOrigins, ",") {
			origins = append(origins, strings.TrimSpace(origin))
		}
	}

	modules := api.node.config.WSModules
	if apis != nil {
		modules = nil
		for _, m := range strings.Split(*apis, ",") {
			modules = append(modules, strings.TrimSpace(m))
		}
	}

	if err := api.node.startWS(fmt.Sprintf("%s:%d", *host, *port), api.node.rpcAPIs, modules, origins); err != nil {
		return false, err
	}
	return true, nil
}

// StopRPC terminates an already running websocket RPC API endpoint.
func (api *PrivateAdminAPI) StopWS() (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.wsHandler == nil {
		return false, fmt.Errorf("WebSocket RPC not running")
	}
	api.node.stopWS()
	return true, nil
}

// PublicAdminAPI is the collection of administrative API methods exposed over
// both secure and unsecure RPC channels.
type PublicAdminAPI struct {
	node *Node // Node interfaced by this API
}

// NewPublicAdminAPI creates a new API definition for the public admin methods
// of the node itself.
func NewPublicAdminAPI(node *Node) *PublicAdminAPI {
	return &PublicAdminAPI{node: node}
}

// Peers retrieves all the information we know about each individual peer at the
// protocol granularity.
func (api *PublicAdminAPI) Peers() ([]*p2p.PeerInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.PeersInfo(), nil
}

// NodeInfo retrieves all the information we know about the host node at the
// protocol granularity.
func (api *PublicAdminAPI) NodeInfo() (*p2p.NodeInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.NodeInfo(), nil
}

// Datadir retrieves the current data directory the node is using.
func (api *PublicAdminAPI) Datadir() string {
	return api.node.DataDir()
}

// PublicDebugAPI is the collection of debugging related API methods exposed over
// both secure and unsecure RPC channels.
type PublicDebugAPI struct {
	node *Node // Node interfaced by this API
}

// NewPublicDebugAPI creates a new API definition for the public debug methods
// of the node itself.
func NewPublicDebugAPI(node *Node) *PublicDebugAPI {
	return &PublicDebugAPI{node: node}
}

// Metrics retrieves all the known system metric collected by the node.
func (api *PublicDebugAPI) Metrics(raw bool) (map[string]interface{}, error) {
	// Create a rate formatter
	units := []string{"", "K", "M", "G", "T", "E", "P"}
	round := func(value float64, prec int) string {
		unit := 0
		for value >= 1000 {
			unit, value, prec = unit+1, value/1000, 2
		}
		return fmt.Sprintf(fmt.Sprintf("%%.%df%s", prec, units[unit]), value)
	}
	format := func(total float64, rate float64) string {
		return fmt.Sprintf("%s (%s/s)", round(total, 0), round(rate, 2))
	}
	// Iterate over all the metrics, and just dump for now
	counters := make(map[string]interface{})
	metrics.DefaultRegistry.Each(func(name string, metric interface{}) {
		// Create or retrieve the counter hierarchy for this metric
		root, parts := counters, strings.Split(name, "/")
		for _, part := range parts[:len(parts)-1] {
			if _, ok := root[part]; !ok {
				root[part] = make(map[string]interface{})
			}
			root = root[part].(map[string]interface{})
		}
		name = parts[len(parts)-1]

		// Fill the counter with the metric details, formatting if requested
		if raw {
			switch metric := metric.(type) {
			case metrics.Meter:
				root[name] = map[string]interface{}{
					"AvgRate01Min": metric.Rate1(),
					"AvgRate05Min": metric.Rate5(),
					"AvgRate15Min": metric.Rate15(),
					"MeanRate":     metric.RateMean(),
					"Overall":      float64(metric.Count()),
				}

			case metrics.Timer:
				root[name] = map[string]interface{}{
					"AvgRate01Min": metric.Rate1(),
					"AvgRate05Min": metric.Rate5(),
					"AvgRate15Min": metric.Rate15(),
					"MeanRate":     metric.RateMean(),
					"Overall":      float64(metric.Count()),
					"Percentiles": map[string]interface{}{
						"5":  metric.Percentile(0.05),
						"20": metric.Percentile(0.2),
						"50": metric.Percentile(0.5),
						"80": metric.Percentile(0.8),
						"95": metric.Percentile(0.95),
					},
				}

			default:
				root[name] = "Unknown metric type"
			}
		} else {
			switch metric := metric.(type) {
			case metrics.Meter:
				root[name] = map[string]interface{}{
					"Avg01Min": format(metric.Rate1()*60, metric.Rate1()),
					"Avg05Min": format(metric.Rate5()*300, metric.Rate5()),
					"Avg15Min": format(metric.Rate15()*900, metric.Rate15()),
					"Overall":  format(float64(metric.Count()), metric.RateMean()),
				}

			case metrics.Timer:
				root[name] = map[string]interface{}{
					"Avg01Min": format(metric.Rate1()*60, metric.Rate1()),
					"Avg05Min": format(metric.Rate5()*300, metric.Rate5()),
					"Avg15Min": format(metric.Rate15()*900, metric.Rate15()),
					"Overall":  format(float64(metric.Count()), metric.RateMean()),
					"Maximum":  time.Duration(metric.Max()).String(),
					"Minimum":  time.Duration(metric.Min()).String(),
					"Percentiles": map[string]interface{}{
						"5":  time.Duration(metric.Percentile(0.05)).String(),
						"20": time.Duration(metric.Percentile(0.2)).String(),
						"50": time.Duration(metric.Percentile(0.5)).String(),
						"80": time.Duration(metric.Percentile(0.8)).String(),
						"95": time.Duration(metric.Percentile(0.95)).String(),
					},
				}

			default:
				root[name] = "Unknown metric type"
			}
		}
	})
	return counters, nil
}

// PublicWeb3API offers helper utils
type PublicWeb3API struct {
	stack *Node
}

// NewPublicWeb3API creates a new Web3Service instance
func NewPublicWeb3API(stack *Node) *PublicWeb3API {
	return &PublicWeb3API{stack}
}

// ClientVersion returns the node name
func (s *PublicWeb3API) ClientVersion() string {
	return s.stack.Server().Name
}

// Sha3 applies the ethereum sha3 implementation on the input.
// It assumes the input is hex encoded.
func (s *PublicWeb3API) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}
