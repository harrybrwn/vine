package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/block"
	"github.com/harrybrwn/go-ledger/blockstore"
	"github.com/harrybrwn/go-ledger/p2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	log "github.com/sirupsen/logrus"
)

const (
	// DiscoveryTag is the mDNS discovery service tag
	DiscoveryTag = "blk-discovery._tcp"
	// DiscoveryTime is the time that the discovery service waits
	// between restarts
	DiscoveryTime = time.Second * 15

	peerIDLen = 46
)

// Node is a node
type Node struct {
	host     host.Host
	ctx      context.Context
	newPeers <-chan peer.AddrInfo
	cancel   context.CancelFunc
	store    *blockstore.BlockStore
}

// FullNode will run a full node
func FullNode(ctx context.Context, host host.Host, store *blockstore.BlockStore) (*Node, error) {
	ctx, stop := context.WithCancel(ctx)
	ch, err := p2p.StartDiscovery(ctx, host, DiscoveryTag, DiscoveryTime)
	if err != nil {
		stop()
		return nil, err
	}
	n := &Node{
		host:     host,
		ctx:      ctx,
		store:    store,
		newPeers: ch,
		cancel:   stop,
	}
	// start local discovery
	go n.discover()

	host.SetStreamHandlerMatch("/blk/head", pathyes, func(s network.Stream) {
		// response for nodes getting the first block
		_, protocol := path.Split(string(s.Protocol()))
		blk, err := n.store.HeadBlock()
		if err != nil {
			log.Error(err)
			return
		}
		log.Trace("got head block")
		sendBlock(protocol, blk, s)
	})
	host.SetStreamHandlerMatch(
		"/blk/block",
		matchIDLen(peerIDLen),
		n.handleBlockStreamReq,
	)
	host.SetStreamHandler("/blk/tx", func(s network.Stream) {
		// listen for new transactions
	})
	return n, nil
}

// Close the node
func (n *Node) Close() error {
	n.cancel()
	return n.host.Network().Close()
}

func (n *Node) discover() {
	net := n.host.Network()
	for addr := range n.newPeers {
		if addr.ID == n.host.ID() {
			log.Trace("blocked self discovery")
			continue
		}
		if net.Connectedness(addr.ID) == network.Connected {
			continue
		}
		log.Infof("connecting to %s", addr.ID.Pretty())
		if err := n.host.Connect(n.ctx, addr); err != nil {
			log.Warn("could not connect:", err)
		}
	}
}

func (n *Node) handleBlockStreamReq(s network.Stream) {
	protocol, hash := getBlockHashFromProto(s.Protocol())
	blk, err := n.store.Get(hash)
	if err != nil {
		log.Errorf("block %x not found: %v", hash, err)
		// TODO: figure out how i'm going to send errors back through the stream
		return
	}
	sendBlock(protocol, blk, s)
}

func sendBlock(protocol string, blk *block.Block, s network.Stream) {
	var (
		conn = s.Conn()
		err  error
		raw  []byte

		data = struct {
			Block  *block.Block
			Sender peer.ID
		}{blk, conn.LocalPeer()}
	)

	switch protocol {
	case "protobuf":
		raw, err = proto.Marshal(blk)
	case "json":
		raw, err = json.Marshal(&data)
	default:
		raw, err = json.MarshalIndent(&data, "", "  ")
	}
	if err != nil {
		// TODO: send an error through the stream
		log.WithError(err).Error("could not marshal block data")
		return
	}
	s.Write(raw)
	s.Close()
	log.WithFields(log.Fields{
		"protocol": s.Protocol(),
		"from":     conn.LocalPeer().Pretty(),
		"to":       conn.RemotePeer().Pretty(),
		"hash":     hex.EncodeToString(blk.Hash),
	}).Info("sent block")
}

func getBlockHashFromProto(p protocol.ID) (string, []byte) {
	protopath, last := path.Split(string(p))
	switch last {
	case "protobuf":
		_, hash := path.Split(protopath)
		return "protobuf", []byte(hash)
	case "json":
		_, hash := path.Split(protopath)
		return "json", []byte(hash)
	default:
		return "", []byte(last)
	}
}

func matchIDLen(l int) func(string) bool {
	return func(s string) bool {
		_, id := path.Split(s)
		if len(id) == l {
			return true
		}
		return false
	}
}

func pathyes(p string) bool {
	return true
}

func withRPCProtocol(base string) func(string) bool {
	return func(p string) bool {
		return false
	}
}
func jsonOrProtobufPath(p string) bool {
	_, protocol := path.Split(p)
	fmt.Println(p, protocol)
	if len(protocol) == 0 {
		return true
	}
	switch protocol {
	case "json", "protobuf":
		return true
	}
	return false
}
