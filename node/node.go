//go:generate protoc -I.. -I. --go_out=paths=source_relative:. ./node.proto

package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/harrybrwn/go-ledger/block"
	"github.com/harrybrwn/go-ledger/blockstore"
	"github.com/harrybrwn/go-ledger/p2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	// DiscoveryTag is the mDNS discovery service tag
	DiscoveryTag = "blk-discovery._tcp"
	// DiscoveryTime is the time that the discovery service waits
	// between restarts
	DiscoveryTime = time.Second * 30
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

	host.SetStreamHandlerMatch(
		"/blk/head", regex(`^(/test|/protobuf|/proto|/json)?/blk/head$`),
		func(s network.Stream) {
			defer s.Close()
			// response for nodes getting the first block
			parts := strings.Split(string(s.Protocol()), "/")
			protocol := parts[1]

			blk, err := n.store.HeadBlock()
			if err != nil {
				log.WithError(err).Error("could not get head block")
				return
			}
			log.WithField("protocol", protocol).Trace("got head block")

			err = sendBlock(protocol, blk, s)
			if err != nil {
				log.WithError(err).Debug("could not send block through network")
				fmt.Fprintf(s, `{"error":"%v"}`, err.Error())
				return
			}
		},
	)

	host.SetStreamHandlerMatch(
		"/blk/test", regex(`^/blk/test(/[A-Za-z]+)?$`),
		func(s network.Stream) {
			s.Write([]byte("testing testing 123"))
			s.Close()
		},
	)

	host.SetStreamHandlerMatch(
		"/blk/block",
		regex(`^/blk/block/.{65}?$`),
		n.handleBlockStreamReq,
	)

	host.SetStreamHandler("/blk/tx", func(s network.Stream) {
		// listen for new transactions
	})
	return n, nil
}

// Sync with the rest of the network.
func (n *Node) Sync() error {
	return nil
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
	defer s.Close()
	protocol, hash := getBlockHashFromProto(s.Protocol())
	if protocol == "" || hash == nil {
		fmt.Fprintf(s, `{"error":"could not find block"}`)
		return
	}
	buf := make([]byte, 32)
	_, err := s.Read(buf)
	if err != nil {
		log.Error("could not read stream: " + err.Error())
		return
	}
	log.Infof("getting %x from %s", hash, protocol)
	blk, err := n.store.Get(hash)
	if err != nil {
		fmt.Fprintf(s, `{"error":"block not found: %s"}`, err.Error())
		return
	}
	err = sendBlock(protocol, blk, s)
	if err != nil {
		fmt.Fprintf(s, `{"error":"%s"}`, err.Error())
		return
	}
}

func sendBlock(protocol string, blk *block.Block, s network.Stream) error {
	var (
		conn = s.Conn()
		err  error
		raw  []byte
		// TODO: I don't actually need to have the sender field
		data = BlockRequest{
			Block:  blk,
			Sender: string(conn.LocalPeer()),
		}
	)

	switch protocol {
	case "protobuf", "proto":
		raw, err = proto.Marshal(&data)
	case "json":
		raw, err = json.Marshal(&data)
	case "blk", "test":
		raw, err = json.MarshalIndent(&data, "", "  ")
	default:
		return errors.New("unknown protocol")
	}
	if err != nil {
		return errors.Wrap(err, "could not marshal block")
	}
	_, err = s.Write(raw)
	log.WithFields(log.Fields{
		"protocol": s.Protocol(),
		"from":     conn.LocalPeer().Pretty(),
		"to":       conn.RemotePeer().Pretty(),
		"hash":     hex.EncodeToString(blk.Hash),
	}).Info("sent block")
	return err
}

func getBlockHashFromProto(p protocol.ID) (string, []byte) {
	protopath, last := path.Split(string(p))
	switch last {
	case "protobuf", "proto":
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

func pathHasPrefix(prefix string) func(string) bool {
	return func(p string) bool { return strings.HasPrefix(p, prefix) }
}

func regex(pattern string) func(string) bool {
	pat := regexp.MustCompile(pattern)
	return pat.MatchString
}
