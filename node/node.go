package node

//go:generate protoc -I../protobuf -I.. --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. ../protobuf/node.proto

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
	"github.com/harrybrwn/vine/block"
	"github.com/harrybrwn/vine/p2p"
	"github.com/libp2p/go-libp2p-core/event"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const (
	// DiscoveryTag is the mDNS discovery service tag
	DiscoveryTag = "vine._tcp"
	// DiscoveryTime is the time that the discovery service waits
	// between restarts
	DiscoveryTime = time.Second * 30

	// GRPCProto is the default gRPC protocol
	GRPCProto = "/vine/grpc/0.1"
)

// Node is a node
type Node struct {
	host  host.Host
	store block.Store
	txdb  block.TxFinder

	newPeers <-chan peer.AddrInfo

	ctx    context.Context
	cancel context.CancelFunc
	errs   chan error

	// Set of transaction IDs (encoded as hex) that have been received
	// from the network.
	// TODO implement this
	txCache map[string]struct{}

	UnimplementedBlockStoreServer
}

// New will create a partial node
func New(ctx context.Context, host host.Host) (*Node, error) {
	ctx, stop := context.WithCancel(ctx)
	disc := p2p.Discovery{
		Host:     host,
		Service:  DiscoveryTag,
		Duration: DiscoveryTime,
	}
	ch, err := disc.StartContext(ctx)
	if err != nil {
		stop()
		return nil, err
	}
	n := &Node{
		host:     host,
		ctx:      ctx,
		newPeers: ch,
		errs:     make(chan error),
		cancel:   stop,
		store:    nil,
	}
	return n, nil
}

// This is temporary
type blockStoreTxdb interface {
	block.Store
	block.TxFinder
}

// FullNode will run a full node
func FullNode(ctx context.Context, host host.Host, store blockStoreTxdb) (*Node, error) {
	ctx, stop := context.WithCancel(ctx)
	discovery := p2p.Discovery{
		Host:     host,
		Service:  DiscoveryTag,
		Duration: DiscoveryTime,
	}
	ch, err := discovery.StartContext(ctx)
	if err != nil {
		stop()
		return nil, err
	}
	n := &Node{
		host:     host,
		ctx:      ctx,
		store:    store,
		txdb:     store,
		newPeers: ch,
		cancel:   stop,
		errs:     make(chan error),
	}

	host.SetStreamHandlerMatch(
		"/vine/head", regex(`^(/test|/protobuf|/proto|/json)?/vine/head$`),
		func(s network.Stream) {
			defer s.Close()
			// response for nodes getting the first block
			parts := strings.Split(string(s.Protocol()), "/")
			protocol := parts[1]

			blk, err := n.store.Head()
			if err != nil {
				log.WithError(err).Debug("could not respond with head block")
				sendError(s, err)
				return
			}
			log.WithField("protocol", protocol).Trace("got head block")

			err = sendBlock(protocol, blk, s)
			if err != nil {
				log.WithError(err).Debug("could not send block through network")
				sendError(s, err)
				return
			}
		},
	)

	host.SetStreamHandlerMatch(
		"/vine/test", regex(`^/vine/test(/[A-Za-z]+)?$`),
		func(s network.Stream) {
			s.Write([]byte("testing testing 123"))
			s.Close()
		},
	)

	host.SetStreamHandlerMatch(
		"/vine/block",
		regex(`^/vine/block/.{65}?$`),
		n.handleBlockStreamReq,
	)

	host.SetStreamHandler(
		"/vine/chain",
		func(s network.Stream) {
			defer s.Close()
			err = sendChain(s, store)
			if err != nil {
				log.WithError(err).Error("could not marshal chain into json")
			}
		},
	)

	// listen for new transactions
	host.SetStreamHandler("/vine/tx", func(s network.Stream) {
		log.WithFields(log.Fields{
			"proto": s.Protocol(),
		}).Info("tx received")
	})

	return n, nil
}

// Start the node
func (n *Node) Start() error {
	// start local discovery
	go n.discover()
	go func() {
		for err := range n.errs {
			log.WithFields(log.Fields{
				"error": err,
			}).Error("node: discovery error")
		}
	}()
	return nil
}

// StartWithGRPC will start the node and listen for requests
// from the network with a grpc server.
func (n *Node) StartWithGRPC(srv *grpc.Server, proto protocol.ID) error {
	l := newStreamListener(n.ctx, n.host, proto)
	go func() {
		err := srv.Serve(l)
		if err != nil {
			log.WithError(err).Error("could not serve grpc server")
		}
	}()
	return n.Start()
}

// Sync with the rest of the network.
func (n *Node) Sync() error {
	return nil
}

// Close the node
func (n *Node) Close() error {
	n.cancel()
	return n.host.Close()
}

// Peers returns a slice of peer ids that are addressable
func (n *Node) Peers() peer.IDSlice {
	hostid := n.host.ID()
	ids := n.host.Peerstore().PeersWithAddrs()
	peers := make(peer.IDSlice, 0, len(ids))
	for _, id := range ids {
		if id == hostid {
			continue
		}
		peers = append(peers, id)
	}
	return peers
}

// PeerAddrs will iterate through the node's peers and
// collect their addresses.
func (n *Node) PeerAddrs() []multiaddr.Multiaddr {
	hostid := n.host.ID()
	addrs := make([]multiaddr.Multiaddr, 0)
	for _, id := range n.host.Peerstore().PeersWithAddrs() {
		if id == hostid {
			continue
		}
		for _, a := range n.host.Peerstore().Addrs(id) {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

// GetHeadBlock will get the head block from the network
func (n *Node) GetHeadBlock() (*block.Block, error) {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithContextDialer(GRPCDialer(n.host, GRPCProto)),
	}
	ctx, cancel := context.WithCancel(n.ctx)
	defer cancel()
	for _, p := range n.Peers() {
		conn, err := grpc.DialContext(ctx, p.Pretty(), opts...)
		if err != nil {
			log.Warning(err)
			continue
		}
		client := NewBlockStoreClient(conn)
		msg, err := client.Head(ctx, &Empty{})
		if err != nil {
			continue
		}
		return msg.Block, nil
	}
	return nil, errors.New("did not find head block")
}

// BroadcastTx will broadcast a transaction to all the node's peers
func (n *Node) BroadcastTx(tx *block.Transaction) error {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithContextDialer(GRPCDialer(n.host, GRPCProto)),
	}
	for _, p := range n.Peers() {
		conn, err := grpc.DialContext(n.ctx, p.Pretty(), opts...)
		if err != nil {
			log.WithFields(log.Fields{"error": err, "peer": p}).Error("could not dial peer")
			continue
		}
		client := NewBlockStoreClient(conn)
		status, err := client.Tx(n.ctx, &TxMsg{Sender: n.host.ID().Pretty(), Tx: tx})
		if err != nil {
			log.WithError(err).Error("could not send transaction")
			continue
		}
		log.WithFields(log.Fields{
			"code":     status.Code,
			"status":   status.Status,
			"receiver": p,
		}).Info("transaction sent")
	}
	return nil
}

func (n *Node) discover() {
	net := n.host.Network()
	emitter, err := n.host.EventBus().Emitter(&event.EvtPeerConnectednessChanged{})
	if err != nil {
		log.WithError(err).Error("could not create connectedness event, shutting down discovery")
		return
	}
	for addr := range n.newPeers {
		if addr.ID == n.host.ID() {
			log.Trace("blocked self discovery")
			continue
		}
		if net.Connectedness(addr.ID) == network.Connected {
			// if we are already connected to this address then skip it
			continue
		}
		if err := n.host.Connect(n.ctx, addr); err != nil {
			log.WithError(err).WithFields(addr.Loggable()).Errorf(
				"could not connect to %s", addr.ID.Pretty())
			continue
		}
		err = emitter.Emit(event.EvtPeerConnectednessChanged{
			Peer:          addr.ID,
			Connectedness: network.Connected,
		})
		if err != nil {
			log.WithError(err).Warn("could not emit connected event")
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
		data = BlockMsg{
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

func sendChain(s network.Stream, store block.Store) error {
	blocks := make([]*block.Block, 0)
	it := store.Iter()
	for {
		blk := it.Next()
		blocks = append(blocks, blk)
		if block.IsGenisis(blk) {
			break
		}
	}
	b, err := json.MarshalIndent(blocks, "  ", "  ")
	if err != nil {
		return err
	}
	_, err = s.Write(b)
	return err
}

func sendError(s network.Stream, err error) {
	fmt.Fprintf(s, `{"error":"%v"}`, err)
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
