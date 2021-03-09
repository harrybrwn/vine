package node

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/harrybrwn/go-vine/block"
	"github.com/harrybrwn/go-vine/blockstore"
	"github.com/harrybrwn/go-vine/internal/mockblock"
	"github.com/harrybrwn/go-vine/key/wallet"
	"github.com/harrybrwn/mdns"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	manet "github.com/multiformats/go-multiaddr-net"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

const TestingProto = "/vine/grpc/test/0.1"

func init() {
	log.SetLevel(log.PanicLevel)
	log.SetOutput(io.Discard)
	mdnslog := mdns.Logger()
	mdnslog.Out = io.Discard
}

func checkfn(t *testing.T) func(error) {
	return func(e error) {
		t.Helper()
		if e != nil {
			t.Error(e)
		}
	}
}

var none = &Empty{}

func TestDialGRPC(t *testing.T) {
	check := checkfn(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remote := startTestNode(ctx, t)
	defer remote.Close()
	remoteID := remote.host.ID()

	host, err := libp2p.New(ctx, libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0", "/ip6/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	node, err := FullNode(ctx, host, mockblock.NewChain(wallet.New()))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	// Directly connect to test server
	node.host.Connect(context.Background(), peer.AddrInfo{
		ID:    remote.host.ID(),
		Addrs: remote.host.Addrs(),
	})
	node.Start()
	time.Sleep(time.Microsecond * 150) // need to wait for the discovery goroutine

	conn, err := grpc.Dial(
		remoteID.Pretty(),
		grpc.WithContextDialer(GRPCDialer(host, TestingProto)),
		grpc.WithInsecure(),
	)
	check(err)
	defer conn.Close()
	client := NewBlockStoreClient(conn)
	blkmsg, err := client.Head(context.Background(), none)
	check(err)
	p, err := peer.Decode(blkmsg.Sender)
	check(err)
	if p != remoteID {
		t.Error("sender ID did not match remote id")
	}
	if len(blkmsg.Block.Hash) == 0 {
		t.Error("no hash block message")
	}
}

func startTestNode(ctx context.Context, t *testing.T) *Node {
	t.Helper()
	w := wallet.New()
	host, err := libp2p.New(ctx,
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.Identity(w),
	)
	if err != nil {
		t.Fatal(err)
	}
	store, err := blockstore.Open("", blockstore.AsInMemory())
	if err != nil {
		t.Fatal(err)
	}
	store.Push(block.Genisis(block.Coinbase(w)))
	node, err := FullNode(ctx, host, store)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	RegisterBlockStoreServer(srv, node)
	err = node.StartWithGRPC(srv, TestingProto)
	if err != nil {
		t.Error(err)
	}
	return node
}

func dialTestGRPC(s network.Stream, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	remote := s.Conn().RemoteMultiaddr()
	addr, err := manet.ToNetAddr(remote)
	if err != nil {
		return nil, err
	}
	dialer := grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return nil, nil
	})
	opts = append(opts, dialer)
	return grpc.Dial(addr.String(), opts...)
}
