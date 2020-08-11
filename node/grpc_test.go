package node

import (
	"context"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"github.com/harrybrwn/go-ledger/internal/mockblock"
	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	manet "github.com/multiformats/go-multiaddr-net"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func init() {
	log.SetLevel(log.PanicLevel)
	log.SetOutput(ioutil.Discard)
}

func checkfn(t *testing.T) func(error) {
	return func(e error) {
		t.Helper()
		if e != nil {
			t.Error(e)
		}
	}
}

func TestDialGRPC(t *testing.T) {
	check := checkfn(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remote := startTestNode(ctx, t)
	remoteID := remote.host.ID()

	host, err := libp2p.New(ctx, libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	node, err := FullNode(ctx, host, mockblock.NewChain(wallet.New()))
	if err != nil {
		t.Fatal(err)
	}
	node.Start()
	time.Sleep(time.Microsecond * 150) // need to wait for the discovery goroutine

	conn, err := grpc.Dial(
		remoteID.Pretty(),
		grpc.WithContextDialer(GRPCDialer(node.host, "/grpc/0.1")),
		grpc.WithInsecure(),
	)
	check(err)
	defer conn.Close()
	client := NewGetBlockClient(conn)
	blkmsg, err := client.Block(context.Background(), &BlockReq{Hash: []byte("head")})
	check(err)
	p, err := peer.Decode(blkmsg.Sender)
	check(err)
	if p != remoteID {
		t.Error("sender ID did not match remote id")
	}
}

func startTestNode(ctx context.Context, t *testing.T) *Node {
	t.Helper()
	w := wallet.New()
	priv, _, err := crypto.ECDSAKeyPairFromKey(w.PrivateKey())
	if err != nil {
		t.Error(err)
	}
	host, err := libp2p.New(ctx,
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.Identity(priv),
	)
	if err != nil {
		t.Fatal(err)
	}
	node, err := FullNode(ctx, host, mockblock.NewChain(w))
	if err != nil {
		t.Fatal(err)
	}
	srv := nodeServer(host.ID())
	err = node.StartWithGRPC(srv)
	if err != nil {
		t.Error(err)
	}
	return node
}

func nodeServer(id peer.ID) *grpc.Server {
	grpcsrv := grpc.NewServer()
	srv := &blkServer{id: id}
	RegisterGetBlockServer(grpcsrv, srv)
	return grpcsrv
}

// grpc service implimenting GetBlock
type blkServer struct {
	id peer.ID
	UnimplementedGetBlockServer
}

func (s *blkServer) Block(ctx context.Context, msg *BlockReq) (*BlockMsg, error) {
	log.Infof("got block request for %x", msg.Hash)
	return &BlockMsg{
		Block:    nil,
		Sender:   s.id.Pretty(),
		ErrorMsg: "not implemented",
	}, nil
}

var _ GetBlockServer = (*blkServer)(nil)

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
