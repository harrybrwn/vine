package node

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	manet "github.com/multiformats/go-multiaddr-net"
)

func newStreamListener(ctx context.Context, h host.Host, proto protocol.ID) *streamListener {
	ctx, cancel := context.WithCancel(ctx)
	l := &streamListener{
		host:    h,
		streams: make(chan network.Stream),
		ctx:     ctx,
		cancel:  cancel,
	}
	if proto == "" {
		proto = "/grpc/0.1"
	}
	h.SetStreamHandler(proto, l.streamHandler)
	return l
}

// GRPCDialer creates a dialer function for use as a grpc.DialOption.
// A stream creator can be a host.Host from libp2p
//
// Use with the grpc.WithContextDialer dialer option
func GRPCDialer(h host.Host, proto ...protocol.ID) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		pid, err := peer.Decode(addr)
		if err != nil {
			return nil, err
		}
		s, err := h.NewStream(ctx, pid, proto...)
		if err != nil {
			return nil, err
		}
		return newStreamConn(s)
	}
}

type streamListener struct {
	host    host.Host
	streams chan network.Stream
	ctx     context.Context
	cancel  context.CancelFunc
}

func (sl *streamListener) streamHandler(s network.Stream) {
	select {
	case <-sl.ctx.Done():
		return
	case sl.streams <- s:
	}
}

func (sl *streamListener) Accept() (net.Conn, error) {
	select {
	case <-sl.ctx.Done():
		sl.cancel()
		return nil, sl.ctx.Err()
	case s := <-sl.streams:
		return newStreamConn(s)
	}
}

func (sl *streamListener) Close() error {
	return sl.host.Close()
}

func (sl *streamListener) Addr() net.Addr {
	addrs := sl.host.Network().ListenAddresses()
	for _, maaddr := range addrs {
		addr, err := manet.ToNetAddr(maaddr)
		if err == nil {
			return addr
		}
	}
	return nil
}

func newStreamConn(s network.Stream) (*streamConn, error) {
	local, err := manet.ToNetAddr(s.Conn().LocalMultiaddr())
	if err != nil {
		return nil, err
	}
	remote, err := manet.ToNetAddr(s.Conn().RemoteMultiaddr())
	if err != nil {
		return nil, err
	}
	return &streamConn{
		Stream: s,
		local:  local,
		remote: remote,
	}, nil
}

type streamConn struct {
	network.Stream
	local  net.Addr
	remote net.Addr
}

func (sc *streamConn) LocalAddr() net.Addr {
	return sc.local
}

func (sc *streamConn) RemoteAddr() net.Addr {
	return sc.remote
}

var (
	_ net.Conn     = (*streamConn)(nil)
	_ net.Listener = (*streamListener)(nil)
)
