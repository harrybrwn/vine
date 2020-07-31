package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/harrybrwn/go-ledger/p2p"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newSendCmd() *cobra.Command {
	c := &cobra.Command{
		Use:           "send [messages...]",
		Short:         "Send a message to the network.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return newCommandErr("no messages", cmd)
			}
			ctx := context.Background()
			node, err := libp2p.New(ctx, libp2p.NoListenAddrs)
			if err != nil {
				return err
			}
			fmt.Println(node.ID().Pretty())
			ch, err := p2p.DiscoverOnce(node.ID(), discoveryTag)
			if err != nil {
				return err
			}

			for pa := range ch {
				go func(peer peer.AddrInfo) {
					fmt.Println("connecting to", peer.ID.Pretty())
					if err := node.Connect(ctx, peer); err != nil {
						log.Printf("Could not connect to %s: %v", peer.ID.Pretty(), err)
						return
					}
					s, err := node.NewStream(ctx, peer.ID, "/msg")
					if err != nil {
						log.Println("Could not create stream:", err)
						return
					}
					fmt.Fprintf(s, "%s\n", strings.Join(args, " "))
					s.Close()
				}(pa)
			}
			return nil
		},
	}
	return c
}

func newSyncCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "sync",
		Short: "Sync with blockchains on the network.",
	}
	return c
}

func newTestCmd() *cobra.Command {
	c := &cobra.Command{
		Use:    "test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			node, err := libp2p.New(
				ctx,
				libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
			)
			if err != nil {
				return err
			}
			fmt.Println(node.ID().Pretty())
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			ch, err := p2p.StartDiscovery(ctx, node, discoveryTag, time.Second)
			if err != nil {
				return err
			}

			for pa := range ch {
				if err := node.Connect(context.Background(), pa); err != nil {
					log.Error("Could not connect:", err)
					continue
				}
				s, err := node.NewStream(ctx, pa.ID, protocol.ID("/blk/block/"+node.ID().Pretty()))
				if err != nil {
					log.Error("could not create stream:", err)
					continue
				}
				// stop when the first stream is successful
				cancel()
				fmt.Print("reading from stream: ")
				io.Copy(os.Stdout, s)
				s.Close()
				println()
			}
			return nil
		},
	}
	return c
}

func newDaemonCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "daemon",
		Short: "Start a daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			pid := os.Getpid()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			node, err := libp2p.New(
				ctx,
				libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
			)
			if err != nil {
				return err
			}
			defer node.Close()

			fmt.Println(pid, node.ID())
			log.Infof("Starting daemon from pid=%d, node=%s", pid, node.ID().Pretty())
			return startDaemon(ctx, node)
		},
	}
	return c
}

var (
	discoveryTag = "blk-discovery._tcp"
	discoverTime = time.Second * 15
)

const peerIDLen = 46

func startDaemon(ctx context.Context, node host.Host) error {
	node.SetStreamHandler("/msg", func(s network.Stream) {
		// for testing
		io.Copy(os.Stdout, s)
	})
	node.SetStreamHandler("/blk/head", func(s network.Stream) {
		// response for nodes getting the first block
	})
	node.SetStreamHandlerMatch(
		"/blk/block",
		matchIDLen(peerIDLen),
		handleBlockReqStream,
	)

	discCtx, stopDiscovery := context.WithCancel(ctx)
	defer stopDiscovery()
	ch, err := p2p.StartDiscovery(discCtx, node, discoveryTag, discoverTime)
	if err != nil {
		return err
	}

	go func() {
		net := node.Network()
		for addr := range ch {
			if net.Connectedness(addr.ID) == network.Connected {
				continue
			}
			fmt.Println("connecting to", addr.ID)
			if err := node.Connect(ctx, addr); err != nil {
				log.Warn("could not connect:", err)
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	}
}

func handleBlockReqStream(stream network.Stream) {
	path, blkID := path.Split(string(stream.Protocol()))
	fmt.Fprintf(stream, `%s{"blockID": %s, "block": null}`, path, blkID)
	stream.Close()
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

type notifeeFunc func(peer.AddrInfo)

func (nf notifeeFunc) HandlePeerFound(p peer.AddrInfo) {
	nf(p)
}
