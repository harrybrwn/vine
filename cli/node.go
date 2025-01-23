package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/harrybrwn/config"
	"github.com/harrybrwn/vine/block"
	"github.com/harrybrwn/vine/blockstore"
	"github.com/harrybrwn/vine/key"
	"github.com/harrybrwn/vine/key/wallet"
	"github.com/harrybrwn/vine/node"
	"github.com/harrybrwn/vine/p2p"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

func newhost(ctx context.Context) (host.Host, error) {
	w, err := openWallet(config.GetString("wallet"))
	if err != nil {
		return nil, err
	}
	return libp2p.New(ctx,
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.Identity(w),
	)
}

func newnode(ctx context.Context) (*node.Node, host.Host, error) {
	h, err := newhost(ctx)
	if err != nil {
		return nil, nil, err
	}
	n, err := node.New(ctx, h)
	if err != nil {
		return nil, nil, err
	}
	return n, h, nil
}

func newNodeWithWallet(ctx context.Context, w *wallet.Wallet) (*node.Node, error) {
	h, err := libp2p.New(ctx, libp2p.Identity(w), libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
	if err != nil {
		return nil, err
	}
	n, err := node.New(ctx, h)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func newSendCmd() *cobra.Command {
	var (
		to  string
		fee uint64
	)
	c := &cobra.Command{
		Use:   "send <amount>",
		Short: "Send tokens to an address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if to == "" {
				return errors.New("no address to send tokens to")
			}
			amount, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			w, err := openWallet(config.GetString("wallet"))
			if err != nil {
				return err
			}
			store, err := blockstore.Open(blocksDir())
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			h, err := libp2p.New(
				ctx,
				libp2p.Identity(w),
				libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
			)
			if err != nil {
				return err
			}
			n, err := node.FullNode(ctx, h, store)
			if err != nil {
				return err
			}
			if err = n.Start(); err != nil {
				return err
			}
			time.Sleep(time.Millisecond * 250) // wait for discovery

			tx := block.NewTransaction()
			err = tx.Append(block.BuildUTXOSet(store.Iter()),
				block.TxDesc{
					From:   w,
					To:     key.NewReceiver(to),
					Amount: uint64(amount) - fee,
				},
			)
			log.Infof("sending tx %x", tx.ID)
			if err != nil {
				return err
			}
			return n.BroadcastTx(tx)
		},
	}
	c.Flags().StringVar(&to, "to", to, "address of token recipient")
	c.Flags().Uint64VarP(&fee, "fee", "f", fee, "add a fee to the transaction")
	return c
}

func newSayCmd() *cobra.Command {
	c := &cobra.Command{
		Use:           "say [message...]",
		Short:         "Send a message to the network.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return newCommandErr("no messages", cmd)
			}
			ctx := context.Background()
			h, err := libp2p.New(ctx, libp2p.NoListenAddrs)
			if err != nil {
				return err
			}
			fmt.Println(h.ID().Pretty())
			ch, err := p2p.DiscoverOnce(h.ID(), node.DiscoveryTag)
			if err != nil {
				return err
			}
			for pa := range ch {
				go func(peer peer.AddrInfo) {
					fmt.Println("connecting to", peer.ID.Pretty())
					if err := h.Connect(ctx, peer); err != nil {
						log.Printf("Could not connect to %s: %v", peer.ID.Pretty(), err)
						return
					}
					s, err := h.NewStream(ctx, peer.ID, "/msg")
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

func newPeersCmd() *cobra.Command {
	c := &cobra.Command{
		Use:           "peers",
		Short:         "Get info on the peers connected",
		Aliases:       []string{"p"},
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			walletname := config.GetString("wallet")
			w, err := openWallet(walletname)
			if err != nil {
				log.WithError(err).Warnf("could not open wallet %s", walletname)
				w = wallet.New()
			}

			host, err := libp2p.New(
				ctx,
				libp2p.Identity(w),
				libp2p.NoListenAddrs,
			)
			if err != nil {
				return errors.Wrap(err, "could not create host")
			}

			cmd.Println("me:", host.ID().Pretty())
			ch, err := p2p.DiscoverOnce(host.ID(), node.DiscoveryTag)
			if err != nil {
				return err
			}
			for pa := range ch {
				hostname, _ := maLookupAddr(pa.Addrs[0])
				cmd.Printf("{%s: %v, %s}\n", pa.ID, pa.Addrs, hostname)
			}
			return nil
		},
	}
	return c
}

func newHitCmd() *cobra.Command {
	var hit protocol.ID
	var grpcReq bool
	c := &cobra.Command{
		Use:           "hit",
		Short:         "Make calls to any node endpoint and return the first successful response",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			host, err := newhost(ctx)
			if err != nil {
				return err
			}
			fmt.Println(host.ID().Pretty())

			ctx, cancel := context.WithTimeout(ctx, time.Second*5)
			defer cancel()
			if len(args) > 0 && hit == "" {
				hit = protocol.ID(args[0])
				args = args[1:]
			}
			if hit == "" {
				return errors.New("no endpoint to hit")
			}

			if grpcReq {
				var conn *grpc.ClientConn
				conn, err = grpc.Dial("", grpc.WithInsecure())
				if err != nil {
					panic(err)
				}
				client := node.NewBlockStoreClient(conn)
				blkMsg, err := client.GetBlock(ctx, &node.BlockReq{Hash: []byte("no")})
				if err != nil {
					panic(err)
				}
				fmt.Println(blkMsg)
			}

			return hitNetwork(ctx, host, hit)
		},
	}
	return c
}

func hitNetwork(ctx context.Context, host host.Host, proto protocol.ID) error {
	type errorResp struct {
		Error string `json:"error"`
	}
	ch, err := p2p.DiscoverOnce(host.ID(), node.DiscoveryTag)
	if err != nil {
		return err
	}
	for pa := range ch {
		if err := host.Connect(ctx, pa); err != nil {
			log.Error("Could not connect:", err)
			continue
		}
		s, err := host.NewStream(ctx, pa.ID, proto)
		if err != nil {
			return errors.Wrap(err, "could not create stream")
		}
		buf := &bytes.Buffer{}
		io.Copy(buf, s)
		s.Close()
		e := errorResp{}
		json.Unmarshal(buf.Bytes(), &e)
		if e.Error != "" {
			continue
		}
		fmt.Printf("%s\n", buf.String())
		return nil
	}
	return fmt.Errorf("could not find '%s'", proto)
}

func newRPCCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "rpc",
		Short: "Make rpc calls to the network",
		// Run: func(cmd *cobra.Command, args []string) { cmd.Usage() },
	}
	c.AddCommand(
		newRCPHeadCmd(),
		newRPCBaseCmd(),
		newRPCBlockCmd(),
		newRPCTxCmd(),
		&cobra.Command{
			Use: "test",
			RunE: func(cmd *cobra.Command, args []string) error {
				ctx, cancel := context.WithCancel(cmd.Context())
				defer cancel()
				host, err := newhost(ctx)
				if err != nil {
					return err
				}
				defer host.Close()
				ch, err := (&p2p.Discovery{
					Host:     host,
					Service:  node.DiscoveryTag,
					Duration: node.DiscoveryTime,
				}).StartContext(ctx)
				if err != nil {
					return nil
				}
				for addr := range ch {
					if addr.ID == host.ID() || host.Network().Connectedness(addr.ID) == network.Connected {
						continue
					}
					err = host.Connect(ctx, addr)
					if err != nil {
						return err
					}
					conns := host.Network().ConnsToPeer(addr.ID)
					fmt.Println(addr.ID, conns)
				}
				return nil
			},
		},
	)
	return c
}

type hexbytes []byte

func (hb hexbytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(hb))
}

// same as block.Block but with pretty json marshalling
type displayBlock struct {
	Data         []byte
	Nonce        int64
	Hash         hexbytes
	PrevHash     hexbytes
	Transactions []*block.Transaction
}

// assumes not running full node with discovery service
func askFirstGRPCPeer(
	ctx context.Context,
	host host.Host,
	fn func(peer.AddrInfo, node.BlockStoreClient) error,
) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := p2p.DiscoverOnce(host.ID(), node.DiscoveryTag)
	if err != nil {
		return nil
	}
	for addr := range ch {
		err := host.Connect(ctx, addr)
		if err != nil {
			continue
		}
		conn, err := grpc.DialContext(
			ctx, addr.ID.Pretty(),
			grpc.WithContextDialer(node.GRPCDialer(host, node.GRPCProto)),
			grpc.WithInsecure(),
		)
		if err != nil {
			continue
		}
		client := node.NewBlockStoreClient(conn)
		if err = fn(addr, client); err == nil {
			conn.Close()
			return nil
		}
		conn.Close()
	}
	err = errors.New("no response from any peers")
	return err
}

func newRCPHeadCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "head",
		Short: "Get the head block",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			host, err := newhost(ctx)
			if err != nil {
				return err
			}
			return askFirstGRPCPeer(
				ctx, host,
				func(addr peer.AddrInfo, client node.BlockStoreClient) error {
					blkmsg, err := client.Head(ctx, &node.Empty{})
					if err != nil {
						log.WithFields(log.Fields{
							"peer":  addr.ID,
							"error": err,
						}).Trace("did not find block here")
						return err
					}
					b, err := json.MarshalIndent(&blkmsg, "", "  ")
					if err != nil {
						return err
					}
					cmd.Printf("%s\n", b)
					return nil
				})
		},
	}
	return c
}

func newRPCBaseCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "base",
		Short: "Get the base of the chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			host, err := newhost(ctx)
			if err != nil {
				return err
			}
			return askFirstGRPCPeer(
				ctx, host,
				func(addr peer.AddrInfo, client node.BlockStoreClient) error {
					blkmsg, err := client.Base(ctx, &node.Empty{})
					if err != nil {
						log.WithFields(log.Fields{
							"peer":  addr.ID,
							"error": err,
						}).Trace("did not find genesis block here")
						return err
					}
					b, err := json.MarshalIndent(&blkmsg, "", "  ")
					if err != nil {
						return err
					}
					cmd.Printf("%s\n", b)
					return nil
				},
			)
		},
	}
	return c
}

func grpcClient(ctx context.Context) (node.BlockStoreClient, error) {
	host, err := newhost(ctx)
	if err != nil {
		return nil, err
	}
	addr := getFirstPeer(host)
	host.Connect(ctx, *addr)
	conn, err := grpc.DialContext(
		ctx, addr.ID.Pretty(),
		grpc.WithContextDialer(node.GRPCDialer(host, node.GRPCProto)),
		grpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}
	return node.NewBlockStoreClient(conn), nil
}

func newRPCBlockCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "block <hash>",
		Short: "Get a block from the network",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			hash, err := tryDecode(args[0],
				base64.RawStdEncoding.DecodeString,
				base64.StdEncoding.DecodeString,
				base64.RawURLEncoding.DecodeString,
				hex.DecodeString,
			)
			if err != nil {
				return err
			}
			host, err := newhost(ctx)
			if err != nil {
				return err
			}
			return askFirstGRPCPeer(ctx, host, func(addr peer.AddrInfo, client node.BlockStoreClient) error {
				blkmsg, err := client.GetBlock(ctx, &node.BlockReq{Hash: hash})
				if err != nil {
					return err
				}
				b, err := json.MarshalIndent(blkmsg, "", "  ")
				if err != nil {
					return err
				}
				cmd.Printf("%s\n", b)
				return nil
			})
		},
	}
	return c
}

func newRPCTxCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "tx <hash>",
		Short: "Get a transaction from the network",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hash, err := tryDecode(args[0],
				base64.RawStdEncoding.DecodeString,
				base64.StdEncoding.DecodeString,
				base64.RawURLEncoding.DecodeString,
				hex.DecodeString,
			)
			if err != nil {
				return err
			}
			cmd.Printf("%x\n", hash)
			return nil
		},
	}
	return c
}

func newTestCmd(conf *Config) *cobra.Command {
	c := &cobra.Command{
		Use:    "test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(config.GetString("config"))
			fmt.Println(config.GetString("ConfigDir"))
			fmt.Printf("%+v\n", conf)
			return nil
		},
	}
	return c
}

func getFirstPeer(h host.Host) *peer.AddrInfo {
	ch, err := p2p.DiscoverOnce(h.ID(), node.DiscoveryTag)
	if err != nil {
		return nil
	}
	for p := range ch {
		if p.ID != h.ID() {
			return &peer.AddrInfo{ID: p.ID, Addrs: p.Addrs}
		}
	}
	return nil
}
