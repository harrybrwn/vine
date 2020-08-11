package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/harrybrwn/go-ledger/internal/config"
	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/harrybrwn/go-ledger/node"
	"github.com/harrybrwn/go-ledger/p2p"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
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

func newSyncCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "sync",
		Short: "Sync with blockchains on the network.",
	}
	return c
}

func newPeersCmd() *cobra.Command {
	c := &cobra.Command{
		Use:           "peers",
		Short:         "Get info on the peers connected",
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
			priv := cryptoPrivKey(w.PrivateKey())

			host, err := libp2p.New(
				ctx,
				libp2p.Identity(priv),
				libp2p.NoListenAddrs,
			)
			if err != nil {
				return errors.Wrap(err, "could not create host")
			}

			fmt.Println("me:", host.ID().Pretty())
			ch, err := p2p.DiscoverOnce(host.ID(), node.DiscoveryTag)
			if err != nil {
				return err
			}

			for pa := range ch {
				fmt.Println(pa)
			}
			return nil
		},
	}
	return c
}

func newTestCmd() *cobra.Command {
	var hit string
	var gprcReq bool
	c := &cobra.Command{
		Use:           "test",
		Short:         "Make calls to any node endpoint and return the first successful response",
		Hidden:        true,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				walletname = config.GetString("wallet")
				w          *wallet.Wallet
				err        error
			)
			w, err = openWallet(walletname)
			if err != nil {
				log.WithError(err).Warn("could not open wallet")
				w = wallet.New()
			}
			priv := cryptoPrivKey(w.PrivateKey())

			ctx := context.Background()
			host, err := libp2p.New(ctx,
				libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
				libp2p.Identity(priv),
			)
			if err != nil {
				return err
			}
			fmt.Println(host.ID().Pretty())

			ctx, cancel := context.WithTimeout(ctx, time.Second*5)
			defer cancel()
			ch, err := p2p.DiscoverOnce(host.ID(), node.DiscoveryTag)
			if err != nil {
				return err
			}
			if len(args) > 0 && hit == "" {
				hit = args[0]
				args = args[1:]
			}
			if hit == "" {
				return errors.New("no endpoint to hit")
			}

			if gprcReq {
				var conn *grpc.ClientConn
				conn, err = grpc.Dial("", grpc.WithInsecure())
				if err != nil {
					panic(err)
				}
				client := node.NewGetBlockClient(conn)
				blkMsg, err := client.Block(ctx, &node.BlockReq{Hash: []byte("no")})
				if err != nil {
					panic(err)
				}
				fmt.Println(blkMsg)
			}

			type errorResp struct {
				Error string `json:"error"`
			}
			for pa := range ch {
				if err := host.Connect(ctx, pa); err != nil {
					log.Error("Could not connect:", err)
					continue
				}
				s, err := host.NewStream(ctx, pa.ID, protocol.ID(hit))
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
				cancel()
				fmt.Printf("%s\n", buf.String())
				return nil
			}
			return fmt.Errorf("could not find '%s'", hit)
		},
	}
	return c
}

func blocksDir() string {
	return filepath.Join(
		config.GetString("config"),
		"blocks",
	)
}

func cryptoPrivKey(k *ecdsa.PrivateKey) crypto.PrivKey {
	priv, _, err := crypto.ECDSAKeyPairFromKey(k)
	if err != nil {
		return nil
	}
	return priv
}
