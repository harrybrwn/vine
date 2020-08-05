package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/harrybrwn/go-ledger/blockstore"
	"github.com/harrybrwn/go-ledger/internal/config"
	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/harrybrwn/go-ledger/node"
	"github.com/harrybrwn/go-ledger/p2p"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	p2pconfig "github.com/libp2p/go-libp2p/config"
	"github.com/pkg/errors"
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
		Use:   "peers",
		Short: "Get info on the peers connected",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			opts := []p2pconfig.Option{libp2p.NoListenAddrs}
			walletName := config.GetString("wallet")
			if walletName != "" {
				key, err := openKey(walletName)
				if err == nil {
					opts = append(opts, libp2p.Identity(key))
				} else {
					log.Warn(err)
				}
			}
			host, err := libp2p.New(ctx, opts...)
			if err != nil {
				return err
			}
			fmt.Println("me:", host.ID().Pretty())
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
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
	c := &cobra.Command{
		Use:    "test",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := []p2pconfig.Option{
				libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
			}
			walletName := config.GetString("wallet")
			if walletName != "" {
				key, err := openKey(walletName)
				if err == nil {
					opts = append(opts, libp2p.Identity(key))
				} else {
					log.Warn(err)
				}
			}

			ctx := context.Background()
			host, err := libp2p.New(ctx, opts...)
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

			for pa := range ch {
				if err := host.Connect(ctx, pa); err != nil {
					log.Error("Could not connect:", err)
					continue
				}
				s, err := host.NewStream(ctx, pa.ID, protocol.ID(hit))
				if err != nil {
					log.Error(err)
					continue
				}
				io.Copy(os.Stdout, s)
				s.Close()
				cancel()
				println()
				return nil
			}
			return nil
		},
	}
	return c
}

func newDaemonCmd() *cobra.Command {
	c := &cobra.Command{
		Use:           "daemon",
		Short:         "Start the daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			opts := []libp2p.Option{
				libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
			}
			walletname := config.GetString("wallet")
			if walletname != "" {
				key, err := openKey(walletname)
				if err == nil {
					opts = append(opts, libp2p.Identity(key))
				} else {
					log.Warn(err)
				}
			}

			host, err := libp2p.New(ctx, opts...)
			if err != nil {
				return err
			}
			defer host.Close()

			termSigs := make(chan os.Signal)
			signal.Notify(termSigs, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-termSigs
				fmt.Print("\r") // hide the '^C'
				log.Info("Shutting down...")

				host.Close()
				time.Sleep(time.Second) // hey man, this makes it look cool ok, don't judge

				log.Info("Graceful shutdown successful.")
				os.Exit(0)
			}()

			// for testing
			host.SetStreamHandler("/msg", func(s network.Stream) {
				buf := new(bytes.Buffer)
				io.Copy(buf, s)
				log.Info(buf.String())
			})

			pid := os.Getpid()
			fmt.Println(pid, host.ID())
			log.WithFields(log.Fields{
				"pid":  pid,
				"node": host.ID().Pretty(),
			}).Infof("Starting full node")

			store, err := blockstore.New(wallet.New(), filepath.Join(config.GetString("config"), "blocks"))
			if err != nil {
				return err
			}
			node, err := node.FullNode(ctx, host, store)
			if err != nil {
				return err
			}
			defer node.Close()

			select {
			case <-ctx.Done():
				host.Close()
				return nil
			}
		},
	}
	return c
}

func handleInterupt() {
}
