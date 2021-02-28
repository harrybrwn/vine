package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/harrybrwn/config"
	"github.com/harrybrwn/go-ledger/blockstore"
	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/harrybrwn/go-ledger/node"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/network"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newDaemonCmd() *cobra.Command {
	var (
		init bool
	)
	c := &cobra.Command{
		Use:           "daemon",
		Short:         "Start the daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(init)
		},
	}
	c.Flags().BoolVar(&init, "init", init, "initialize with default settings")
	return c
}

func runDaemon(init bool) error {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
	}

	if init {
		err := initConfigDir(config.GetString("config"))
		if err != nil {
			return err
		}
	}

	var (
		walletname = config.GetString("wallet")
		w          *wallet.Wallet
		err        error
	)
	if walletname == "default" {
		w = wallet.New()
		defer writeWallet("default", w)
	} else {
		w, err = openWallet(walletname)
		if err == nil {
			priv := cryptoPrivKey(w.PrivateKey())
			opts = append(opts, libp2p.Identity(priv))
		} else {
			log.WithError(err).Warn("could not open wallet")
			w = wallet.New()
		}
	}

	host, err := libp2p.New(ctx, opts...)
	if err != nil {
		return err
	}
	defer host.Close()
	termSigs := make(chan os.Signal)
	signal.Notify(termSigs, os.Interrupt, syscall.SIGTERM)

	// for testing
	host.SetStreamHandler("/msg", func(s network.Stream) {
		buf := new(bytes.Buffer)
		io.Copy(buf, s)
		log.Info(buf.String())
	})

	pid := os.Getpid()
	log.WithFields(log.Fields{
		"pid": pid, "node": host.ID().Pretty(),
	}).Infof("Starting full node")

	store, err := blockstore.Open(blocksDir())
	if err != nil {
		return err
	}
	fullnode, err := node.FullNode(ctx, host, store)
	if err != nil {
		return err
	}

	defer func() {
		if err = fullnode.Close(); err != nil {
			log.WithError(err).Warning("failed to close node")
		}
		if err = store.Close(); err != nil {
			log.WithError(err).Error("could not close block store")
		} else {
			time.Sleep(time.Second / 2) // hey man, this makes it look cool ok, don't judge
			log.Info("Graceful shutdown successful.")
		}
	}()

	err = fullnode.Start()
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-termSigs:
		fmt.Print("\r") // hide the '^C'
		log.Info("Shutting down...")
		time.Sleep(time.Second / 4) // hey man, this makes it look cool ok, don't judge
		return nil
	}
}
