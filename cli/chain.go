package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/harrybrwn/config"
	"github.com/harrybrwn/vine/block"
	"github.com/harrybrwn/vine/blockstore"
	"github.com/harrybrwn/vine/internal/logging"
	"github.com/harrybrwn/vine/key/wallet"
	"github.com/harrybrwn/vine/node"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newChainCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "chain",
		Short: "Manage the local blockchain.",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := blockstore.Open(
				blocksDir(),
				blockstore.WithLogger(logging.Discard),
			)
			if err != nil {
				return err
			}
			var (
				b      []byte
				blocks = make([]*block.Block, 0)
				it     = store.Iter()
			)
			for {
				blk := it.Next()
				if blk == nil {
					break
				}
				blocks = append(blocks, blk)
				if block.IsGenisis(blk) {
					break
				}
			}
			b, err = json.MarshalIndent(blocks, "  ", "  ")
			if err != nil {
				return err
			}
			cmd.Printf("%s\n", b)
			return nil
		},
	}
	c.AddCommand(
		newSyncCmd(),
		newInitBlockStoreCmd(),
	)
	return c
}

func newSyncCmd() *cobra.Command {
	var (
		timeout = time.Millisecond * 250
	)
	c := &cobra.Command{
		Use:   "sync",
		Short: "Sync with the network.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var ctx = cmd.Context()
			host, err := newhost(ctx)
			if err != nil {
				return err
			}
			log.WithField("id", host.ID()).Info("Syncing to network")
			store, err := blockstore.Open(blocksDir())
			if err != nil {
				return err
			}
			defer store.Close()
			n, err := node.FullNode(ctx, host, store)
			if err != nil {
				return err
			}
			defer n.Close()
			if err = n.Start(); err != nil {
				return err
			}
			time.Sleep(timeout) // Sleep to let the node find peers TODO fix this

			blk, err := n.GetHeadBlock()
			if err != nil {
				return err
			}
			hashlog := log.WithFields(log.Fields{
				"hash": fmt.Sprintf("%x...%x", loggableHash(blk.Hash)...),
			})
			_, err = store.Get(blk.Hash)
			if err == nil {
				hashlog.Warn("already have this block")
				return nil
			}
			return store.Push(blk)
		},
	}

	c.Flags().DurationVarP(&timeout, "timeout", "i", timeout, "wait timeout")
	return c
}

func newInitBlockStoreCmd() *cobra.Command {
	var (
		address     string
		withGenesis bool
	)
	c := &cobra.Command{
		Use:           "init",
		Short:         "Initialize a new blockchain",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			confdir := config.GetString("config")
			storageDir := blocksDir()
			if err = initConfigDir(confdir, storageDir); err != nil {
				return err
			}

			var (
				name = config.GetString("wallet")
				w    *wallet.Wallet
			)
			if name == "" {
				return errors.New("no wallet")
			} else if name == "default" {
				w = wallet.New()
			} else {
				w, err = openWallet(name)
				if err != nil {
					return err
				}
			}
			defer writeWallet(name, w)

			if withGenesis {
				db, err := blockstore.Open(storageDir)
				if err != nil {
					return nil
				}
				defer func() {
					e := db.Close()
					if err == nil {
						err = e
					}
				}()
				// if the head block exists then return
				if hash := db.HeadHash(); hash != nil {
					return nil
				}
				blk := block.Genisis(block.Coinbase(w))
				return db.Push(blk)
			}
			err = blockstore.CreateEmpty(storageDir)
			if err != nil {
				return err
			}
			log.Trace("block database created")
			return nil
		},
	}
	flags := c.Flags()
	flags.StringVar(&address, "address", "", "Address name as it appears in the wallet")
	flags.BoolVar(&withGenesis, "genesis", false, "create a new chain with the genesis block")
	flags.MarkHidden("with-coinbase")
	return c
}
