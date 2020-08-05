package cli

import (
	"path/filepath"

	"github.com/harrybrwn/go-ledger/blockstore"
	"github.com/harrybrwn/go-ledger/internal/config"
	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/spf13/cobra"
)

func newInitBlockStoreCmd() *cobra.Command {
	var (
		address string
	)
	c := &cobra.Command{
		Use:           "init",
		Short:         "Initialize a new blockchain",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			confdir := config.GetString("config")
			if err = mkdir(confdir); err != nil {
				return err
			}
			storageDir := filepath.Join(confdir, "blocks")
			if err = mkdir(storageDir); err != nil {
				return err
			}
			if err = mkdir(filepath.Join(confdir, "wallets")); err != nil {
				return err
			}
			user := wallet.New()
			store, err := blockstore.New(user, storageDir)
			if err != nil {
				return err
			}
			return store.Close()
		},
	}
	flags := c.Flags()
	flags.StringVar(&address, "address", "", "Address name as it appears in the wallet")
	return c
}
