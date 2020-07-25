package cli

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newWalletCmd() *cobra.Command {
	var delete bool
	c := &cobra.Command{
		Use:   "wallet",
		Short: "Manage public and private keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			walletDir := filepath.Join(configDir(), "wallets")
			if len(args) == 0 {
				files, err := ioutil.ReadDir(walletDir)
				if err != nil {
					return err
				}
				for _, f := range files {
					args = append(args, f.Name())
				}
			}

			var (
				filename string
				wlt      *wallet.Wallet = new(wallet.Wallet)
			)
			for _, arg := range args {
				filename = filepath.Join(walletDir, arg)
				if delete {
					if err := os.Remove(filename); err != nil {
						return err
					}
					continue
				}
				file, err := os.Open(filename)
				if err != nil {
					return err
				}
				if _, err = wlt.ReadFrom(file); err != nil {
					return err
				}
				cmd.Printf("%s: %s\n", arg, wlt.Address())
				if err = file.Close(); err != nil {
					return err
				}
			}
			return nil
		},
	}

	flags := c.Flags()
	flags.BoolVarP(&delete, "delete", "d", delete, "Delete a wallet key pair")

	c.AddCommand(
		&cobra.Command{
			Use:   "gen-pair <name>",
			Short: "Generate a new public-private key pair",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) < 1 {
					return errors.New("no wallet name given")
				}
				walletFile := filepath.Join(configDir(), "wallets", args[0])
				file, err := os.Create(walletFile)
				if err != nil {
					return errors.Wrap(err, "could not create wallet file")
				}
				wlt := wallet.New(wallet.Version1)
				_, err = wlt.WriteTo(file)
				return err
			},
		},
	)
	return c
}
