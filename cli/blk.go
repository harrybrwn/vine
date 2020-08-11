package cli

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/harrybrwn/errs"
	"github.com/harrybrwn/go-ledger/block"
	"github.com/harrybrwn/go-ledger/blockstore"
	"github.com/harrybrwn/go-ledger/internal/config"
	"github.com/harrybrwn/go-ledger/key/wallet"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/nsf/termbox-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func initConfigDir(confdir string) (err error) {
	if err = mkdir(confdir); err != nil {
		return err
	}
	if err = mkdir(filepath.Join(confdir, "blocks")); err != nil {
		return err
	}
	if err = mkdir(filepath.Join(confdir, "wallets")); err != nil {
		return err
	}
	return nil
}

func newInitBlockStoreCmd() *cobra.Command {
	var (
		address     string
		withGenisis bool
	)
	c := &cobra.Command{
		Use:           "init",
		Short:         "Initialize a new blockchain",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			confdir := config.GetString("config")
			storageDir := filepath.Join(confdir, "blocks")
			if err = initConfigDir(confdir); err != nil {
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

			if withGenisis {
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
	flags.BoolVar(&withGenisis, "with-genisis", false, "create the data with a new coinbase transaction")
	flags.MarkHidden("with-coinbase")
	return c
}

func newWalletCmd() *cobra.Command {
	var delete string
	c := &cobra.Command{
		Use:   "wallet",
		Short: "Manage public and private keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			walletDir := filepath.Join(config.GetString("config"), "wallets")
			if len(args) == 0 {
				files, err := ioutil.ReadDir(walletDir)
				if err != nil {
					return err
				}
				for _, f := range files {
					args = append(args, f.Name())
				}
			}

			if delete != "" {
				filename := filepath.Join(walletDir, delete)
				return os.Remove(filename)
			}
			for _, arg := range args {
				w, err := openWallet(arg)
				if err != nil {
					return err
				}
				id, _ := peer.IDFromPrivateKey(w.PrivKey())
				fmt.Printf("%s: %s %x\n", arg, id.Pretty(), w.Address())
			}
			return nil
		},
	}

	flags := c.Flags()
	flags.StringVarP(&delete, "delete", "d", delete, "Delete a wallet key pair")

	c.AddCommand(&cobra.Command{
		Use:   "gen-pair <name>",
		Short: "Generate a new public-private key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("no wallet name given")
			}
			err := writeWallet(args[0], wallet.New())
			if err != nil {
				return errors.Wrap(err, "could not create wallet file")
			}
			return nil
		},
	})
	return c
}

func openKey(name string) (crypto.PrivKey, error) {
	file := filepath.Join(config.GetString("config"), "wallets", name)
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalECDSAPrivateKey(raw)
}

func openWallet(name string) (*wallet.Wallet, error) {
	walletfile := filepath.Join(config.GetString("config"), "wallets", name)
	file, err := os.Open(walletfile)
	if os.IsNotExist(err) {
		return wallet.New(), nil
	}
	if err != nil {
		return nil, err
	}
	wlt := &wallet.Wallet{}
	_, err = wlt.ReadFrom(file)
	if err != nil {
		file.Close()
		return nil, errors.Wrap(err, "failed to read wallet file")
	}
	return wlt, file.Close()
}

func writeWallet(name string, w *wallet.Wallet) error {
	dir := filepath.Join(config.GetString("config"), "wallets")
	os.MkdirAll(dir, 0700)
	file, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		log.WithError(err).Warn("could not create wallet file")
		return err
	}
	defer file.Close()
	_, err = w.WriteTo(file)
	return errors.Wrap(err, "could not write wallet to file")
}

func newConfigCmd() *cobra.Command {
	var edit, file, dir bool
	c := &cobra.Command{
		Use:     "config",
		Short:   "Manage program configuration",
		Aliases: []string{"conf"},
		RunE: func(cmd *cobra.Command, args []string) error {
			f := config.FileUsed()
			if file {
				fmt.Println(f)
				return nil
			}
			if dir {
				fmt.Println(filepath.Dir(f))
				return nil
			}

			if edit {
				if f == "" {
					return errors.New("no config file")
				}
				editor := config.GetString("editor")
				if editor == "" {
					return errors.New("no editor set (see $EDITOR)")
				}
				ex := exec.Command(editor, f)
				ex.Stdout = cmd.OutOrStdout()
				ex.Stderr = cmd.ErrOrStderr()
				ex.Stdin = cmd.InOrStdin()
				return ex.Run()
			}
			return cmd.Help()
		},
	}

	c.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Get a config variable",
		Run: func(cmd *cobra.Command, args []string) {
			for _, arg := range args {
				cmd.Println(config.Get(arg))
			}
		},
	})
	flags := c.Flags()
	flags.BoolVarP(&edit, "edit", "e", edit, "edit the configuration file")
	flags.BoolVarP(&file, "file", "f", file, "print the filepath of the configuration file")
	flags.BoolVarP(&dir, "dir", "d", dir, "print the path of the configuration folder")
	return c
}

func newLogCmd() *cobra.Command {
	var (
		file, reset bool
		less        bool
		num         int
		level       string
	)
	c := &cobra.Command{
		Use:           "logs",
		Short:         "Manage logs and log files",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if file {
				fmt.Println(LogFile.Filename)
				return nil
			}
			if reset {
				return os.Remove(LogFile.Filename)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var proc *exec.Cmd
			if less {
				proc = exec.CommandContext(ctx, "less", LogFile.Filename)
				proc.Stdout = cmd.OutOrStdout()
				return proc.Run()
			}
			proc = exec.CommandContext(ctx, "tail", "-F", LogFile.Filename, "-n", strconv.Itoa(num))
			proc.Stderr, proc.Stdin = cmd.ErrOrStderr(), cmd.InOrStdin()

			copy := io.Copy
			if config.GetBool("nocolor") {
				copy = copyNoColor
			}

			pipe, err := proc.StdoutPipe()
			if err != nil {
				return err
			}
			defer pipe.Close()
			if err = proc.Start(); err != nil {
				return err
			}

			go copy(os.Stdout, pipe)

			err = proc.Wait()
			if e, ok := err.(*exec.ExitError); ok && e.Error() == "signal: killed" {
				return proc.Process.Release()
			}
			return err
		},
	}

	flags := c.Flags()
	flags.BoolVarP(&file, "file", "f", file, "print the path of the logfile")
	flags.BoolVarP(&reset, "reset", "r", reset, "reset the logfile")
	flags.IntVarP(&num, "num", "n", 20, "number of lines of log file shown")
	flags.BoolVar(&less, "less", less, "run less to look at the logs")
	flags.StringVar(&level, "level", level, "filter out the logs at a certain level")
	return c
}

var colorRegex = regexp.MustCompile("[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]")

// yes, i copied this from io.Copy in the io package
func copyNoColor(dest io.Writer, src io.Reader) (written int64, err error) {
	return copyFilter(dest, src, func(b []byte) []byte {
		return colorRegex.ReplaceAll(b, nil)
	})
}

func copyFilter(dest io.Writer, src io.Reader, filter func([]byte) []byte) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dest.Write(filter(buf[0:nr]))
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			// TODO: predict what the difference will be here
			if nr != nw {
				err = io.ErrShortWrite
				// break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

// use like this...
//
//	if err := termbox.Init(); err != nil {
// 		return err
//	}
//	go keypoll(cancel)
func keypoll(cancel func()) {
	defer func() {
		cancel()
		termbox.Close()
	}()
	for {
		event := termbox.PollEvent()
		switch event.Type {
		case termbox.EventKey:
			if event.Ch == 'q' {
				return
			}
		case termbox.EventError:
			return
		}
	}
}

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion",
		Short: "Print a completion script to stdout.",
		Long: `Use the completion command to generate a script for shell
completion. Note: for zsh you will need to use the command
'compdef _edu edu' after you source the generated script.`,
		Example:   "$ source <(edu completion zsh)",
		ValidArgs: []string{"zsh", "bash", "ps", "powershell", "fish"},
		Aliases:   []string{"comp"},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			root := cmd.Root()
			out := cmd.OutOrStdout()
			if len(args) == 0 {
				return errors.New("no shell type given")
			}
			switch args[0] {
			case "zsh":
				return root.GenZshCompletion(out)
			case "ps", "powershell":
				return root.GenPowerShellCompletion(out)
			case "bash":
				return root.GenBashCompletion(out)
			case "fish":
				return root.GenFishCompletion(out, false)
			}
			return errs.New("unknown shell type")
		},
	}
}
