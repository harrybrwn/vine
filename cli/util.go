package cli

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/harrybrwn/config"
	"github.com/harrybrwn/vine/key/wallet"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/nsf/termbox-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const (
	configDirName = "vine"
)

func initConfigDir(confdir, blockdir string) (err error) {
	if err = mkdir(confdir); err != nil {
		return err
	}
	if err = os.MkdirAll(blockdir, 0700); err != nil {
		return err
	}
	if err = mkdir(filepath.Join(confdir, "wallets")); err != nil {
		return err
	}
	return nil
}

func configDir() string {
	var dir string
	if dir = os.Getenv("VINE_CONFIG"); dir != "" {
		return dir
	} else if dir = os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		dir = filepath.Join(dir, configDirName)
	} else if dir = os.Getenv("HOME"); dir != "" {
		dir = filepath.Join(dir, "."+configDirName)
	} else if dir = os.Getenv("USERPROFILE"); dir != "" {
		dir = filepath.Join(dir, "."+configDirName)
	}
	if dir == "" {
		dir = "./.vine"
	}
	return dir
}

func blocksDir() string {
	dir, err := config.GetStringErr("data")
	if err != nil {
		dir = "blocks"
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	return filepath.Join(config.GetString("config"), dir)
}

func cryptoPrivKey(k *ecdsa.PrivateKey) crypto.PrivKey {
	priv, _, err := crypto.ECDSAKeyPairFromKey(k)
	if err != nil {
		return nil
	}
	return priv
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

type usable interface {
	UseLine() string
	UsageString() string
}

func newCommandErr(msg string, cmd usable) error {
	return &CommandError{Msg: msg, Use: cmd.UseLine()}
}

// CommandError is an error returned by cli commands
type CommandError struct {
	Msg, Use string
}

func (ce *CommandError) Error() string {
	return ce.Msg
}

func mkdir(d string) error {
	err := os.Mkdir(d, 0700)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not create %s: %v", d, err)
	}
	return nil
}

func maLookupAddr(maddr multiaddr.Multiaddr) (string, error) {
	addr, err := manet.ToNetAddr(maddr)
	var ip net.IP
	switch a := addr.(type) {
	case *net.IPNet:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	case *net.UnixAddr:
		ip = net.IP(a.Name)
	default:
		return "", errors.New("unknown net.Addr type")
	}
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return "", err
	}
	if len(names) < 1 {
		return "", errors.New("no hostname found")
	}
	if len(names) > 1 {
		return names[0], errors.New("too many hostnames found")
	}
	return names[0], nil
}

func tryDecode(s string, decoders ...func(string) ([]byte, error)) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	for _, dec := range decoders {
		b, err = dec(s)
		if err == nil {
			return b, nil
		}
	}
	return nil, err
}

func hideFlagNames(set *pflag.FlagSet, names ...string) {
	for _, n := range names {
		set.MarkHidden(n)
	}
}

var allLogLevels = allLogLevelsStr()

func allLogLevelsStr() []string {
	s := make([]string, len(log.AllLevels))
	for i, l := range log.AllLevels {
		s[i] = l.String()
	}
	return s
}

// use like this...
//
//  _, cancel := context.WithCancel()
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

func loggableHash(h []byte) []interface{} {
	return []interface{}{h[:5], h[len(h)-3:]}
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
