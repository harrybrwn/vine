package cli

import (
	"io/ioutil"
	stdlog "log"
	"os"
	"path/filepath"

	"github.com/harrybrwn/go-ledger/internal/config"
	"github.com/harrybrwn/go-ledger/internal/logging"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config is the command line configuration structure
type Config struct {
	Wallet string `yaml:"wallet"`
	Editor string `yaml:"editor" env:"EDITOR"`
	// LogLevel will set the log level for all logs that are
	// written to standard out
	LogLevel string `yaml:"loglevel" default:"warn"`
}

// NewBLK returns a new 'blk' root command
func NewBLK() *cobra.Command {
	conf := new(Config)
	dir := configDir()
	config.AddPath(dir)
	config.SetFilename("config.yml")
	config.SetType("yaml")
	config.SetStruct(conf)

	LogFile.Filename = filepath.Join(dir, "blk.log")
	stdlog.SetOutput(LogFile)
	log.SetOutput(ioutil.Discard)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:            true,
		DisableColors:          false,
		DisableLevelTruncation: true,
	})
	log.AddHook(logging.NewLogFileHook(LogFile, &log.TextFormatter{
		ForceColors:            false,
		DisableColors:          true,
		DisableLevelTruncation: true,
	}))

	c := &cobra.Command{
		Use:   "blk",
		Short: "blk is a tool for managing a local blockchain network",
		Long: `blk is a tool for managing a local blockchain network.

This is in very early stages of development and a public node
should not be run. Trade currency on this blockchain at your own
risk, as of 2020 there is a high risk of being overpowered by a
51% attack.`,
		SilenceUsage:  false,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		PersistentPreRunE: cliPreRun,
	}
	flags := c.PersistentFlags()
	flags.StringVar(&conf.LogLevel, "loglevel", conf.LogLevel, "set the app's logging level")
	flags.StringVarP(&conf.Wallet, "wallet", "w", conf.Wallet, "current wallet to use")

	c.AddCommand(
		newConfigCmd(),
		newInitBlockStoreCmd(),
		newWalletCmd(),

		newDaemonCmd(),
		newSendCmd(),
		newSyncCmd(),

		newTestCmd(),
	)
	return c
}

var (
	// LogFile is the command line program log file
	LogFile = &lumberjack.Logger{
		Filename:   filepath.Join(os.TempDir(), "blk.log"),
		MaxSize:    25,  // megabytes
		MaxBackups: 10,  // number of spare files
		MaxAge:     365, // days
		Compress:   false,
	}
)

// NewBLKMine returns a new 'blkmine' root command
func NewBLKMine() *cobra.Command {
	return &cobra.Command{
		Use:           "blkmine",
		SilenceErrors: false,
		SilenceUsage:  false,
	}
}
