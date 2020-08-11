package cli

import (
	"io/ioutil"
	stdlog "log"
	"os"
	"path/filepath"
	"time"

	"github.com/harrybrwn/go-ledger/internal/config"
	"github.com/harrybrwn/go-ledger/internal/logging"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config is the command line configuration structure
type Config struct {
	Wallet string `yaml:"wallet" default:"default"`
	Editor string `yaml:"editor" env:"EDITOR"`
	// LogLevel will set the log level for all logs that are
	// written to standard out
	LogLevel string `yaml:"loglevel" default:"info"`
	NoColor  bool   `yaml:"nocolor"`
	// Config is the config directory used for the cli
	Config string `yaml:"config" env:"BLK_CONFIG"`
}

// NewBLK returns a new 'blk' root command
func NewBLK(version string) *cobra.Command {
	config.AddPath("$BLK_CONFIG")
	config.AddDefaultDirs("blk")
	config.SetFilename("config.yml")
	config.SetType("yaml")

	conf := &Config{}
	config.SetConfig(conf)
	log.SetReportCaller(false)

	err := config.ReadConfigFile()
	dir := config.DirUsed()
	if err == config.ErrNoConfigFile {
		if err = mkdir(dir); err != nil {
			log.WithError(err).Errorf("could not create config directory '%s'", config.DirUsed())
		}
		f, e := os.OpenFile(config.FileUsed(), os.O_CREATE, 0600)
		f.Close()
		err = e
	}

	c := &cobra.Command{
		Use:   "blk",
		Short: "blk is a tool for managing a local blockchain network",
		Long: `blk is a tool for managing a local blockchain network.

This is in very early stages of development and a public node
should not be run. Trade currency on this blockchain at your own
risk, as of 2020 there is a high risk of being overpowered by a
51% attack.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return cliPreRun(dir, conf)
		},
		PersistentPostRunE: func(*cobra.Command, []string) error { return nil },
	}

	flags := c.PersistentFlags()
	flags.StringVar(&conf.LogLevel, "loglevel", conf.LogLevel, "set the app's logging level")
	flags.StringVarP(&conf.Wallet, "wallet", "w", conf.Wallet, "current wallet to use")
	flags.StringVarP(&conf.Config, "config", "c", conf.Config, "set the app's config directory")
	flags.BoolVar(&conf.NoColor, "nocolor", conf.NoColor, "disable all terminal colors")

	c.SetHelpTemplate(commandTemplate)
	c.AddCommand(
		newConfigCmd(),
		newLogCmd(),
		newCompletionCmd(),
		newInitBlockStoreCmd(),
		newWalletCmd(),

		newDaemonCmd(),
		newSyncCmd(),
		newSendCmd(),
		newPeersCmd(),

		newTestCmd(),
	)
	return c
}

// LogFile is the command line program log file
var LogFile = &lumberjack.Logger{
	Filename:   filepath.Join(os.TempDir(), "blk.log"),
	MaxSize:    25,  // megabytes
	MaxBackups: 10,  // number of spare files
	MaxAge:     365, // days
	Compress:   false,
}

func cliPreRun(dir string, conf *Config) error {
	LogFile.Filename = filepath.Join(dir, "blk.log")

	var format log.Formatter = &log.TextFormatter{
		ForceColors:            !conf.NoColor,
		DisableColors:          conf.NoColor,
		DisableLevelTruncation: true,
		DisableQuote:           true,
		FullTimestamp:          true,
		TimestampFormat:        time.Stamp,
		PadLevelText:           false,
	}
	format = &logging.PrefixedFormatter{
		TimeFormat: time.RFC3339,
		Prefix:     "",
	}
	stdlog.SetOutput(LogFile)
	log.SetOutput(ioutil.Discard)
	log.SetFormatter(format)
	log.AddHook(logging.NewLogFileHook(LogFile, format))

	level, err := log.ParseLevel(config.GetString("loglevel"))
	if err != nil {
		defer log.Errorf("bad loglevel '%s'", conf.LogLevel)
		level = log.WarnLevel
	}
	log.SetLevel(log.TraceLevel)
	log.AddHook(&logging.Hook{
		Writer:    os.Stdout,
		LogLevels: log.AllLevels[:level+1],
	})
	return nil
}

var commandTemplate = `Usage:
{{if .Runnable}}
	{{.UseLine}}{{end}}{{if gt (len .Aliases) 0}}

Aliases:
	{{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
	{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:

{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:
{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
