package cli

import (
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/harrybrwn/config"
	"github.com/harrybrwn/mdns"
	"github.com/harrybrwn/vine/internal"
	"github.com/harrybrwn/vine/internal/logging"
	"github.com/harrybrwn/vine/key/wallet"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/pkg/errors"
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
	Config string `yaml:"config" env:"VINE_CONFIG"`

	// Data directory (defaults to the same as the config dir)
	Data string `yaml:"data"`
}

// GlobalFlags are the cli's global persisant flags
type GlobalFlags struct {
	Silent  bool
	mdnslog bool
}

// Flags are the GLOBAL flags... someone help me... why am i using globals
var Flags GlobalFlags

// New returns a new 'vine' root command
func New() *cobra.Command {
	config.AddPath("$VINE_CONFIG")
	config.SetFilename("config.yml")
	config.SetType("yaml")

	conf := &Config{}
	config.SetConfig(conf)
	log.SetReportCaller(false)

	if conf.Config != "" {
		config.AddPath(conf.Config)
	}
	config.AddUserConfigDir("vine")
	config.InitDefaults()

	dir := config.DirUsed()
	err := config.ReadConfigFile()
	if err == config.ErrNoConfigFile {
		if err = mkdir(dir); err != nil {
			log.WithError(err).Errorf("could not create config directory '%s'", config.DirUsed())
		}
		f, e := os.OpenFile(config.FileUsed(), os.O_CREATE, 0600)
		f.Close()
		err = e
	}
	if config.IsEmpty("config") {
		conf.Config = dir
	}

	var (
		configdir string
		trace     bool
		globals   = &Flags

		cpuprof, memprof bool
	)

	c := &cobra.Command{
		Use:   "vine",
		Short: "vine is a tool for managing a local blockchain network",
		Long: `vine is a tool for managing a local blockchain network.

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
			if trace {
				conf.LogLevel = "trace"
			}
			if configdir != "" {
				conf.Config = configdir
				config.ReadConfigFromFile(filepath.Join(configdir, "config.yml"))
			}
			return cliPreRun(conf, &Flags, &configdir)(cmd, args)
		},
	}

	flags := c.PersistentFlags()
	flags.StringVarP(&conf.LogLevel, "loglevel", "l", conf.LogLevel, "set the app's logging level")
	flags.BoolVarP(&globals.Silent, "silent", "s", globals.Silent, "do not print log messages to stdout")
	flags.StringVarP(&conf.Wallet, "wallet", "w", conf.Wallet, "current wallet to use")
	flags.StringVarP(&configdir, "config", "c", configdir, "set the app's config directory")
	flags.BoolVar(&conf.NoColor, "nocolor", conf.NoColor, "disable all terminal colors")

	flags.BoolVarP(&trace, "trace", "t", trace, "")
	flags.BoolVar(&globals.mdnslog, "mdnslog", globals.mdnslog, "")
	flags.BoolVar(&cpuprof, "cpuprof", cpuprof, "")
	flags.BoolVar(&memprof, "memprof", memprof, "")
	hideFlagNames(flags, "trace", "mdnslog", "cpuprof", "memprof")

	c.RegisterFlagCompletionFunc("loglevel", func(
		*cobra.Command, []string, string,
	) ([]string, cobra.ShellCompDirective) {
		return allLogLevels, cobra.ShellCompDirectiveNoSpace
	})

	c.SetHelpTemplate(config.IndentedCobraHelpTemplate)
	c.AddCommand(
		newConfigCmd(),
		newVersionCmd(),
		logging.NewLogCmd(LogFile),
		newCompletionCmd(),
		newWalletCmd(),

		newChainCmd(),
		newDaemonCmd(&Flags),
		newSendCmd(),
		newHitCmd(),
		newSayCmd(),
		newPeersCmd(),
		newRPCCmd(),

		newTestCmd(),
	)
	return c
}

var (
	version = "dev"
	date    string
	commit  string
	hash    string
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Show the command version",
		Aliases: []string{"v"},
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			if version == "dev" {
				cmd.Printf("%s development version\n", root.Name())
				return nil
			}
			cmd.Printf("%s version %s\n", root.Name(), version)
			cmd.Printf("date:   %s\n", date)
			cmd.Printf("commit: %s\n", commit)
			if hash != "" {
				cmd.Printf("hash:   %s\n", hash)
			}
			return nil
		},
	}
}

// StatusError is an error that
// carries an exit status.
type StatusError struct {
	Msg  string
	Code int
}

func (se *StatusError) Error() string {
	return se.Msg
}

// LogFile is the command line program log file
var LogFile = &lumberjack.Logger{
	Filename:   filepath.Join(os.TempDir(), "vine-debug.log"),
	MaxSize:    500, // megabytes
	MaxBackups: 10,  // number of spare files
	MaxAge:     365, // days
	Compress:   false,
}

func cliPreRun(conf *Config, globals *GlobalFlags, dir *string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if (*dir) != "" {
			conf.Config = *dir
		}
		if globals.Silent {
			globals.mdnslog = false
		}

		// Set the actual filename
		LogFile.Filename = filepath.Join(conf.Config, "debug.log")
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
		stdlog.SetOutput(LogFile) // for other packages
		log.SetOutput(io.Discard)
		log.SetFormatter(format)
		log.AddHook(logging.NewLogFileHook(LogFile, format))

		level, err := log.ParseLevel(config.GetString("loglevel"))
		if err != nil {
			defer log.Errorf(
				"bad loglevel '%s' use (%v)",
				conf.LogLevel,
				strings.Join(allLogLevelsStr(), "|"),
			)
			level = log.InfoLevel
		}

		// The logger writes to the log file
		// by default so we want all levels.
		log.SetLevel(log.TraceLevel)

		// We add a logging hook in order to
		// log to stdout.
		stdouthook := &logging.Hook{
			Writer:    os.Stdout,
			LogLevels: log.AllLevels[:level+1],
		}
		// This will prevent logging to stdout
		if !globals.Silent {
			log.AddHook(stdouthook)
		}

		// Copy the logger and change it for the mdns package
		mdns.SetLogger(*log.StandardLogger())
		mdnslog := mdns.Logger()
		// Reset the logging hooks because this is how
		// we disable different logging streams
		mdnslog.Hooks = make(log.LevelHooks)
		mdnslog.Formatter = &logging.PrefixedFormatter{
			TimeFormat: time.RFC3339,
			Prefix:     "[mdns]",
		}
		mdnslog.AddHook(logging.NewLogFileHook(LogFile, mdnslog.Formatter))
		// If we want to write mdns logs to stdout
		// then we add the stdout hook
		if globals.mdnslog {
			mdnslog.AddHook(stdouthook)
		}
		return nil
	}
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
				id, _ := peer.IDFromPrivateKey(w)
				fmt.Printf("%s:\n\tpeer id: %s\n\taddress: %x\n\n", arg, id.Pretty(), w.Address())
			}
			return nil
		},
	}

	flags := c.Flags()
	flags.StringVarP(&delete, "delete", "d", delete, "Delete a wallet key pair")

	c.AddCommand(&cobra.Command{
		Use:     "gen-pair <name>",
		Short:   "Generate a new public-private key pair",
		Aliases: []string{"gen"},
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

func newConfigCmd() *cobra.Command {
	var edit, file, dir bool
	c := &cobra.Command{
		Use:     "config",
		Short:   "Manage program configuration",
		Aliases: []string{"conf"},
		RunE: func(cmd *cobra.Command, args []string) error {
			confdir := config.GetString("config")
			var f string
			if confdir == "" {
				f = config.FileUsed()
			} else {
				f = filepath.Join(confdir, "config.yml")
			}
			if file {
				fmt.Println(f)
				return nil
			}
			if dir {
				if confdir == "" {
					fmt.Println(config.DirUsed())
				} else {
					fmt.Println(confdir)
				}
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
			return internal.GenCompletion(root, out, args[0])
		},
	}
}

func init() {
	cobra.AddTemplateFunc("indent", indent)
}

func indent(s string) string {
	parts := strings.Split(s, "\n")
	for i := range parts {
		parts[i] = "    " + parts[i]
	}
	return strings.Join(parts, "\n")
}
