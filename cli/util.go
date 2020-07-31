package cli

import (
	"os"
	"path/filepath"

	"github.com/harrybrwn/go-ledger/internal/config"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"github.com/spf13/cobra"
)

var configDirName = "blk"

func configDir() string {
	var dir string
	if dir = os.Getenv("BLK_CONFIG"); dir != "" {
		return dir
	}
	if dir = os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, configDirName)
	}
	if dir = os.Getenv("HOME"); dir != "" {
		return filepath.Join(dir, "."+configDirName)
	}
	if dir = os.Getenv("USERPROFILE"); dir != "" {
		return filepath.Join(dir, "."+configDirName)
	}
	return "./.blk"
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
	return err
}

func cliPreRun(cmd *cobra.Command, args []string) error {
	err := config.ReadConfigFile()
	if err == config.ErrNoConfigFile {
		os.OpenFile(config.FileUsed(), os.O_CREATE, 0600)
	} else if err != nil {
		return err
	}
	lvl := config.GetString("loglevel")
	level, err := log.ParseLevel(lvl)
	if err != nil {
		defer log.Errorf("bad loglevel '%s'", lvl)
		level = log.WarnLevel
	}
	log.SetLevel(log.TraceLevel)
	log.AddHook(&writer.Hook{
		Writer:    os.Stdout,
		LogLevels: log.AllLevels[:level+1],
	})
	return nil
}
