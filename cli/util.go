package cli

import (
	"os"
	"path/filepath"
)

var (
	configDirName = "blk"
)

func configDir() string {
	var dir string
	if dir = os.Getenv("BLK_CONFIG"); dir != "" {
		return dir
	} else if dir = os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		dir = filepath.Join(dir, configDirName)
	} else if dir = os.Getenv("HOME"); dir != "" {
		dir = filepath.Join(dir, "."+configDirName)
	} else if dir = os.Getenv("USERPROFILE"); dir != "" {
		dir = filepath.Join(dir, "."+configDirName)
	}
	if dir == "" {
		dir = "./.blk"
	}
	return dir
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
