package cli

import (
	"os"
	"path/filepath"
)

var configDirName = "blk"

func configDir() string {
	var dir string
	if dir = os.Getenv("BLK_CONFIG"); dir != "" {
		return filepath.Join(dir, configDirName)
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

func mkdir(d string) error {
	err := os.Mkdir(d, 0700)
	if os.IsExist(err) {
		return nil
	}
	return err
}
