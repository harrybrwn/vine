package internal

import (
	"errors"
	"io"

	"github.com/spf13/cobra"
)

// GenCompletion will write a command completion script to the writer
// given the shell name
func GenCompletion(root *cobra.Command, w io.Writer, shell string) error {
	switch shell {
	case "zsh":
		return root.GenZshCompletion(w)
	case "ps", "powershell":
		return root.GenPowerShellCompletion(w)
	case "bash":
		return root.GenBashCompletion(w)
	case "fish":
		return root.GenFishCompletion(w, false)
	}
	return errors.New("unknown shell type")
}
