package cli

import (
	"github.com/spf13/cobra"
)

// NewBLK returns a new 'blk' root command
func NewBLK() *cobra.Command {
	c := &cobra.Command{
		Use:           "blk",
		SilenceUsage:  false,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}
	c.AddCommand(
		newInitBlockStoreCmd(),
		newSyncCmd(),
	)
	return c
}

// NewBLKMine returns a new 'blkmine' root command
func NewBLKMine() *cobra.Command {
	return &cobra.Command{
		Use:           "blkmine",
		SilenceErrors: false,
		SilenceUsage:  false,
	}
}
