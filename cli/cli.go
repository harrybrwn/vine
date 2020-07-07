package cli

import (
	"github.com/spf13/cobra"
)

// NewBLK returns a new 'blk' root command
func NewBLK() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "blk",
		SilenceUsage:  false,
		SilenceErrors: false,
	}
	return cmd
}

// NewBLKMine returns a new 'blkmine' root command
func NewBLKMine() *cobra.Command {
	return &cobra.Command{
		Use:           "blkmine",
		SilenceErrors: false,
		SilenceUsage:  false,
	}
}
