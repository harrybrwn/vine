package main

import (
	"fmt"
	"os"

	"github.com/harrybrwn/go-ledger/cli"
)

func main() {
	cmd := cli.NewBLKMine()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
