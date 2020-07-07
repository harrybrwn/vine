package main

import (
	"fmt"
	"os"

	"github.com/harrybrwn/blockchain/cli"
)

func main() {
	cmd := cli.NewBLK()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
