package main

import (
	"os"

	"github.com/harrybrwn/go-ledger/cli"
	log "github.com/sirupsen/logrus"
)

var version string

func main() {
	cmd := cli.NewBLK(version)
	if err := cmd.Execute(); err != nil {
		switch e := err.(type) {
		case *cli.CommandError:
			log.Errorf(
				"%s\n\nUsage: %s\n",
				e.Msg, e.Use,
			)
		default:
			log.Error(err)
		}
		os.Exit(1)
	}
}
