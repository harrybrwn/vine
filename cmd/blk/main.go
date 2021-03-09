package main

import (
	"context"
	"fmt"
	"os"

	"github.com/harrybrwn/go-ledger/cli"
	log "github.com/sirupsen/logrus"
)

func main() {
	cmd := cli.New()
	err := cmd.ExecuteContext(context.Background())
	if err != nil {
		Errorf := log.Errorf
		if cli.Flags.Silent {
			Errorf = func(format string, v ...interface{}) {
				fmt.Printf(format, v...)
			}
		}
		switch e := err.(type) {
		case *cli.CommandError:
			Errorf(
				"%s\n\nUsage: %s\n",
				e.Msg, e.Use,
			)
		case *cli.StatusError:
			Errorf("Error: %s", e.Error())
			os.Exit(e.Code)
		default:
			Errorf("Error: %v\n", err)
		}
		os.Exit(1)
	}
}
