package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/harrybrwn/vine/cli"
	"github.com/harrybrwn/vine/internal"
)

//go:generate sh -c "go run $(pwd)/$GOFILE ../../build"

func main() {
	var dir string
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		dir = cwd
	} else {
		dir = filepath.Join(cwd, os.Args[1])
	}

	compdir := filepath.Join(dir, "completion")
	if _, err := os.Stat(compdir); os.IsNotExist(err) {
		err = os.MkdirAll(compdir, 0755)
		if err != nil {
			log.Fatal(err)
		}
	}
	root := cli.New()

	for _, shell := range []string{
		"zsh",
		"bash",
		"powershell",
		"fish",
	} {
		f, err := os.OpenFile(
			filepath.Join(compdir, shell),
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
			0644,
		)
		defer f.Close()
		if err != nil {
			log.Fatal(err)
		}
		err = internal.GenCompletion(root, f, shell)
		if err != nil {
			log.Fatal(err)
		}
		if shell == "zsh" {
			f.Write([]byte(fmt.Sprintf("\ncompdef _%[1]s %[1]s\n", root.Name())))
		}
	}
}
