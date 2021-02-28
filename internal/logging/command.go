package logging

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/harrybrwn/config"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

// NewLogCmd creates a new log command from a log file
func NewLogCmd(logfile *lumberjack.Logger) *cobra.Command {
	var (
		file, reset bool
		less        bool
		num         int
		level       string
	)
	c := &cobra.Command{
		Use:           "logs",
		Short:         "Manage logs and log files",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if file {
				fmt.Println(logfile.Filename)
				return nil
			}
			if reset {
				return os.Remove(logfile.Filename)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var proc *exec.Cmd
			if less {
				proc = exec.CommandContext(ctx, "less", logfile.Filename)
				proc.Stdout = cmd.OutOrStdout()
				return proc.Run()
			}
			proc = exec.CommandContext(ctx, "tail", "-F", logfile.Filename, "-n", strconv.Itoa(num))
			proc.Stderr, proc.Stdin = cmd.ErrOrStderr(), cmd.InOrStdin()

			copy := io.Copy
			if config.GetBool("nocolor") {
				copy = copyNoColor
			}

			pipe, err := proc.StdoutPipe()
			if err != nil {
				return err
			}
			defer pipe.Close()
			if err = proc.Start(); err != nil {
				return err
			}

			go copy(os.Stdout, pipe)

			err = proc.Wait()
			if e, ok := err.(*exec.ExitError); ok && e.Error() == "signal: killed" {
				return proc.Process.Release()
			}
			return err
		},
	}

	flags := c.Flags()
	flags.BoolVarP(&file, "file", "f", file, "print the path of the logfile")
	flags.BoolVarP(&reset, "reset", "r", reset, "reset the logfile")
	flags.IntVarP(&num, "num", "n", 20, "number of lines of log file shown")
	flags.BoolVar(&less, "less", less, "run less to look at the logs")
	flags.StringVar(&level, "level", level, "filter out the logs at a certain level")
	return c
}

var colorRegex = regexp.MustCompile("[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]")

// yes, i copied this from io.Copy in the io package
func copyNoColor(dest io.Writer, src io.Reader) (written int64, err error) {
	return copyFilter(dest, src, func(b []byte) []byte {
		return colorRegex.ReplaceAll(b, nil)
	})
}

func copyFilter(dest io.Writer, src io.Reader, filter func([]byte) []byte) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dest.Write(filter(buf[0:nr]))
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			// TODO: predict what the difference will be here
			if nr != nw {
				err = io.ErrShortWrite
				// break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}
