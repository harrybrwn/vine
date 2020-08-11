package logging

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

// PrefixedFormatter is a logging text formatter that logs with a prefix
type PrefixedFormatter struct {
	Prefix     string
	TimeFormat string
}

// Format using the prefixed formatter
func (pf *PrefixedFormatter) Format(e *logrus.Entry) ([]byte, error) {
	var col color.Attribute
	switch e.Level {
	case logrus.PanicLevel, logrus.ErrorLevel:
		col = color.FgRed
	case logrus.WarnLevel:
		col = color.FgYellow
	case logrus.InfoLevel:
		col = color.FgCyan
	case logrus.DebugLevel, logrus.TraceLevel:
		col = color.FgWhite
	default:
		return nil, errors.New("unknown logging level")
	}
	var keys []string
	for k := range e.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	levelStr := strings.ToUpper(e.Level.String())
	var b bytes.Buffer

	format := "\x1b[90m[%s]\x1b[0m \x1b[%dm%-5s\x1b[0m %s: %s"
	if pf.Prefix == "" {
		format = "\x1b[90m[%s]\x1b[0m \x1b[%dm%-5s\x1b[0m %s%s"
	}
	timeFormat := pf.TimeFormat
	if timeFormat == "" {
		timeFormat = time.RFC3339
	}

	fmt.Fprintf(&b, format,
		e.Time.Format(timeFormat), col, levelStr, pf.Prefix, e.Message)

	for _, k := range keys {
		fmt.Fprintf(&b, " \x1b[%dm%s\x1b[0m=", col, k)
		val := e.Data[k]
		s, ok := val.(string)
		if !ok {
			s = fmt.Sprint(val)
		}
		if !needsQuotes(s) {
			b.WriteString(s)
		} else {
			b.WriteString(fmt.Sprintf("%q", s))
		}
	}
	if b.Bytes()[b.Len()-1] != '\n' {
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// SilentFormatter is a logrus formatter that does nothing
type SilentFormatter struct{}

// Format does nothing
func (sf *SilentFormatter) Format(*logrus.Entry) ([]byte, error) {
	return nil, nil
}

func needsQuotes(s string) bool {
	if len(s) == 0 {
		return true
	}
	for _, c := range s {
		if !isChar(c) {
			return true
		}
	}
	return false
}

func isChar(c rune) bool {
	return c >= '!' && c <= '~'
}
