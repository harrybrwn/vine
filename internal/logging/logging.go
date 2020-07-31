package logging

import (
	"io"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// Copy returns a copy of the logrus standar logger
func Copy() *logrus.Logger {
	l := logrus.StandardLogger()
	return &logrus.Logger{
		Out:          l.Out,
		Hooks:        l.Hooks,
		Formatter:    l.Formatter,
		ReportCaller: l.ReportCaller,
		Level:        l.Level,
		ExitFunc:     l.ExitFunc,
	}
}

// NewLogFileHook will create a logrus hook that logs to a log file
// for all logging levels
func NewLogFileHook(file io.Writer, formatter log.Formatter) log.Hook {
	return &logfilehook{
		file:      file,
		level:     log.TraceLevel,
		formatter: formatter,
	}
}

type logfilehook struct {
	file      io.Writer
	level     log.Level
	formatter log.Formatter
}

func (lf *logfilehook) Levels() []log.Level {
	return log.AllLevels[:lf.level+1]
}

func (lf *logfilehook) Fire(e *log.Entry) error {
	b, err := lf.formatter.Format(e)
	if err != nil {
		return err
	}
	_, err = lf.file.Write(b)
	return err
}
