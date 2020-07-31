package logging

import "github.com/sirupsen/logrus"

// Domain will return a new logger for a specified domain
func Domain(domain string, lvl logrus.Level) *logrus.Logger {
	l := logrus.StandardLogger()
	logger := &logrus.Logger{
		Out:          l.Out,
		Hooks:        l.Hooks,
		Formatter:    l.Formatter,
		ReportCaller: l.ReportCaller,
		Level:        lvl,
		ExitFunc:     l.ExitFunc,
	}
	logger.AddHook(&DomainHook{
		Level:  lvl,
		Domain: domain,
	})
	return logger
}

// DomainHook is a logrus hook that will log with a
// spesific prefix
type DomainHook struct {
	Level  logrus.Level
	Domain string
	Info   interface{}
}

// Levels returns the levels that the domain logs to
func (dh *DomainHook) Levels() []logrus.Level {
	return logrus.AllLevels[:dh.Level+1]
}

// Fire will fire off the hook
func (dh *DomainHook) Fire(e *logrus.Entry) error {
	if dh.Info == nil {
		e.Data["domain"] = dh.Domain
	} else {
		e.Data[dh.Domain] = dh.Info
	}
	return nil
}
