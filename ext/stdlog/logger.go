package stdlogger

import (
	"fmt"
	"log"

	"github.com/salvationdao/hub"
)

type stdLogger struct {
	err error
}

// Err returns a COPY of the logger with error attached.
// err needs attaching so it is readabible available for log libraries like ZeroLog that take errors in a function independent of the message.
//
// A copy is returned to avoid error being echoed out of it's scope.
//
// I.E.
//
//	// BAD
//	➜  go run main.go
//	9:31AM WRN Failed to initialise sentry error="[Sentry] DsnParseError: invalid scheme"
//	9:31AM TRC registered CHECK error="[Sentry] DsnParseError: invalid scheme"
//	9:31AM INF Starting API error="[Sentry] DsnParseError: invalid scheme"
//	// Good
//	➜  go run main.go
//	9:32AM WRN Failed to initialise sentry error="[Sentry] DsnParseError: invalid scheme"
//	9:32AM TRC registered CHECK
//	9:32AM INF Starting API
func (l *stdLogger) Err(err error) hub.Logger {
	log := stdLogger{err: err}
	return &log
}

func (l *stdLogger) Panicf(format string, a ...interface{}) {
	if l.err != nil {
		format = format + " error=%v"
		a = append(a, l.err)
	}
	pnc := fmt.Errorf(format, a...)
	panic(pnc)
}
func (l *stdLogger) Errorf(format string, a ...interface{}) {
	format = "Error: " + format
	l.printer(format, a...)
}
func (l *stdLogger) Warnf(format string, a ...interface{}) {
	format = "Warn: " + format
	l.printer(format, a...)
}
func (l *stdLogger) Infof(format string, a ...interface{}) {
	format = "Info: " + format
	l.printer(format, a...)
}
func (l *stdLogger) Debugf(format string, a ...interface{}) {
	format = "Debug: " + format
	l.printer(format, a...)
}
func (l *stdLogger) Tracef(format string, a ...interface{}) {
	format = "Trace: " + format
	l.printer(format, a...)
}

func (l *stdLogger) printer(format string, a ...interface{}) {
	if l.err != nil {
		format = format + "error=%v"
		a = append(a, l.err)
	}
	log.Printf(format, a...)
}
