package hub

import "fmt"

type Logger interface {
	// Err returns a COPY of the logger with error attached.
	// err needs attaching so it is readabible available for log libraries like ZeroLog that take errors in a function independent of the message.
	//
	// A copy is returned to avoid error being echoed out of it's scope.
	//
	// I.E.
	//    // BAD
	//    ➜  go run main.go
	//    9:31AM WRN Failed to initialise sentry error="[Sentry] DsnParseError: invalid scheme"
	//    9:31AM TRC registered CHECK error="[Sentry] DsnParseError: invalid scheme"
	//    9:31AM INF Starting API error="[Sentry] DsnParseError: invalid scheme"
	//    // Good
	//    ➜  go run main.go
	//    9:32AM WRN Failed to initialise sentry error="[Sentry] DsnParseError: invalid scheme"
	//    9:32AM TRC registered CHECK
	//    9:32AM INF Starting API
	Err(err error) Logger
	Panicf(format string, a ...interface{})
	Errorf(format string, a ...interface{})
	Warnf(format string, a ...interface{})
	Infof(format string, a ...interface{})
	Debugf(format string, a ...interface{})
	Tracef(format string, a ...interface{})
}

type defaultLogger struct {
	err error
}

func (l *defaultLogger) Err(err error) Logger {
	return &defaultLogger{err: err}
}

// Panicf will throw real panic
func (l *defaultLogger) Panicf(format string, a ...interface{}) {
	if l.err != nil {
		format = format + " error=%v"
		a = append(a, l.err)
	}
	pnc := fmt.Errorf(format, a...)
	panic(pnc)
}
func (l *defaultLogger) Errorf(format string, a ...interface{}) {}
func (l *defaultLogger) Warnf(format string, a ...interface{})  {}
func (l *defaultLogger) Infof(format string, a ...interface{})  {}
func (l *defaultLogger) Debugf(format string, a ...interface{}) {}
func (l *defaultLogger) Tracef(format string, a ...interface{}) {}
