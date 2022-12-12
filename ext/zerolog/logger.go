package zerologger

import (
	"github.com/rs/zerolog"
	"github.com/salvationdao/hub"
)

type ZeroLogger struct {
	log zerolog.Logger
	err error
}

func New(log zerolog.Logger) *ZeroLogger {
	return &ZeroLogger{log: log}
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
func (l *ZeroLogger) Err(err error) hub.Logger {
	log := New(l.log)
	log.err = err
	return log
}

func (l *ZeroLogger) Panicf(format string, a ...interface{}) {
	l.log.Panic().Err(l.err).Msgf(format, a...)
}
func (l *ZeroLogger) Errorf(format string, a ...interface{}) {
	l.log.Error().Err(l.err).Msgf(format, a...)
}
func (l *ZeroLogger) Warnf(format string, a ...interface{}) {
	l.log.Warn().Err(l.err).Msgf(format, a...)
}
func (l *ZeroLogger) Infof(format string, a ...interface{}) {
	l.log.Info().Err(l.err).Msgf(format, a...)
}
func (l *ZeroLogger) Debugf(format string, a ...interface{}) {
	l.log.Debug().Err(l.err).Msgf(format, a...)
}
func (l *ZeroLogger) Tracef(format string, a ...interface{}) {
	l.log.Trace().Err(l.err).Msgf(format, a...)
}
