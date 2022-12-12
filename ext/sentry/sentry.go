package SentryTracer

import (
	"context"
	"net/http"

	"github.com/getsentry/sentry-go"
	"github.com/salvationdao/hub"
)

type SentryTracer struct{}

func New() *SentryTracer {
	return &SentryTracer{}
}

func (st *SentryTracer) OnConnect(ctx context.Context, r *http.Request) context.Context {
	sentryHub := sentry.GetHubFromContext(ctx)
	if sentryHub == nil {
		sentryHub = sentry.CurrentHub().Clone()
	}
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetRequest(r)
		scope.SetTag("cmd", "ServeHTTP")
	})

	ctx = sentry.SetHubOnContext(ctx, sentryHub)
	return ctx
}

func (st *SentryTracer) OnEventStart(ctx context.Context, operation string, commandName string, transactionID string) context.Context {
	// Setup tracing
	perentSpan := sentry.TransactionFromContext(ctx)
	if perentSpan == nil {
		perentSpan = sentry.StartSpan(ctx, operation)
	}
	span := perentSpan.StartChild(operation, sentry.TransactionName(commandName))

	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("cmd", commandName)
		scope.SetTag("transaction_id", transactionID)
	})

	ctx = span.Context() // This allows this span to be accessed by TracerStop and to be used as a perent
	return ctx
}

func (st *SentryTracer) OnEventStop(ctx context.Context, log hub.Logger, err error) {
	span := sentry.TransactionFromContext(ctx)
	span.Finish()
}
