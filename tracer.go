package hub

import (
	"context"
	"net/http"
)

type Tracer interface {
	OnConnect(ctx context.Context, r *http.Request) context.Context
	OnEventStart(ctx context.Context, operation string, commandName string, transactionID string, identifier string) context.Context
	OnEventStop(context.Context, Logger, error)
}

type defaultTracer struct{}

func (t *defaultTracer) OnConnect(ctx context.Context, r *http.Request) context.Context {
	return ctx
}

func (t *defaultTracer) OnEventStart(ctx context.Context, operation string, commandName string, transactionID string, identifier string) context.Context {
	return ctx
}

func (t *defaultTracer) OnEventStop(context.Context, Logger, error) {}
