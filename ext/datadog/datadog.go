package DatadogTracer

import (
	"context"
	"fmt"
	"net/http"

	"github.com/salvationdao/hub"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type TracerContext string

type DatadogTracer struct{}

func New() *DatadogTracer {
	return &DatadogTracer{}
}

func (tc TracerContext) String() string {
	return fmt.Sprintf("contextkey_%s", string(tc))
}

func (ht *DatadogTracer) OnConnect(ctx context.Context, r *http.Request) context.Context {
	return ctx
}

func (ht *DatadogTracer) OnEventStart(ctx context.Context, operation string, commandName string, transactionID string, identifier string) context.Context {
	span := tracer.StartSpan("hub_handler", tracer.ResourceName(commandName))
	if identifier != "" {
		span.SetTag("identifier", identifier)
	}
	return context.WithValue(ctx, TracerContext("span"), span)
}

func (ht *DatadogTracer) OnEventStop(ctx context.Context, l hub.Logger, err error) {
	span := ctx.Value(TracerContext("span")).(tracer.Span)
	span.Finish(tracer.WithError(err))
}

// Middleware is a http middleware used to implement dog for HTTP Handlers.
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			span, augmentedCtx := tracer.StartSpanFromContext(
				r.Context(),
				"http_handler",
				tracer.ResourceName(fmt.Sprintf("%s %s", r.Method, r.URL.Path)),
				tracer.Tag("http.method", r.Method),
				tracer.Tag("http.url", r.URL.Path),
			)
			defer span.Finish()
			r = r.WithContext(augmentedCtx)
			next.ServeHTTP(w, r)
		})
	}
}

// HttpFinishSpan finishes the span with HTTP response.
func HttpFinishSpan(ctx context.Context, statusCode int, err error) error {
	span, ok := tracer.SpanFromContext(ctx)
	if !ok {
		return fmt.Errorf("datadog tracer not found in context")
	}
	span.SetTag("http.status_code", statusCode)
	span.Finish(tracer.WithError(err))
	return nil
}
