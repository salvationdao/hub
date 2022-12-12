# Hub

Web socket hub for salvationdao projects

## Server Examples

- [Basic server with default options](examples/basic/main.go)

- [Opinionated server with the standard options](examples/salvationdao/main.go)

## New Hub Options

```go
type Opts struct {
    // Log is a levelled error aware logger.
    // Default does nothing with the log messages unless panic is called.
    Log Logger
    // Tracer collects instrumentation and errors for external service consumption.
    // Default does nothing with the informaition.
    Tracer Tracer
    // WelcomeMsg is sent immediately after a connection is established
    WelcomeMsg *WelcomeMsg
    // AcceptOptions configure the websocket listener
    AcceptOptions *websocket.AcceptOptions
}
```

### `Opts.Log`

```go
type Logger interface {
    Err(err error) Logger
   Panicf(format string, a ...interface{}) // **NOTE: The panics are real, even in the default implementation**
   Errorf(format string, a ...interface{})
   Warnf(format string, a ...interface{})
   Infof(format string, a ...interface{})
   Debugf(format string, a ...interface{})
   Tracef(format string, a ...interface{})
}
```

Provides a way to hook a custom logger into the library.  
**NOTE: The panics are real, even in the default implementation**  
Pre-Built loggers are available

- [Based on go's standard log](./ext/stdlog/logger.go)
- [Based on the ZeroLog library](./ext/zerolog/logger.go)

### `Opts.Tracer`

Provides a way to hook a performace tracer into the library.  
The default won't record anything.  
A Pre-Built Tracer is available

- [Using Sentry](./ext/sentry/sentry.go)

```go
type Tracer interface {
    OnConnect(ctx context.Context, r *http.Request) context.Context
    OnEventStart(ctx context.Context, operation string, commandName string, transactionID string) context.Context
    OnEventStop(context.Context, Logger)
}
```

### `Opts.WelcomeMsg`

Provids an optional welcome message.

```go
type WelcomeMsg struct {
    Key     HubCommandKey `json:"key"`
    Payload interface{}   `json:"payload"`
}

// Example Payload
type WelcomePayload struct {
    Message string        `json:"message"`
}
```

### `Opts.AcceptOptions`

The options to configure the [nhooyr web socket (pkg.go.dev)](https://pkg.go.dev/nhooyr.io/websocket#AcceptOptions).
