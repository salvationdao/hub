package main

import (
	"context"
	"net/http"

	"github.com/getsentry/sentry-go"
	"github.com/go-chi/chi"
	"github.com/rs/zerolog"
	"github.com/salvationdao/hub"
	SentryTracer "github.com/salvationdao/hub/ext/sentry"
	zerologger "github.com/salvationdao/hub/ext/zerolog"
	"nhooyr.io/websocket"
)

const HubKeyWelcome hub.HubCommandKey = hub.HubCommandKey("Welcome")

// WelcomePayload is the response sent when a client connects to the server
type WelcomePayload struct {
	Message string        `json:"message"`
	Config  WelcomeConfig `json:"config"`
}

// WelcomeConfig is the config sent when a client connects to the server
type WelcomeConfig struct {
	// SentryFrontendTracePercent expressed as a number between 0 and 1
	SentryFrontendTracePercent float32 `json:"sentry_frontend_trace_percent"`
}

func main() {
	l := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()
	log := zerologger.New(l)

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              "PROJECTDSN",
		AttachStacktrace: false,
		// Unfortunately terror interfears with the stack trace that stdlib.Error collects
		// causing all sentry stack traces to look alike. Creating matching errors
	})
	if err != nil {
		log.Err(err).Errorf("Failed to initialise sentry")
	}

	welcome := &hub.WelcomeMsg{
		Key: HubKeyWelcome,
		Payload: WelcomePayload{
			Message: "Welcome to Opinions",
			Config: WelcomeConfig{
				SentryFrontendTracePercent: 0.5,
			},
		},
	}

	r := chi.NewRouter()
	apiHub := hub.New(&hub.Config{
		Log:        log,
		Tracer:     SentryTracer.New(),
		WelcomeMsg: welcome,
		AcceptOptions: &websocket.AcceptOptions{
			InsecureSkipVerify: true,
			// HACK: iOS 15 websocket implentation has a bug in the compression algorithm.
			//       As of iOS 15 webkit uses `NSURLSESSION` for websocket connections,
			//       Limiting commpressed messages to approximately 126 bytes.
			//       Discussion thread https://developer.apple.com/forums/thread/685403
			//
			//       Use the following test server to test iOS 15+ before reactivating compression
			//       open counter page and click send junk.
			//       https://libwebsockets.org/testserver/
			//       Nathan 18 Oct 2021
			CompressionMode: websocket.CompressionDisabled,
		},
	})
	_ = NewCheckController(apiHub)

	r.Route("/api", func(r chi.Router) {
		r.Handle("/ws", apiHub)
	})

	log.Infof("Starting API")

	server := &http.Server{
		Handler: r,
		Addr:    ":8080",
	}

	log.Err(
		server.ListenAndServe(),
	).Errorf("ListenAndServe failed")

}

// CheckController holds handlers for checking server status
type CheckController struct {
	apiHub *hub.Hub
}

// NewCheckController creates the check hub
func NewCheckController(apiHub *hub.Hub) *CheckController {
	checkController := &CheckController{
		apiHub: apiHub,
	}

	apiHub.Handle(HubKeyCheck, checkController.HandleCheck)
	return checkController
}

// HubKeyCheck is used to route to the  handler
const HubKeyCheck hub.HubCommandKey = hub.HubCommandKey("CHECK")

type CheckReplyPayload struct {
	Check string `json:"check"`
}

func (hub *CheckController) HandleCheck(ctx context.Context, client *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	response := CheckReplyPayload{Check: "ok"}
	hub.apiHub.Log.Infof("%s hit", HubKeyCheck)
	reply(response)
	return nil
}
