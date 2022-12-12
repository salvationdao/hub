package main

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/salvationdao/hub"
)

func main() {
	r := chi.NewRouter()

	conf := hub.Config{}
	apiHub := hub.New(conf)
	_ = NewCheckController(apiHub)

	r.Route("/api", func(r chi.Router) {
		r.Handle("/ws", apiHub)
	})

	log.Println("Starting API")

	server := &http.Server{
		Handler: r,
		Addr:    ":8080",
	}

	log.Fatalln(
		server.ListenAndServe(),
	)
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
	reply(response)
	return nil
}
