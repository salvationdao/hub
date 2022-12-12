package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/salvationdao/terror"
	"nhooyr.io/websocket"
)

// HubKeyErr is an error response key
const HubKeyErr = "HUB:ERROR"

// HubCommandKey is used to route to the correct handlers
type HubCommandKey string

// HubCommandRequest contains everything a handler would expect
type HubCommandRequest struct {
	Key           HubCommandKey `json:"key"`
	TransactionID string        `json:"transaction_id"`
	Payload       []byte        `json:"payload"`
	Client        *Client
}

// ReplyFunc is used to send a synchronous response from a handler
type ReplyFunc func(interface{})

// SecureError returns a forbidden response
type SecureError struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// HubCommandFunc is a registered handler for the hub to route to
type HubCommandFunc func(ctx context.Context, hub *Client, payload []byte, reply ReplyFunc) error

type SessionKey string

const sessionKey SessionKey = "hub-session"

var xx = 0

// Hub is the hub
type Hub struct {
	Log                   Logger
	LoggingEnabled        bool
	middlewares           map[HubCommandKey]HubCommandFunc
	clientMap             *ClientsMap
	commands              map[HubCommandKey]HubCommandFunc
	Events                HubEvents
	tracer                Tracer
	encodedWelcomeMsg     []byte
	acceptOptions         *websocket.AcceptOptions
	ClientCleanUpCallback ClientOfflineFn
	WebsocketReadLimit    int64
}

type Config struct {
	// Log is a levelled error aware logger.
	// Default does nothing with the log messages
	Log            Logger
	LoggingEnabled bool
	// Tracer collects instrumentation and errors for external service consumption.
	// Default does nothing with the information.
	Tracer Tracer
	// WelcomeMsg is sent immediately after a connection is established
	WelcomeMsg *WelcomeMsg
	// AcceptOptions configure the websocket listener
	AcceptOptions *websocket.AcceptOptions
	// ClientOfflineFn is a callback to clean up clients from outside the hub (ie, messagebus)
	ClientOfflineFn

	// Change the initial read limit of the websocket
	WebsocketReadLimit int64
}

// ClientOfflineFn is a callback to clean up clients from outside the hub (ie, messagebus)
type ClientOfflineFn func(cl *Client)

type WelcomeMsg struct {
	Key     HubCommandKey `json:"key"`
	Payload interface{}   `json:"payload"`
}

type ClientsMap struct {
	*sync.Map
}

func (cm *ClientsMap) Range(fn func(SessionID, *Client) bool) {
	cm.Map.Range(func(key, value interface{}) bool {
		c, _ := value.(*Client)
		s, _ := key.(SessionID)
		return fn(s, c)
	})
}

func (cm *ClientsMap) Load(sessionID SessionID) (*Client, bool) {
	c, ok := cm.Map.Load(sessionID)
	if !ok {
		return nil, false
	}
	cl, ok := c.(*Client)
	if !ok {
		return nil, false
	}
	return cl, ok
}

func (cm *ClientsMap) Store(sessionID SessionID, client *Client) {
	cm.Map.Store(sessionID, client)
}

// New creates the hub
func New(conf *Config) *Hub {
	// Create default hub
	hub := &Hub{
		LoggingEnabled:        conf.LoggingEnabled,
		ClientCleanUpCallback: conf.ClientOfflineFn,
		Log:                   &defaultLogger{},
		tracer:                &defaultTracer{},
		encodedWelcomeMsg:     []byte{},

		clientMap:          &ClientsMap{new(sync.Map)},
		Events:             HubEvents{map[Event][]EventHandler{EventOnline: {}, EventOffline: {}}, sync.RWMutex{}},
		commands:           make(map[HubCommandKey]HubCommandFunc),
		WebsocketReadLimit: conf.WebsocketReadLimit,
	}

	// If nil then create an empty conf
	if conf == nil {
		panic("config cannot be nil")
	}
	conf = &*conf

	if conf.Log != nil {
		hub.Log = conf.Log
	}

	if conf.Tracer != nil {
		hub.tracer = conf.Tracer
	}

	if conf.WelcomeMsg != nil {
		if hub.LoggingEnabled {
			conf.Log.Infof("missing welcome message")
		}
		// TODO: use make(chan int) as a type in the welcomeMsg to Trigger this path
		msg, err := json.Marshal(conf.WelcomeMsg)
		if err != nil {
			hub.Log.Err(err).Panicf("failed to marshal WelcomeMessage")
		}
		hub.encodedWelcomeMsg = msg
	}

	if conf.AcceptOptions != nil {
		hub.acceptOptions = conf.AcceptOptions
	}

	hub.acceptOptions.CompressionMode = websocket.CompressionDisabled

	return hub
}

// Handle registers a command to the hub
func (hub *Hub) Handle(key HubCommandKey, fn HubCommandFunc) {
	if _, ok := hub.commands[key]; ok {
		hub.Log.Panicf("command has already been registered to hub: %s", key)
	}
	hub.commands[key] = fn
	hub.Log.Tracef("registered %s", key)
}

// HubClientsFunc isaccepts a function that loops over the clients map
type HubClientsFunc func(sessionID SessionID, client *Client) bool

// HubClientsFunc accepts a function that loops over an individuals clients
type HubUserClientsFunc func(clients map[*Client]bool)

type HubClientsFilterFunc func(client *Client) bool

// Client accepts a sessionID that retrieves a client
func (hub *Hub) Client(sessionID SessionID) (*Client, bool) {
	return hub.clientMap.Load(sessionID)
}

// Clients accepts a function that loops over the clients map
func (hub *Hub) Clients(fn HubClientsFunc, debug ...string) {
	if len(debug) > 0 && hub.LoggingEnabled {
		hub.Log.Debugf("start client map: %s", debug)
	}

	hub.clientMap.Range(fn)
}

func (se *SecureError) Error() string {
	return se.Message
}

// ErrSecureError is a forbidden response
var ErrSecureError = &SecureError{
	Message: "Forbidden",
	Success: false,
}

// inExcluded compares client to excluded list
func inExcluded(client *Client, excluded []*Client) bool {
	for _, exc := range excluded {
		if exc == client {
			return true
		}
	}
	return false
}

// SendFn used to send messages to users
type SendFn func(key string, payload interface{}, userIdentifiers ...string) []string

// Send sends payloads to the connected users sent in userIDs
// returns an array of users that did not receive message
func (hub *Hub) Send(ctx context.Context, key HubCommandKey, payload interface{}, clients ...*Client) {
	resp := struct {
		Key     HubCommandKey `json:"key"`
		Payload interface{}   `json:"payload"`
	}{
		Key:     key,
		Payload: payload,
	}

	b, err := json.Marshal(resp)
	if err != nil {
		if hub.LoggingEnabled {
			hub.Log.Err(err).Errorf("send: issue marshalling resp")
		}
		return
	}

	//swallow errors because it doesn't matter
	for _, c := range clients {
		go c.Send(b)
	}
}

// Online adds websocket clients to the pool
// It will create maps as required
// Guests are classified as uuid.Nil
// A single userID may have multiple hub clients attached (multiple browsers, multiple devices, multiple guests)
func (hub *Hub) Online(hubc *Client) {
	hub.clientMap.Store(hubc.SessionID, hubc)
	hub.Events.Trigger(context.Background(), EventOnline, hubc, func(err error) {})
}

// Offline removes disconnected websocket clients from the pool
// removes maps when they're empty
func (hub *Hub) Offline(hubc *Client) {
	hub.clientMap.Delete(hubc)
	hub.Events.Trigger(context.Background(), EventOffline, hubc, func(err error) {})
}

// ErrSync is a synchronous error, and error with a sessionID
type ErrSync struct {
	Key           HubCommandKey `json:"key"`
	TransactionID string        `json:"transaction_id"`
	Message       string        `json:"message"`
}

// do retrieve command function and run it on websocket request
func (hub *Hub) do(cmd *HubCommandRequest) {
	var hubErr error
	ctx := cmd.Client.ctx
	ctx = hub.tracer.OnEventStart(ctx, "hub.do", string(cmd.Key), cmd.TransactionID, cmd.Client.Identifier())
	defer func() {
		hub.tracer.OnEventStop(ctx, hub.Log, hubErr)
	}()

	fn, ok := hub.commands[cmd.Key]
	if !ok {
		if hub.LoggingEnabled {
			hub.Log.Warnf("no command found for %s", cmd.Key)
		}
		errmsg := &ErrSync{
			Key:           HubKeyErr,
			TransactionID: cmd.TransactionID,
			Message:       "Command not found, try again or contact support.",
		}

		b, err := json.Marshal(errmsg)
		if err != nil {
			return
		}

		go cmd.Client.Send(b)
		return
	}

	//TODO: implement error handling

	reply := func(payload interface{}) {
		resp := struct {
			Key           HubCommandKey `json:"key"`
			TransactionID string        `json:"transaction_id"`
			Success       bool          `json:"success"`
			Payload       interface{}   `json:"payload"`
		}{
			Key:           cmd.Key,
			TransactionID: cmd.TransactionID,
			Success:       true,
			Payload:       payload,
		}

		b, err := json.Marshal(resp)
		if err != nil {
			if hub.LoggingEnabled {
				hub.Log.Err(err).Errorf("marshalling error")
			}
		}

		go cmd.Client.Send(b)
	}

	hubErr = fn(context.Background(), cmd.Client, cmd.Payload, reply)
	if hubErr != nil {
		// Log the error
		if hubErr.Error() == "access forbidden" {
			hub.Log.Debugf("%s:%s access denied", cmd.Client.Identifier(), cmd.Key)
		} else {
			hub.Log.Err(hubErr).Errorf("%s returned with an error", cmd.Key)
		}

		// Prep response to client
		errmsg := &ErrSync{
			Key:           HubKeyErr,
			TransactionID: cmd.TransactionID,
			Message:       hubErr.Error(),
		}
		var bErr *terror.TError
		if errors.As(hubErr, &bErr) {
			errmsg.Message = bErr.Message

		}
		b, err := json.Marshal(errmsg)
		if err != nil {
			if hub.LoggingEnabled {
				hub.Log.Err(err).Errorf("marshalling error")
			}
			return
		}

		go cmd.Client.Send(b)
	}
}

type TracerConnectEventFunc func(ctx context.Context, r *http.Request) context.Context

// ServeHTTP connects websocket clients and upgrades them
// guests will be added to the "GUEST" pool
func (hub *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := hub.tracer.OnConnect(r.Context(), r)
	// Upgrade connection to websocket
	c, err := websocket.Accept(w, r, hub.acceptOptions)
	if err != nil {
		if hub.LoggingEnabled {
			hub.Log.Err(err).Errorf("websocket upgrade")
		}
		return
	}

	if hub.WebsocketReadLimit > 0 {
		c.SetReadLimit(hub.WebsocketReadLimit)
	}
	if hub.LoggingEnabled {
		hub.Log.Debugf("Opening connection")
	}
	hubc := NewHubClient(ctx, hub, c, r, w)

	hub.Clients(func(sessionID SessionID, client *Client) bool {
		hub.Events.Trigger(ctx, EventConnect, hubc, func(err error) {})
		return true
	})

	hub.Online(hubc)
	defer hub.Offline(hubc)
	hubc.ListenAndSend()

	// cleanup
	for {
		<-hubc.ctx.Done()
		hubc.hub.Log.Debugf("hubc.ListenAndSend clean up finished")
		return
	}
}
