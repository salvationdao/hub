package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/antonholmquist/jason"
	"github.com/gofrs/uuid"
	"go.uber.org/atomic"
	"nhooyr.io/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 3 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
)

type hubClientMessage struct {
	MsgType websocket.MessageType
	payload []byte
	//context context.Context
	//cancel  context.CancelFunc
}

type SessionID string

// Client contains client session state
type Client struct {
	Level          int           // permissions level
	Permissions    []string      // permissions they hold
	ident          atomic.String // gets set on auth to their ID by default, no auth - no ident
	hub            *Hub
	SessionID      SessionID
	ctx            context.Context
	close          context.CancelFunc
	Offline        atomic.Bool
	Request        *http.Request
	ResponseWriter http.ResponseWriter
	*websocket.Conn
	LockClient bool
}

// Identifier returns the users identifier
func (hubc *Client) Identifier() string {
	return hubc.ident.Load()
}

// SetIdentifier sets a users identifier
func (hubc *Client) SetIdentifier(ident string) {
	hubc.ident.Store(ident)
}

// SetLevel sets the level of the user
func (hubc *Client) SetLevel(level int) {
	if !hubc.LockClient {
		hubc.Level = level
	}
}

// SetPermissions sets the level of the user
func (hubc *Client) SetPermissions(perms []string) {
	if !hubc.LockClient {
		hubc.Permissions = perms
	}
}

// HasPermission checks if the user holds a permission
func (hubc *Client) HasPermission(perms string) bool {
	for _, prm := range hubc.Permissions {
		if prm == perms {
			return true
		}
	}
	return false
}

func (hubc *Client) IsHigherLevel(level int) bool {
	return hubc.Level > level
}

func (hubc *Client) IsHigherOrSameLevel(level int) bool {
	return hubc.Level >= level
}

// NewHubClient returns a new hub client
// A hub client is a persistent websocket session
func NewHubClient(ctx context.Context, hub *Hub, c *websocket.Conn, r *http.Request, w http.ResponseWriter) *Client {
	ctx, cancel := context.WithCancel(ctx)

	hubc := &Client{
		hub:            hub,
		Request:        r,
		ResponseWriter: w,
		SessionID:      SessionID(uuid.Must(uuid.NewV4()).String()),
		ctx:            ctx,
		close:          cancel,
		Conn:           c,
	}

	return hubc
}

// write enforces a timeout on websocket writes
func write(msg *hubClientMessage, timeout time.Duration, c *websocket.Conn) error {
	if c == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return c.Write(ctx, msg.MsgType, msg.payload)
}

// pingTimeout enforces a timeout on websocket ping
func pingTimeout(ctx context.Context, timeout time.Duration, c *websocket.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.Ping(ctx)
}

// Send will send a payload to the hub client
func (hubc *Client) SendErrorCallback(payload []byte, callback func(err error)) {
	if hubc.Offline.Load() == true {
		return
	}

	msg := &hubClientMessage{
		payload: payload,
		MsgType: websocket.MessageText,
	}

	err := write(msg, writeWait, hubc.Conn)
	if err != nil {
		hubc.Offline.Store(true)
		callback(err)
		_ = hubc.Close(websocket.StatusInternalError, "failed to send")
		hubc.hub.Offline(hubc)
		if errors.Is(err, context.Canceled) {
			return
		}
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
			websocket.CloseStatus(err) == websocket.StatusGoingAway {
			return
		}
		if hubc.hub.LoggingEnabled {
			hubc.hub.Log.Err(err).Warnf("error sending")
		}
	}
}

// Send will send a payload to the hub client
func (hubc *Client) Send(payload []byte) {
	if hubc.Offline.Load() == true {
		return
	}

	msg := &hubClientMessage{
		payload: payload,
		MsgType: websocket.MessageText,
	}

	err := write(msg, writeWait, hubc.Conn)
	if err != nil {
		hubc.Offline.Store(true)
		_ = hubc.Close(websocket.StatusInternalError, "failed to send")
		hubc.hub.Offline(hubc)
		if errors.Is(err, context.Canceled) {
			return
		}
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
			websocket.CloseStatus(err) == websocket.StatusGoingAway {
			return
		}
		if hubc.hub.LoggingEnabled {
			hubc.hub.Log.Err(err).Warnf("error sending")
		}
	}
}

// SendWithMessageType will send a payload to the hub client with given message type
func (hubc *Client) SendBinaryErrCallback(payload []byte, callback func(err error)) {
	if hubc.Offline.Load() {
		return
	}

	msg := &hubClientMessage{
		payload: payload,
		MsgType: websocket.MessageBinary,
	}

	err := write(msg, writeWait, hubc.Conn)
	if err != nil {
		hubc.Offline.Store(true)
		callback(err)
		_ = hubc.Close(websocket.StatusInternalError, "failed to send")
		hubc.hub.Offline(hubc)
		if errors.Is(err, context.Canceled) {
			return
		}
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
			websocket.CloseStatus(err) == websocket.StatusGoingAway {
			return
		}
		if hubc.hub.LoggingEnabled {
			hubc.hub.Log.Err(err).Warnf("error sending")
		}
	}
}

// SendWithMessageType will send a payload to the hub client with given message type
func (hubc *Client) SendWithMessageType(payload []byte, msgType websocket.MessageType) {
	if hubc.Offline.Load() {
		return
	}

	msg := &hubClientMessage{
		payload: payload,
		MsgType: msgType,
	}

	err := write(msg, writeWait, hubc.Conn)
	if err != nil {
		hubc.Offline.Store(true)
		_ = hubc.Close(websocket.StatusInternalError, "failed to send")
		hubc.hub.Offline(hubc)
		if errors.Is(err, context.Canceled) {
			return
		}
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
			websocket.CloseStatus(err) == websocket.StatusGoingAway {
			return
		}
		if hubc.hub.LoggingEnabled {
			hubc.hub.Log.Err(err).Warnf("error sending")
		}
	}
}

// ListenAndSend listens for incoming messages and pumps them to the correct connected hub clients
func (hubc *Client) ListenAndSend() {
	go hubc.receivePump()

	if len(hubc.hub.encodedWelcomeMsg) != 0 {
		hubc.Send(hubc.hub.encodedWelcomeMsg)
	}
}

func (hubc *Client) receivePump() {
	for {
		select {
		case <-hubc.ctx.Done():
			return
		default:
			_, payload, err := hubc.Conn.Read(hubc.ctx)
			if err != nil {
				hubc.Offline.Store(true)
				_ = hubc.Close(websocket.StatusInternalError, "failed to read from pump")

				hubc.hub.Offline(hubc)
				if errors.Is(err, context.Canceled) {
					return
				}
				if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
					websocket.CloseStatus(err) == websocket.StatusGoingAway {
					return
				}
				if hubc.hub.LoggingEnabled {
					hubc.hub.Log.Err(fmt.Errorf("read ws conn: %w", err))
				}
				return
			}

			v, err := jason.NewObjectFromBytes(payload)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
					websocket.CloseStatus(err) == websocket.StatusGoingAway {
					return
				}
				if hubc.hub.LoggingEnabled {
					hubc.hub.Log.Err(err).Errorf("make object from bytes. Object: %s", string(payload))
				}
				continue
			}
			cmdKey, err := v.GetString("key")
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
					websocket.CloseStatus(err) == websocket.StatusGoingAway {
					return
				}
				if hubc.hub.LoggingEnabled {
					hubc.hub.Log.Err(err).Errorf(`missing json key "key"`)
				}
				continue
			}

			if cmdKey == "" {
				if hubc.hub.LoggingEnabled {
					hubc.hub.Log.Err(fmt.Errorf("missing key value")).Errorf("missing key/command value")
				}
				continue
			}

			if hubc.hub.LoggingEnabled {
				hubc.hub.Log.Debugf("%s | received", cmdKey)
			}
			tid, err := v.GetString("transaction_id")
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
					websocket.CloseStatus(err) == websocket.StatusGoingAway {
					return
				}
				if hubc.hub.LoggingEnabled {
					hubc.hub.Log.Err(err).Errorf("get transactionID string")
				}
				continue
			}

			go hubc.hub.do(&HubCommandRequest{
				Key:           HubCommandKey(cmdKey),
				TransactionID: tid,
				Payload:       payload,
				Client:        hubc,
			})
		}
	}
}
