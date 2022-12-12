package hub

import (
	"context"
	"sync"
)

//events
type Event string
type TriggerChan chan func() (context.Context, error)
type EventHandler func(ctx context.Context, client *Client) error

type ErrorCallback func(error)

const (
	EventConnect Event = "BEFOREUPGRADE"
	EventOnline  Event = "ONLINE"
	EventOffline Event = "OFFLINE"
)

type HubEvents struct {
	events map[Event][]EventHandler
	sync.RWMutex
}

func (ev *HubEvents) AddEventHandler(event Event, handler EventHandler, errCB ErrorCallback) {
	ev.events[event] = append(ev.events[event], handler)
}

func (ev *HubEvents) Trigger(ctx context.Context, event Event, client *Client, errCallback ErrorCallback) {
	for _, fn := range ev.events[event] {
		err := fn(ctx, client)
		if err != nil {
			errCallback(err)
		}
	}
}

func (ev *HubEvents) TriggerMany(ctx context.Context, event Event, client *Client, errCallback ErrorCallback) {
	for _, fn := range ev.events[event] {
		err := fn(ctx, client)
		if err != nil {
			errCallback(err)
		}
	}
}
