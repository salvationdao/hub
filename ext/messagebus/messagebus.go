package messagebus

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/rs/zerolog"
	"github.com/salvationdao/hub"
)

type BusKey string

type bus struct {
	m map[string]*hub.Client
	w map[*hub.Client]bool
	sync.RWMutex
}

func newbus() *bus {
	return &bus{
		m:       make(map[string]*hub.Client),
		w:       make(map[*hub.Client]bool),
		RWMutex: sync.RWMutex{},
	}
}

type busmap struct {
	m   map[BusKey]*bus
	log *zerolog.Logger

	sync.RWMutex
}

func (b *bus) Remove(hubc *hub.Client) {
	b.Lock()
	if b.w == nil {
		b.w = map[*hub.Client]bool{}
	}
	delete(b.w, hubc)
	b.Unlock()
}

func (b *bus) Delete(key string) {
	b.Lock()
	if b.m == nil {
		b.m = make(map[string]*hub.Client)
	}
	delete(b.m, key)
	b.Unlock()
}

func (b *bus) Insert(ws *hub.Client) {
	b.Lock()
	if b.w == nil {
		b.w = map[*hub.Client]bool{}
	}
	b.w[ws] = true
	b.Unlock()
}

func (b *bus) Store(key string, ws *hub.Client) {
	b.Lock()
	if b.m == nil {
		b.m = make(map[string]*hub.Client)
	}
	b.m[key] = ws
	b.Unlock()
}

func (b *bus) Load(key string) (*hub.Client, bool) {
	b.Lock()
	defer b.Unlock()
	if b.m == nil {
		b.m = map[string]*hub.Client{}
	}
	ws, ok := b.m[key]
	if ws == nil || ws.Offline.Load() {
		delete(b.m, key)
		return nil, false
	}
	return ws, ok
}

func (bm *busmap) Store(busKey BusKey, b *bus) *bus {
	bm.Lock()
	if b == nil {
		b = newbus()
	}
	if b.m == nil {
		b.m = make(map[string]*hub.Client)
	}
	bm.m[busKey] = b
	bm.Unlock()
	return b
}

func (bm *busmap) Range(fn func(key BusKey, bs *bus) bool) {
	bm.Lock()
	defer bm.Unlock()
	if bm.m == nil {
		bm.m = make(map[BusKey]*bus)
	}
	for buskey, bs := range bm.m {
		if !fn(buskey, bs) {
			return
		}
	}
}

func (b *bus) RangeClients(fn func(hubc *hub.Client) bool) {
	b.RLock()
	defer b.RUnlock()
	if b.w == nil {
		b.w = map[*hub.Client]bool{}
	}
	for ws, _ := range b.w {
		if !fn(ws) {
			return
		}
	}
}

func (b *bus) RangeMutate(fn func(key string, hubc *hub.Client) bool) {
	b.Lock()
	defer b.Unlock()
	if b.m == nil {
		b.m = make(map[string]*hub.Client)
	}
	for tx, ws := range b.m {
		if !fn(tx, ws) {
			return
		}
	}
}

func (b *bus) Range(fn func(key string, hubc *hub.Client) bool) {
	b.RLock()
	defer b.RUnlock()
	if b.m == nil {
		b.m = make(map[string]*hub.Client)
	}
	for tx, ws := range b.m {
		if !fn(tx, ws) {
			return
		}
	}
}

func (bm *busmap) Load(busKey BusKey) *bus {
	defer func() {
		if err := recover(); err != nil {
			bm.log.Error().Interface("err", err).Msg("panic! panic! panic! Panic at the MessageBus.Load!")
		}
	}()
	bm.Lock()
	defer bm.Unlock()
	if bm.m == nil {
		bm.m = make(map[BusKey]*bus)
	}
	b, ok := bm.m[busKey]
	if !ok {
		bm.m[busKey] = newbus()
		return bm.m[busKey]
	}
	return b
}

// message bus store (hubkey, sync.map)
type MessageBus struct {
	log    *zerolog.Logger
	busses *busmap
	sync.Mutex
}

// (string, true)
type TransactionBus struct {
	transactions []hub.SessionID
	client       *hub.Client
}

type message struct {
	ctx           context.Context
	busKey        BusKey
	data          interface{}
	filterOptions []BusSendFilterOption
}

type Message struct {
	Payload       interface{} `json:"payload"`
	Key           BusKey      `json:"key"`
	TransactionID string      `json:"transaction_id"`
}

func NewMessageBus(log *zerolog.Logger) *MessageBus {
	return &MessageBus{
		busses: &busmap{
			m:   make(map[BusKey]*bus),
			log: log,
		},
		log: log,
	}
}

func (mb *MessageBus) Bus(busKey BusKey) *bus {
	defer func() {
		if err := recover(); err != nil {
			mb.log.Error().Interface("err", err).Msg("panic! panic! panic! Panic at the MessageBus.Bus!")
		}
	}()

	return mb.busses.Load(busKey)
}

func (mb *MessageBus) SubClient(busKey BusKey, hubc *hub.Client) *bus {
	defer func() {
		if err := recover(); err != nil {
			mb.log.Error().Interface("err", err).Msg("panic! panic! panic! Panic at the MessageBus.Sub!")
		}
	}()

	b := mb.Bus(busKey)
	b.Insert(hubc)
	mb.busses.Store(busKey, b)

	return b
}

func (mb *MessageBus) Sub(busKey BusKey, hubc *hub.Client, transactionID string) *bus {
	defer func() {
		if err := recover(); err != nil {
			mb.log.Error().Interface("err", err).Msg("panic! panic! panic! Panic at the MessageBus.Sub!")
		}
	}()

	mb.Lock()
	defer mb.Unlock()
	b := mb.Bus(busKey)
	b.Store(transactionID, hubc)

	return b
}

func (mb *MessageBus) Delete(busKey BusKey, hubc *hub.Client) {
	b := mb.Bus(busKey)
	if b == nil {
		return
	}
	b.Remove(hubc)
}

func (mb *MessageBus) UnsubClient(busKey BusKey, hubc *hub.Client) {
	b := mb.Bus(busKey)
	if b == nil {
		return
	}
	b.Remove(hubc)
}

func (mb *MessageBus) Unsub(busKey BusKey, hubc *hub.Client, transactionID string) {
	b := mb.Bus(busKey)
	if b == nil {
		return
	}
	b.Delete(transactionID)
}

const busKeyUnsubALL = "UNSUB_ALL"

func (mb *MessageBus) UnsubAll(hubc *hub.Client) {
	mb.busses.Range(func(key BusKey, b *bus) bool {
		b.Lock()
		if b.w == nil {
			b.w = map[*hub.Client]bool{}
		}
		delete(b.w, hubc)
		b.Unlock()
		b.RangeMutate(func(tx string, ws *hub.Client) bool {
			if ws == hubc {
				delete(b.m, tx)
			}
			return true
		})
		return true
	})
}

func (mb *MessageBus) SendBinary(busKey BusKey, data []byte, filterOptions ...BusSendFilterOption) {
	defer func() {
		if err := recover(); err != nil {
			mb.log.Error().Interface("err", err).Msg("panic! panic! panic! Panic at the MessageBus.Send!")
		}
	}()
	b := mb.busses.Load(busKey)
	b.RangeClients(func(hubc *hub.Client) bool {
		if len(filterOptions) > 0 && !checkHubClientValid(hubc, filterOptions) {
			return true
		}
		go hubc.SendBinaryErrCallback(data, func(err error) {
			b.Remove(hubc)
		})
		return true
	})
}

func (mb *MessageBus) Send(busKey BusKey, data interface{}, filterOptions ...BusSendFilterOption) {
	defer func() {
		if err := recover(); err != nil {
			mb.log.Error().Interface("err", err).Msg("panic! panic! panic! Panic at the MessageBus.Send!")
		}
	}()
	b := mb.busses.Load(busKey)
	b.Range(func(tx string, hubc *hub.Client) bool {
		if len(filterOptions) > 0 && !checkHubClientValid(hubc, filterOptions) {
			return true
		}
		jd, err := json.Marshal(&Message{
			data,
			busKey,
			tx,
		})
		if err != nil {
			mb.log.Err(err).Msgf("json err")
			return true
		}
		go hubc.SendErrorCallback(jd, func(err error) {
			b.Delete(tx)
		})
		return true
	})

}

type BusSendFilterOption struct {
	Ident     string
	SessionID hub.SessionID
}

func checkHubClientValid(cl *hub.Client, bfs []BusSendFilterOption) bool {
	for _, bf := range bfs {
		if bf.Ident != "" && bf.Ident == cl.Identifier() {
			return true
		}
		if bf.SessionID != "" && bf.SessionID == cl.SessionID {
			return true
		}
	}
	return false
}
