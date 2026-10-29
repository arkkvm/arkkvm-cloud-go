// Package ws implements the two WebSocket signaling channels:
// the device channel at "/" and the client channel at
// "/webrtc/signaling/client". All connection state lives in the in-process
// Hub; gorilla/websocket forbids concurrent writers, so every connection owns
// a dedicated writer goroutine fed by a bounded send channel.
package ws

import (
	"context"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn serializes writes for one underlying websocket connection: callers
// push into send from any goroutine; a single writer goroutine is the only
// code that ever calls WriteMessage.
type wsConn struct {
	ws          *websocket.Conn
	send        chan []byte
	ctx         context.Context
	cancel      context.CancelFunc
	writeTimeout time.Duration
	closeOnce   sync.Once
}

func newWSConn(parent context.Context, ws *websocket.Conn, sendBuffer int, writeTimeout time.Duration) *wsConn {
	ctx, cancel := context.WithCancel(parent)
	return &wsConn{
		ws:           ws,
		send:         make(chan []byte, sendBuffer),
		ctx:          ctx,
		cancel:       cancel,
		writeTimeout: writeTimeout,
	}
}

// start launches the writer goroutine.
func (c *wsConn) start() {
	go c.writer()
}

// writer drains the send channel until the connection is cancelled.
func (c *wsConn) writer() {
	for {
		select {
		case payload := <-c.send:
			_ = c.ws.SetWriteDeadline(time.Now().Add(c.writeTimeout))
			if err := c.ws.WriteMessage(websocket.TextMessage, payload); err != nil {
				c.cancel()
				return
			}
		case <-c.ctx.Done():
			_ = c.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_ = c.ws.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "server closing"))
			_ = c.ws.Close()
			return
		}
	}
}

// SendTo queues a text message. A send channel that stays full for
// writeTimeout means the peer is stuck: the connection is torn down,
// mirroring the legacy async-send-timeout semantics.
func (c *wsConn) SendTo(payload []byte) error {
	select {
	case c.send <- payload:
		return nil
	case <-c.ctx.Done():
		return context.Canceled
	case <-time.After(c.writeTimeout):
		c.cancel()
		return context.DeadlineExceeded
	}
}

// Done exposes the connection lifecycle to read pumps.
func (c *wsConn) Done() <-chan struct{} { return c.ctx.Done() }

// Close cancels the connection exactly once.
func (c *wsConn) Close() { c.closeOnce.Do(c.cancel) }
