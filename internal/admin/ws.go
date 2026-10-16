package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// handleWS streams live events and per-second traffic to the dashboard.
// websocket.Accept rejects cross-origin handshakes by default.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := c.CloseRead(r.Context())
	msgs, unsub := s.hub.Subscribe()
	defer unsub()

	// Re-validate the session periodically so logout/disable ends the stream.
	recheck := time.NewTicker(time.Minute)
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-recheck.C:
			if _, err := s.session(r); err != nil {
				c.Close(websocket.StatusPolicyViolation, "session expired")
				return
			}
		case m := <-msgs:
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.Write(wctx, websocket.MessageText, m)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
