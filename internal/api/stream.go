package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alstdev/aldap/internal/events"
)

// handleStream serves GET /v1/events/stream (SSE). The id of every event is
// its seq; a client that reconnects with Last-Event-ID (or ?since=) gets
// every record after it that the ring buffer still holds.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request, _ *call) {
	last, ok := resumeFrom(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "Last-Event-ID and since must be a sequence number")
		return
	}
	// Subscribe before reading the backlog so nothing falls in between.
	sub := s.o.Bus.Subscribe(s.o.StreamQueue)
	defer sub.Close()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	st := &streamer{w: w, rc: http.NewResponseController(w), bus: s.o.Bus, types: eventFilter(r), last: last}
	_ = st.rc.SetWriteDeadline(time.Time{}) //nolint:errcheck // unsupported writers keep the server deadline
	if !st.backfill(0) {
		return
	}
	tick := time.NewTicker(s.o.Heartbeat)
	defer tick.Stop()
	var dropped uint64
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if !st.ping() {
				return
			}
		case rec := <-sub.C:
			if !st.deliver(rec) {
				return
			}
		}
		// Records dropped after the last queued one leave no gap to see:
		// read them from the ring buffer as soon as a drop is counted.
		if n := sub.Dropped(); n != dropped {
			dropped = n
			if !st.backfill(0) {
				return
			}
		}
	}
}

// streamer writes the records of one SSE client in seq order.
type streamer struct {
	w     http.ResponseWriter
	rc    *http.ResponseController
	bus   *events.Bus
	types map[string]bool
	last  uint64
}

// send writes rec unless it was sent already or is filtered out.
func (st *streamer) send(rec events.Record) bool {
	if rec.Seq <= st.last {
		return true
	}
	st.last = rec.Seq
	if !keep(st.types, rec) {
		return true
	}
	// text/event-stream: seq, an event kind constant and the record JSON.
	_, err := fmt.Fprintf(st.w, "id: %d\nevent: %s\ndata: %s\n\n", rec.Seq, rec.Event, rec.JSON())
	return err == nil
}

// backfill sends the buffered records after last (and before upTo when set).
func (st *streamer) backfill(upTo uint64) bool {
	for _, rec := range st.bus.Since(st.last, 0) {
		if upTo != 0 && rec.Seq >= upTo {
			break
		}
		if !st.send(rec) {
			return false
		}
	}
	return st.rc.Flush() == nil
}

// deliver sends a live record; a gap means the queue overflowed and is
// filled from the ring buffer first.
func (st *streamer) deliver(rec events.Record) bool {
	if rec.Seq > st.last+1 && !st.backfill(rec.Seq) {
		return false
	}
	return st.send(rec) && st.rc.Flush() == nil
}

func (st *streamer) ping() bool {
	_, err := fmt.Fprint(st.w, ": ping\n\n")
	return err == nil && st.rc.Flush() == nil
}

// resumeFrom reads Last-Event-ID, else ?since=, else 0 (the whole buffer).
func resumeFrom(r *http.Request) (uint64, bool) {
	v := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if v == "" {
		v = r.URL.Query().Get("since")
	}
	if v == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(v, 10, 64)
	return n, err == nil
}
