package wdtt

import (
	"log"
	"sync/atomic"
	"time"
)

type Stats struct {
	TotalBytesUp      atomic.Int64
	TotalBytesDown    atomic.Int64
	ActiveConnections atomic.Int32
}

func NewStats() *Stats {
	return &Stats{}
}

// RunLoop logs the counters once a minute, and only while something moved: a
// line every three seconds kept the log writer (and the phone) busy for nothing.
func (s *Stats) RunLoop(shutdown <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	var lastUp, lastDown int64
	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			up := s.TotalBytesUp.Load()
			down := s.TotalBytesDown.Load()
			if up == lastUp && down == lastDown {
				continue
			}
			lastUp, lastDown = up, down
			totalMB := float64(up+down) / (1024.0 * 1024.0)
			log.Printf("[wdtt] active=%d traffic=%.2f MB", s.ActiveConnections.Load(), totalMB)
		}
	}
}
