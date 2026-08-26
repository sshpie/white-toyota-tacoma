// Package server provides a shared TCP listener with connection limiting,
// per-connection timeouts, and per-IP rate limiting.
package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Handler processes a single accepted connection.
// It is called in its own goroutine and must close conn when done.
type Handler func(ctx context.Context, conn net.Conn)

// Server is a bounded TCP listener.
type Server struct {
	addr           string
	handler        Handler
	maxConns       int
	connTimeout    time.Duration

	sem            chan struct{}      // counting semaphore
	totalConns     atomic.Int64
	totalCmds      atomic.Int64

	ipmu           sync.Mutex
	ipCounts       map[string]int    // simple per-IP connection count

	done           chan struct{}
	stopOnce       sync.Once
	wg             sync.WaitGroup
}

// New creates a Server. maxConns 0 is treated as 500.
func New(addr string, handler Handler, maxConns int, connTimeout time.Duration) *Server {
	if maxConns <= 0 {
		maxConns = 500
	}
	return &Server{
		addr:        addr,
		handler:     handler,
		maxConns:    maxConns,
		connTimeout: connTimeout,
		sem:         make(chan struct{}, maxConns),
		ipCounts:    make(map[string]int),
		done:        make(chan struct{}),
	}
}

// Serve listens and accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}

	// Ensure the listener closes when ctx is cancelled.
	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		ln.Close()
	}()

	log.Printf("server: listening on %s (max=%d)", s.addr, s.maxConns)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				s.wg.Wait()
				return nil
			case <-s.done:
				s.wg.Wait()
				return nil
			default:
				log.Printf("server: accept %s: %v", s.addr, err)
				continue
			}
		}

		// Acquire semaphore slot (non-blocking).
		select {
		case s.sem <- struct{}{}:
		default:
			// At capacity — close immediately.
			conn.Close()
			continue
		}

		// Per-IP limit: max 20 simultaneous connections from one IP.
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !s.acquireIP(ip) {
			conn.Close()
			<-s.sem
			continue
		}

		s.totalConns.Add(1)
		s.wg.Add(1)
		go func(c net.Conn, remoteIP string) {
			defer s.wg.Done()
			defer func() {
				<-s.sem
				s.releaseIP(remoteIP)
			}()
			defer c.Close()

			// Set an absolute deadline for the entire connection lifetime.
			if s.connTimeout > 0 {
				c.SetDeadline(time.Now().Add(s.connTimeout))
			}

			s.handler(ctx, c)
		}(conn, ip)
	}
}

// Stop signals the server to stop accepting new connections.
func (s *Server) Stop() {
	s.stopOnce.Do(func() { close(s.done) })
	s.wg.Wait()
}

// TotalConnections returns the total accepted connection count.
func (s *Server) TotalConnections() int64 {
	return s.totalConns.Load()
}

// IncrCommands increments the total command counter and returns the new value.
func (s *Server) IncrCommands() int64 {
	return s.totalCmds.Add(1)
}

// TotalCommands returns the accumulated command count.
func (s *Server) TotalCommands() int64 {
	return s.totalCmds.Load()
}

func (s *Server) acquireIP(ip string) bool {
	s.ipmu.Lock()
	defer s.ipmu.Unlock()
	if s.ipCounts[ip] >= 20 {
		return false
	}
	s.ipCounts[ip]++
	return true
}

func (s *Server) releaseIP(ip string) {
	s.ipmu.Lock()
	defer s.ipmu.Unlock()
	s.ipCounts[ip]--
	if s.ipCounts[ip] <= 0 {
		delete(s.ipCounts, ip)
	}
}
