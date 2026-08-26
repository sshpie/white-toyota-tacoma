// Package capture handles event collection, sanitization, and persistence.
package capture

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Protocol constants.
const (
	ProtoRedis         = "redis"
	ProtoMySQL         = "mysql"
	ProtoPostgres      = "postgres"
	ProtoMongoDB       = "mongodb"
	ProtoElasticsearch = "elasticsearch"
	ProtoCouchDB       = "couchdb"
)

// Event represents a single attacker interaction.
type Event struct {
	Timestamp string `json:"ts"`
	Protocol  string `json:"proto"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Database  string `json:"database,omitempty"`
	AuthHash  string `json:"auth_hash,omitempty"`
	Command   string `json:"command,omitempty"`
	Payload   string `json:"payload,omitempty"`
}

// Webhook is the exported type alias for callers.
type Webhook = webhookClient

// Store persists events to an append-only JSON-lines file and
// optionally forwards to a webhook.
type Store struct {
	mu      sync.Mutex
	f       *os.File
	webhook *webhookClient
}

// New opens (or creates) the log file and returns a Store.
func New(logPath string, wh *webhookClient) (*Store, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	return &Store{f: f, webhook: wh}, nil
}

// Log sanitizes the event and appends it to the log file.
// It never returns an error to callers — a logging failure is non-fatal.
func (s *Store) Log(e Event) {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	sanitize(&e)

	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("capture: marshal: %v", err)
		return
	}
	b = append(b, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.f.Write(b); err != nil {
		log.Printf("capture: write: %v", err)
	}

	// Webhook is best-effort; do not block the caller.
	if s.webhook != nil {
		go s.webhook.send(b)
	}
}

// Close flushes and closes the log file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// sanitize strips control characters from all string fields.
// This prevents log injection, terminal escape sequences, and
// newline-based SIEM corruption from attacker-supplied content.
func sanitize(e *Event) {
	e.SrcIP = sanitizeStr(e.SrcIP)
	e.Username = sanitizeStr(e.Username)
	e.Password = sanitizeStr(e.Password)
	e.Database = sanitizeStr(e.Database)
	e.AuthHash = sanitizeStr(e.AuthHash)
	e.Command = sanitizeStr(e.Command)
	e.Payload = sanitizeStr(e.Payload)
}

// sanitizeStr removes all Unicode control characters (including \r \n \x00)
// and truncates at 4096 bytes. The JSON output is always valid UTF-8
// because json.Marshal handles remaining non-UTF8 sequences via �.
func sanitizeStr(s string) string {
	if len(s) > 4096 {
		s = s[:4096]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// keep unused import happy
var _ = fmt.Sprintf
