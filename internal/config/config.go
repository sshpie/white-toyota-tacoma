package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Redis struct {
	Enabled     bool   `json:"enabled"`
	Port        int    `json:"port"`
	Version     string `json:"version"`
	RequirePass string `json:"require_pass"`
}

type MySQL struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Version string `json:"version"`
}

type Postgres struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Version string `json:"version"`
}

type MongoDB struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Version string `json:"version"`
}

type Elasticsearch struct {
	Enabled     bool   `json:"enabled"`
	Port        int    `json:"port"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
	NodeName    string `json:"node_name"`
}

type CouchDB struct {
	Enabled bool   `json:"enabled"`
	Port    int    `json:"port"`
	Version string `json:"version"`
}

type Webhook struct {
	Enabled    bool   `json:"enabled"`
	URL        string `json:"url"`
	AuthHeader string `json:"auth_header"`
	TLSVerify  bool   `json:"tls_verify"`
}

type Config struct {
	ListenAddr            string        `json:"listen_addr"`
	LogFile               string        `json:"log_file"`
	MaxConnections        int           `json:"max_connections"`
	ConnectionTimeoutSecs int           `json:"connection_timeout_seconds"`
	MaxRequestBodyBytes   int64         `json:"max_request_body_bytes"`
	Redis                 Redis         `json:"redis"`
	MySQL                 MySQL         `json:"mysql"`
	Postgres              Postgres      `json:"postgres"`
	MongoDB               MongoDB       `json:"mongodb"`
	Elasticsearch         Elasticsearch `json:"elasticsearch"`
	CouchDB               CouchDB       `json:"couchdb"`
	Webhook               Webhook       `json:"webhook"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	// Limit config file to 1 MB to prevent resource exhaustion on malformed input.
	dec := json.NewDecoder(&limitedReader{r: f, n: 1 << 20})
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.MaxConnections < 0 {
		return fmt.Errorf("max_connections must be >= 0")
	}
	if c.ConnectionTimeoutSecs < 0 {
		return fmt.Errorf("connection_timeout_seconds must be >= 0")
	}
	if c.MaxRequestBodyBytes < 0 {
		return fmt.Errorf("max_request_body_bytes must be >= 0")
	}
	if c.Webhook.Enabled && c.Webhook.URL == "" {
		return fmt.Errorf("webhook.url required when webhook.enabled is true")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0"
	}
	if c.LogFile == "" {
		c.LogFile = "tacoma-events.json"
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 200
	}
	if c.ConnectionTimeoutSecs == 0 {
		c.ConnectionTimeoutSecs = 30
	}
	if c.MaxRequestBodyBytes == 0 {
		c.MaxRequestBodyBytes = 1 << 20
	}
	if c.Redis.Port == 0 {
		c.Redis.Port = 6379
	}
	if c.Redis.Version == "" {
		c.Redis.Version = "7.2.4"
	}
	if c.MySQL.Port == 0 {
		c.MySQL.Port = 3306
	}
	if c.MySQL.Version == "" {
		c.MySQL.Version = "8.0.36"
	}
	if c.Postgres.Port == 0 {
		c.Postgres.Port = 5432
	}
	if c.Postgres.Version == "" {
		c.Postgres.Version = "16.2"
	}
	if c.MongoDB.Port == 0 {
		c.MongoDB.Port = 27017
	}
	if c.MongoDB.Version == "" {
		c.MongoDB.Version = "7.0.8"
	}
	if c.Elasticsearch.Port == 0 {
		c.Elasticsearch.Port = 9200
	}
	if c.Elasticsearch.Version == "" {
		c.Elasticsearch.Version = "8.13.2"
	}
	if c.Elasticsearch.ClusterName == "" {
		c.Elasticsearch.ClusterName = "production"
	}
	if c.Elasticsearch.NodeName == "" {
		c.Elasticsearch.NodeName = "node-1"
	}
	if c.CouchDB.Port == 0 {
		c.CouchDB.Port = 5984
	}
	if c.CouchDB.Version == "" {
		c.CouchDB.Version = "3.3.3"
	}
}

// limitedReader prevents malformed / oversized config files from consuming unbounded memory.
type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, fmt.Errorf("config file exceeds size limit")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}
