// White Toyota Tacoma — multi-protocol honeypot
// Protocols: Redis, MySQL, PostgreSQL, MongoDB, Elasticsearch, CouchDB
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"white-toyota-tacoma/internal/capture"
	"white-toyota-tacoma/internal/config"
	"white-toyota-tacoma/internal/fingerprint"
	"white-toyota-tacoma/internal/proto/http"
	"white-toyota-tacoma/internal/proto/mongodb"
	"white-toyota-tacoma/internal/proto/mysql"
	"white-toyota-tacoma/internal/proto/postgres"
	"white-toyota-tacoma/internal/proto/redis"
	"white-toyota-tacoma/internal/server"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Build webhook client if configured.
	var wh *capture.Webhook
	if cfg.Webhook.Enabled {
		wh, err = capture.NewWebhook(cfg.Webhook.URL, cfg.Webhook.AuthHeader, cfg.Webhook.TLSVerify)
		if err != nil {
			log.Fatalf("webhook: %v", err)
		}
	}

	store, err := capture.New(cfg.LogFile, wh)
	if err != nil {
		log.Fatalf("capture store: %v", err)
	}
	defer store.Close()

	fp := fingerprint.New(cfg.Elasticsearch.NodeName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Catch OS signals for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("main: received %v, shutting down", sig)
		cancel()
	}()

	timeout := time.Duration(cfg.ConnectionTimeoutSecs) * time.Second
	var wg sync.WaitGroup

	// Redis
	if cfg.Redis.Enabled {
		counters := &redis.Counters{}
		srv := server.New(
			net.JoinHostPort(cfg.ListenAddr, fmt.Sprintf("%d", cfg.Redis.Port)),
			func(ctx context.Context, conn net.Conn) {
				redis.Handler(ctx, conn, store, fp, cfg.Redis.Version, counters)
			},
			cfg.MaxConnections,
			timeout,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ctx); err != nil {
				log.Printf("redis: %v", err)
			}
		}()
	}

	// MySQL
	if cfg.MySQL.Enabled {
		srv := server.New(
			net.JoinHostPort(cfg.ListenAddr, fmt.Sprintf("%d", cfg.MySQL.Port)),
			func(ctx context.Context, conn net.Conn) {
				mysql.Handler(ctx, conn, store, fp, cfg.MySQL.Version)
			},
			cfg.MaxConnections,
			timeout,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ctx); err != nil {
				log.Printf("mysql: %v", err)
			}
		}()
	}

	// PostgreSQL
	if cfg.Postgres.Enabled {
		srv := server.New(
			net.JoinHostPort(cfg.ListenAddr, fmt.Sprintf("%d", cfg.Postgres.Port)),
			func(ctx context.Context, conn net.Conn) {
				postgres.Handler(ctx, conn, store, fp, cfg.Postgres.Version)
			},
			cfg.MaxConnections,
			timeout,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ctx); err != nil {
				log.Printf("postgres: %v", err)
			}
		}()
	}

	// MongoDB
	if cfg.MongoDB.Enabled {
		srv := server.New(
			net.JoinHostPort(cfg.ListenAddr, fmt.Sprintf("%d", cfg.MongoDB.Port)),
			func(ctx context.Context, conn net.Conn) {
				mongodb.Handler(ctx, conn, store, fp, cfg.MongoDB.Version)
			},
			cfg.MaxConnections,
			timeout,
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ctx); err != nil {
				log.Printf("mongodb: %v", err)
			}
		}()
	}

	// Elasticsearch (HTTP)
	if cfg.Elasticsearch.Enabled {
		esCfg := http.ESConfig{
			Version:     cfg.Elasticsearch.Version,
			ClusterName: cfg.Elasticsearch.ClusterName,
			NodeName:    cfg.Elasticsearch.NodeName,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := net.JoinHostPort(cfg.ListenAddr, fmt.Sprintf("%d", cfg.Elasticsearch.Port))
			if err := http.ServeElasticsearch(ctx, addr, store, fp, esCfg, cfg.MaxRequestBodyBytes); err != nil {
				log.Printf("elasticsearch: %v", err)
			}
		}()
	}

	// CouchDB (HTTP)
	if cfg.CouchDB.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := net.JoinHostPort(cfg.ListenAddr, fmt.Sprintf("%d", cfg.CouchDB.Port))
			if err := http.ServeCouchDB(ctx, addr, store, fp, cfg.CouchDB.Version, cfg.MaxRequestBodyBytes); err != nil {
				log.Printf("couchdb: %v", err)
			}
		}()
	}

	log.Printf("White Toyota Tacoma running (fingerprint node_id=%s pid=%d)", fp.ESNodeUUID[:8], fp.RedisProcessID)
	wg.Wait()
	log.Printf("main: all services stopped")
}

// Ensure unused imports are referenced.
var _ = strings.ToLower
