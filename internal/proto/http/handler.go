// Package http implements the Elasticsearch and CouchDB HTTP honeypot handlers.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"white-toyota-tacoma/internal/capture"
	"white-toyota-tacoma/internal/fingerprint"
)

// ServeElasticsearch starts an Elasticsearch-compatible HTTP honeypot.
func ServeElasticsearch(
	ctx context.Context,
	addr string,
	store *capture.Store,
	fp *fingerprint.FP,
	cfg ESConfig,
	maxBodyBytes int64,
) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", esRootHandler(fp, cfg))
	mux.HandleFunc("/_nodes", esNodesHandler(fp, cfg))
	mux.HandleFunc("/_nodes/", esNodesHandler(fp, cfg))
	mux.HandleFunc("/_cluster/health", esClusterHealthHandler(fp, cfg))
	mux.HandleFunc("/_cluster/stats", esClusterStatsHandler(fp, cfg))
	mux.HandleFunc("/_cat/", esCatHandler(fp, cfg, store, maxBodyBytes))
	mux.HandleFunc("/_search", esSearchHandler(fp, cfg, store, maxBodyBytes))
	mux.HandleFunc("/_xpack", esXpackHandler(fp, cfg))
	mux.HandleFunc("/", esCatchAllHandler(fp, cfg, store, maxBodyBytes))

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// ReadHeaderTimeout prevents Slowloris on headers.
		ReadHeaderTimeout: 10 * time.Second,
		// BaseContext so we honour ctx cancellation.
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	log.Printf("http: elasticsearch listening on %s", addr)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ServeCouchDB starts a CouchDB-compatible HTTP honeypot.
func ServeCouchDB(
	ctx context.Context,
	addr string,
	store *capture.Store,
	fp *fingerprint.FP,
	couchVersion string,
	maxBodyBytes int64,
) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", couchRootHandler(fp, couchVersion))
	mux.HandleFunc("/_session", couchSessionHandler(fp, couchVersion, store, maxBodyBytes))
	mux.HandleFunc("/_utils/", couchFutonHandler())
	mux.HandleFunc("/", couchDBHandler(couchVersion, store, maxBodyBytes))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	log.Printf("http: couchdb listening on %s", addr)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ESConfig holds Elasticsearch honeypot configuration.
type ESConfig struct {
	Version     string
	ClusterName string
	NodeName    string
}

// ---- Elasticsearch handlers ----

func esRootHandler(fp *fingerprint.FP, cfg ESConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			esCatchAllHandler(fp, cfg, nil, 0)(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"name":         cfg.NodeName,
			"cluster_name": cfg.ClusterName,
			"cluster_uuid": fp.ESNodeUUID,
			"version": map[string]interface{}{
				"number":                           cfg.Version,
				"build_flavor":                     "default",
				"build_type":                       "tar",
				"build_hash":                       fp.ESBuildHash,
				"build_date":                       "2024-03-22T03:35:46.757803421Z",
				"build_snapshot":                   false,
				"lucene_version":                   "9.10.0",
				"minimum_wire_compatibility_version": "7.17.0",
				"minimum_index_compatibility_version": "7.0.0",
			},
			"tagline": "You Know, for Search",
		})
	}
}

func esNodesHandler(fp *fingerprint.FP, cfg ESConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"_nodes": map[string]interface{}{
				"total":      1,
				"successful": 1,
				"failed":     0,
			},
			"cluster_name": cfg.ClusterName,
			"nodes": map[string]interface{}{
				fp.ESNodeUUID: map[string]interface{}{
					"name":             cfg.NodeName,
					"transport_address": fmt.Sprintf("%s:9300", fp.ESHostname),
					"host":             fp.ESHostname,
					"ip":               fp.ESHostname,
					"version":          cfg.Version,
					"build_hash":       fp.ESBuildHash,
					"roles":            []string{"master", "data", "ingest"},
					"os": map[string]interface{}{
						"name":          "Linux",
						"arch":          "amd64",
						"version":       "5.15.0",
						"available_processors": 4,
					},
					"process": map[string]interface{}{
						"id":                  fp.ESPID,
						"mlockall":            false,
					},
					"network": map[string]interface{}{
						"primary_interface": map[string]interface{}{
							"address":     fp.ESHostname,
							"name":        "eth0",
							"mac_address": fp.ESMACAddress,
						},
					},
				},
			},
		})
	}
}

func esClusterHealthHandler(fp *fingerprint.FP, cfg ESConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"cluster_name":                cfg.ClusterName,
			"status":                      "green",
			"timed_out":                   false,
			"number_of_nodes":             1,
			"number_of_data_nodes":        1,
			"active_primary_shards":       0,
			"active_shards":               0,
			"relocating_shards":           0,
			"initializing_shards":         0,
			"unassigned_shards":           0,
			"delayed_unassigned_shards":   0,
			"number_of_pending_tasks":     0,
			"number_of_in_flight_fetch":   0,
			"task_max_waiting_in_queue_millis": 0,
			"active_shards_percent_as_number": 100.0,
		})
	}
}

func esClusterStatsHandler(fp *fingerprint.FP, cfg ESConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"cluster_uuid": fp.ESNodeUUID,
			"cluster_name": cfg.ClusterName,
			"status":       "green",
			"nodes":        map[string]interface{}{"count": map[string]int{"total": 1}},
			"indices":      map[string]interface{}{"count": 0, "docs": map[string]int{"count": 0}},
		})
	}
}

func esCatHandler(fp *fingerprint.FP, cfg ESConfig, store *capture.Store, maxBodyBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logHTTPEvent(r, store, capture.ProtoElasticsearch, maxBodyBytes)
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(""))
	}
}

func esSearchHandler(fp *fingerprint.FP, cfg ESConfig, store *capture.Store, maxBodyBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logHTTPEvent(r, store, capture.ProtoElasticsearch, maxBodyBytes)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"took":      1,
			"timed_out": false,
			"_shards":   map[string]int{"total": 0, "successful": 0, "failed": 0},
			"hits": map[string]interface{}{
				"total":     map[string]interface{}{"value": 0, "relation": "eq"},
				"max_score": nil,
				"hits":      []interface{}{},
			},
		})
	}
}

func esXpackHandler(fp *fingerprint.FP, cfg ESConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"build": map[string]string{
				"date":  "2024-03-22T03:35:46.757803421Z",
				"hash":  fp.ESBuildHash,
			},
			"license": map[string]interface{}{
				"status": "active",
				"type":   "basic",
			},
		})
	}
}

func esCatchAllHandler(fp *fingerprint.FP, cfg ESConfig, store *capture.Store, maxBodyBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store != nil {
			logHTTPEvent(r, store, capture.ProtoElasticsearch, maxBodyBytes)
		}
		// Sanitize path before writing into response — never reflect raw input.
		safePath := sanitizePath(r.URL.Path)
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": map[string]interface{}{
				"root_cause": []interface{}{
					map[string]interface{}{
						"type":   "index_not_found_exception",
						"reason": "no such index",
						"index":  safePath,
					},
				},
				"type":  "index_not_found_exception",
				"reason": "no such index",
			},
			"status": 404,
		})
	}
}

// ---- CouchDB handlers ----

func couchRootHandler(fp *fingerprint.FP, version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			couchDBHandler(version, nil, 0)(w, r)
			return
		}
		writeJSONWithContentType(w, http.StatusOK, map[string]interface{}{
			"couchdb": "Welcome",
			"version": version,
			"git_sha": fp.ESBuildHash[:8],
			"features": []string{"access-ready", "partitioned", "pluggable-storage-engines", "reshard"},
			"vendor":   map[string]string{"name": "The Apache Software Foundation"},
		})
	}
}

func couchSessionHandler(fp *fingerprint.FP, version string, store *capture.Store, maxBodyBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, portStr, _ := net.SplitHostPort(r.RemoteAddr)
		port := 0
		fmt.Sscanf(portStr, "%d", &port)

		if r.Method == http.MethodPost {
			body := readLimitedBody(r, maxBodyBytes)
			username, password := "", ""

			// Try JSON body first.
			var creds struct {
				Name     string `json:"name"`
				Password string `json:"password"`
			}
			if json.Unmarshal(body, &creds) == nil {
				username = creds.Name
				password = creds.Password
			} else {
				// Try Basic auth header.
				username, password, _ = r.BasicAuth()
			}

			if username != "" || password != "" {
				store.Log(capture.Event{
					Protocol: capture.ProtoCouchDB,
					SrcIP:    ip,
					SrcPort:  port,
					Username: username,
					Password: password,
					Command:  "SESSION",
				})
			}

			writeJSONWithContentType(w, http.StatusOK, map[string]interface{}{
				"ok":    true,
				"name":  username,
				"roles": []string{"_admin"},
			})
			return
		}

		// GET /_session
		writeJSONWithContentType(w, http.StatusOK, map[string]interface{}{
			"ok":   true,
			"info": map[string]interface{}{"authentication_db": "_users"},
			"userCtx": map[string]interface{}{
				"name":  nil,
				"roles": []interface{}{},
			},
		})
	}
}

func couchFutonHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><h1>CouchDB Fauxton</h1></body></html>"))
	}
}

func couchDBHandler(version string, store *capture.Store, maxBodyBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if store != nil {
			logHTTPEvent(r, store, capture.ProtoCouchDB, maxBodyBytes)
		}
		db := strings.TrimPrefix(r.URL.Path, "/")
		db = strings.Split(db, "/")[0]
		db = sanitizePath(db)

		switch r.Method {
		case http.MethodGet:
			writeJSONWithContentType(w, http.StatusOK, map[string]interface{}{
				"db_name":            db,
				"doc_count":          0,
				"doc_del_count":      0,
				"update_seq":         0,
				"purge_seq":          0,
				"compact_running":    false,
				"disk_size":          0,
				"data_size":          0,
				"instance_start_time": "0",
				"disk_format_version": 6,
				"committed_update_seq": 0,
			})
		case http.MethodPut:
			writeJSONWithContentType(w, http.StatusCreated, map[string]interface{}{"ok": true})
		default:
			writeJSONWithContentType(w, http.StatusMethodNotAllowed, map[string]interface{}{
				"error":  "method_not_allowed",
				"reason": "Only GET, PUT supported",
			})
		}
	}
}

// ---- Helpers ----

// logHTTPEvent reads up to maxBodyBytes of the request body, logs the event,
// and replaces r.Body with a new reader containing what was read.
func logHTTPEvent(r *http.Request, store *capture.Store, proto string, maxBodyBytes int64) {
	ip, portStr, _ := net.SplitHostPort(r.RemoteAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	body := readLimitedBody(r, maxBodyBytes)
	payload := ""
	if len(body) > 0 {
		payload = string(body)
	}

	store.Log(capture.Event{
		Protocol: proto,
		SrcIP:    ip,
		SrcPort:  port,
		Command:  sanitizePath(r.Method + " " + r.URL.Path),
		Payload:  payload,
	})
}

// readLimitedBody reads up to maxBytes from r.Body, replacing r.Body
// with an io.NopCloser wrapping the already-read bytes (so handlers
// can re-read it). It never panics on a nil body.
func readLimitedBody(r *http.Request, maxBytes int64) []byte {
	if r.Body == nil {
		return nil
	}
	lr := io.LimitReader(r.Body, maxBytes)
	data, _ := io.ReadAll(lr)
	r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(data)))
	return data
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("X-elastic-product", "Elasticsearch")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeJSONWithContentType(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "must-revalidate")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// sanitizePath returns the path with all characters outside [A-Za-z0-9._/-]
// replaced with '_', preventing injection into JSON strings or log fields.
func sanitizePath(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '/' || r == '.' || r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}
