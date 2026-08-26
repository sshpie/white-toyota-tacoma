# White Toyota Tacoma

Multi-protocol database honeypot. Listens on Redis, MySQL, PostgreSQL, MongoDB, Elasticsearch, and CouchDB ports simultaneously. Logs every credential, query, and command to a JSON-lines file. Zero external dependencies.

## Quick start

```bash
go install github.com/sshpie/white-toyota-tacoma/cmd/tacoma@latest
cp config.example.json config.json
tacoma -config config.json
```

Or build from source:

```bash
git clone https://github.com/sshpie/white-toyota-tacoma
cd white-toyota-tacoma
go build -o tacoma ./cmd/tacoma/
./tacoma -config config.json
```

## Protocols

| Protocol | Default port | Captured |
|----------|-------------|---------|
| Redis | 6379 | AUTH passwords, SET keys, FLUSHALL/FLUSHDB, raw commands |
| MySQL | 3306 | Username, database, native password hash, COM_QUERY text |
| PostgreSQL | 5432 | Username, database, MD5 auth hash, simple query text |
| MongoDB | 27017 | OP_QUERY + OP_MSG, SASL auth documents, isMaster/hello |
| Elasticsearch | 9200 | HTTP method + path, request body |
| CouchDB | 5984 | `/_session` credentials (JSON body + Basic auth), DB operations |

All events write to a JSON-lines log. Optional webhook delivery with enforced TLS.

## Design

Built after auditing every major open-source honeypot and cataloguing what they get wrong. The fixes are not optional — they are load-bearing for the honeypot to stay alive under real attacker traffic.

**No static fingerprints.** Every identifier real services randomize is generated from `crypto/rand` at startup: Redis `run_id` and `master_replid`, MySQL scramble and connection ID, PostgreSQL backend PID and MD5 salt, MongoDB cluster/node UUID, Elasticsearch node UUID + build hash + MAC address. No two deployments share a fingerprint. No value repeats across restarts.

**No predictable PRNG.** Auth challenges, PIDs, MACs, UUIDs: all `crypto/rand`. Never `math/rand`, never `rand()` seeded from `time(NULL)`. Real servers use entropy; so does this.

**Bounds-checked parsers.** Every wire protocol parser validates length before allocation. `io.ReadFull` everywhere. Null terminator searches return -1 and are handled. No equivalent of pghoney's `buf[-4:0]` negative-index panic or MongoDB-HoneyProxy's swallowed errors.

**Connection limiting.** Semaphore cap (default 500 total, 20 per IP). Scanner floods hit the cap and get dropped cleanly — no goroutine leak.

**Idle timeouts.** Read deadline resets on each successful read. Slow-loris requires actually sending data to hold the connection. An absolute per-connection wall-clock deadline fires as a backstop.

**No blocking DNS.** Source IP extracted from the already-resolved `conn.RemoteAddr()`. No reverse lookup stalling the accept loop.

**Sanitized logging.** All attacker-supplied strings are stripped of Unicode control characters (`\r`, `\n`, `\x00`, ESC sequences) before any log write. Log injection, ANSI injection, and CEF field corruption are not possible.

**Request body limits.** `io.LimitReader` on every POST body. A streaming request body cannot OOM the process.

**Enforced TLS output.** Webhook sender uses `tls.Config{MinVersion: tls.VersionTLS12}`. `tls_verify: false` in config is accepted, logged as a warning, and ignored.

**JSON config only.** `json.Decoder` with `DisallowUnknownFields` and a 1 MB cap. No YAML parser, no `eval`, no RCE surface at config load time.

**OP_MSG implemented.** Any MongoDB driver built against 3.6+ uses OP_MSG (opcode 2013) by default. MongoDB-HoneyProxy captures nothing from those clients because it only handles OP_QUERY (2004). Tacoma handles both.

**HELLO handler.** Redis 7+ clients send `HELLO [proto] AUTH username password` before falling back to RESP2. The credentials are captured before returning `NOPROTO`.

## Config

```bash
cp config.example.json config.json
```

```json
{
  "listen_addr": "0.0.0.0",
  "log_file": "tacoma-events.json",
  "max_connections": 500,
  "connection_timeout_seconds": 120,
  "max_request_body_bytes": 1048576,
  "redis":   { "enabled": true, "port": 6379, "version": "7.2.4" },
  "mysql":   { "enabled": true, "port": 3306, "version": "8.0.36" },
  "postgres":{ "enabled": true, "port": 5432, "version": "16.2"  },
  "mongodb": { "enabled": true, "port": 27017, "version": "7.0.8" },
  "elasticsearch": {
    "enabled": true, "port": 9200,
    "version": "8.13.2",
    "cluster_name": "production",
    "node_name": "node-1"
  },
  "couchdb": { "enabled": true, "port": 5984, "version": "3.3.3" },
  "webhook": {
    "enabled": false,
    "url": "https://your-collector/events",
    "auth_header": "Bearer <token>",
    "tls_verify": true
  }
}
```

Set `"enabled": false` on any protocol to disable it. Version strings are configurable — match whatever you want to blend in with. `max_request_body_bytes` caps POST bodies for Elasticsearch and CouchDB.

## Event log

One JSON object per line:

```
{"ts":"2026-08-25T19:47:01.234Z","proto":"mysql","src_ip":"1.2.3.4","src_port":54321,"username":"root","database":"","auth_hash":"a3f2c1...","command":"CONNECT"}
{"ts":"2026-08-25T19:47:01.891Z","proto":"redis","src_ip":"1.2.3.4","src_port":54322,"password":"admin123","command":"AUTH"}
{"ts":"2026-08-25T19:47:02.100Z","proto":"redis","src_ip":"1.2.3.4","src_port":54322,"username":"default","password":"redis","command":"HELLO AUTH"}
{"ts":"2026-08-25T19:47:02.400Z","proto":"elasticsearch","src_ip":"5.6.7.8","src_port":41200,"command":"POST /_search","payload":"{\"query\":{\"match_all\":{}}}"}
{"ts":"2026-08-25T19:47:03.010Z","proto":"mongodb","src_ip":"9.10.11.12","src_port":52100,"command":"OP_MSG authenticate","payload":"{\"authenticate\":1,\"user\":\"admin\"}"}
```

Fields present depend on protocol and event type. All attacker-supplied strings are sanitized before writing.

### jq recipes

```bash
# Unique source IPs
jq -r .src_ip tacoma-events.json | sort -u

# All captured passwords
jq -r 'select(.password != null) | [.ts, .proto, .src_ip, .password] | @tsv' tacoma-events.json

# MySQL hashes ready for hashcat (format: *HASH or raw hex)
jq -r 'select(.proto == "mysql" and .auth_hash != null) | .auth_hash' tacoma-events.json

# Redis FLUSHALL attempts
jq 'select(.proto == "redis" and (.command == "FLUSHALL" or .command == "FLUSHDB"))' tacoma-events.json

# Activity by source IP (sorted by count)
jq -r .src_ip tacoma-events.json | sort | uniq -c | sort -rn | head -20
```

## Ports

Listening on default database ports requires elevated privileges on Linux. Either run as root (not recommended for production), use `setcap`, or change the ports in config:

```bash
# setcap approach — grants CAP_NET_BIND_SERVICE only
sudo setcap cap_net_bind_service=+ep ./tacoma
```

Or run on high ports and redirect with iptables:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 6379 -j REDIRECT --to-port 16379
# repeat for 3306, 5432, 27017, 9200, 5984
```
