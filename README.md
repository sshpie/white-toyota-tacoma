# White Toyota Tacoma

Multi-protocol honeypot built from scratch after auditing every major open-source honeypot and cataloguing every vulnerability class they share. Zero external dependencies. Zero static fingerprints.

## Protocols

| Protocol | Port | What it captures |
|----------|------|-----------------|
| Redis | 6379 | AUTH passwords, commands (SET/GET/KEYS/FLUSHALL/etc.) |
| MySQL | 3306 | Username, database, native auth hash, queries |
| PostgreSQL | 5432 | Username, database, MD5 auth hash, queries |
| MongoDB | 27017 | OP_QUERY + OP_MSG, SASL auth documents, commands |
| Elasticsearch | 9200 | HTTP method + path, request body payloads |
| CouchDB | 5984 | `/_session` credentials (JSON body + Basic auth), DB ops |

All events are written to a JSON-lines log file. Optional webhook output with enforced TLS verification.

## What makes it different

Every open-source honeypot in the ecosystem shares the same vulnerability classes. This one was designed to fix all of them.

**No static fingerprints.** Every value that real services randomize — Redis `run_id` and `master_replid`, MySQL scramble bytes, PostgreSQL backend PID and MD5 salt, MongoDB cluster/node UUID, Elasticsearch node UUID + build hash + MAC — is generated from `crypto/rand` at startup. No two deployments share a fingerprint. No value is the same across restarts.

**No predictable PRNG.** Auth challenges, PIDs, MACs, connection IDs: all from `crypto/rand`. Never `math/rand`, never `rand()` seeded with `time(NULL)`.

**Bounds-checked parsers.** Every wire protocol parser checks `len(slice)` before indexing. `io.ReadFull` everywhere (not `Read`). Null terminator searches return -1 and are handled. No equivalent of pghoney's `buf[-4:0]` panic or MongoDB-HoneyProxy's missing error handler.

**Connection limiting.** Semaphore cap (configurable, default 200 total + 20 per IP). No unbounded goroutine spawn.

**Idle timeouts, not wall-clock deadlines.** Read deadline is reset on each successful read — slow-loris requires actually sending data, not just holding the connection open.

**No blocking DNS.** `net.SplitHostPort` on the already-resolved `RemoteAddr()`. No `getnameinfo()` equivalent blocking the event loop.

**Sanitized logging.** All attacker-supplied strings are stripped of Unicode control characters (including `\r`, `\n`, `\x00`) before any log write. No log injection, no ANSI escape injection, no CEF field corruption.

**Request body limits.** `io.LimitReader` wraps every POST body read. No `ioutil.ReadAll` equivalent that lets an attacker OOM the process with a streaming body.

**Enforced TLS for output.** Webhook sender uses `tls.Config{MinVersion: tls.VersionTLS12}` and ignores any `tls_verify: false` config value — it logs a warning and proceeds verified anyway.

**JSON config.** `json.Decoder` with `DisallowUnknownFields` and a 1 MB size cap. No `YAML.load` equivalent RCE surface.

**OP_MSG implemented.** MongoDB-HoneyProxy captures zero credentials from any driver built against MongoDB ≥ 3.6 because it only handles OP_QUERY (2004). Tacoma handles both OP_QUERY and OP_MSG (2013).

## Install

```bash
go install github.com/sshpie/white-toyota-tacoma/cmd/tacoma@latest
```

Or build from source (requires Go 1.21+, no other dependencies):

```bash
git clone https://github.com/sshpie/white-toyota-tacoma
cd white-toyota-tacoma
go build -o white-toyota-tacoma ./cmd/tacoma/
```

## Configure

```bash
cp config.example.json config.json
# edit ports, versions, enable/disable protocols
./white-toyota-tacoma -config config.json
```

### config.json fields

```json
{
  "listen_addr": "0.0.0.0",
  "log_file": "tacoma-events.json",
  "max_connections": 200,
  "connection_timeout_seconds": 30,
  "max_request_body_bytes": 1048576,
  "redis":   { "enabled": true, "port": 6379, "version": "7.2.4" },
  "mysql":   { "enabled": true, "port": 3306, "version": "8.0.36" },
  "postgres":{ "enabled": true, "port": 5432, "version": "16.2" },
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

Disable any protocol by setting `"enabled": false`. Port and version strings are configurable — set them to match whatever you're trying to blend in with.

## Event log format

One JSON object per line:

```json
{"ts":"2026-08-25T19:47:01.234Z","proto":"mysql","src_ip":"1.2.3.4","src_port":54321,"username":"root","database":"","auth_hash":"a3f2...","command":"CONNECT"}
{"ts":"2026-08-25T19:47:01.891Z","proto":"redis","src_ip":"1.2.3.4","src_port":54322,"password":"admin123","command":"AUTH"}
{"ts":"2026-08-25T19:47:02.100Z","proto":"elasticsearch","src_ip":"1.2.3.4","src_port":54323,"command":"POST /_search","payload":"{\"query\":{\"match_all\":{}}}"}
```

Fields present depend on protocol and event type. Parse with `jq`:

```bash
# All unique source IPs
jq -r .src_ip tacoma-events.json | sort -u

# All captured passwords
jq -r 'select(.password != null) | [.ts, .proto, .src_ip, .password] | @tsv' tacoma-events.json

# MySQL auth hashes for cracking
jq -r 'select(.proto == "mysql" and .auth_hash != null) | .auth_hash' tacoma-events.json
```

## Security design notes

**Why accept every auth attempt?** Real honeypots that reject bad passwords stop receiving data. Tacoma accepts all credentials to keep the session alive and collect maximum attacker behavior. The captured hash is logged regardless.

**Why no rate limiting beyond the semaphore?** The per-IP connection cap (20 simultaneous) handles most scanner floods. Token bucket rate limiting per IP adds state that creates its own DoS surface; the connection cap is simpler and sufficient.

**Fingerprint resistance.** The fingerprints generated at startup are printed to the log at launch so you can check them:

```
White Toyota Tacoma running (fingerprint node_id=x7Kp2qRm pid=31847)
```

Different on every run. No value matches any known honeypot signature.
