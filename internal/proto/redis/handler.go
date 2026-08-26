package redis

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sshpie/white-toyota-tacoma/internal/capture"
	"github.com/sshpie/white-toyota-tacoma/internal/fingerprint"
)

// Counters tracks per-server Redis stats.
type Counters struct {
	received atomic.Int64 // total_connections_received (monotonic)
	active   atomic.Int64 // currently active connections
	commands atomic.Int64
}

// Handler serves the Redis protocol to one connection.
// It captures credentials and commands; accepts all AUTH passwords
// to keep the session alive and maximise data collection.
func Handler(
	ctx context.Context,
	conn net.Conn,
	store *capture.Store,
	fp *fingerprint.FP,
	version string,
	counters *Counters,
) {
	counters.received.Add(1)
	counters.active.Add(1)
	defer counters.active.Add(-1)

	ip, portStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	r := bufio.NewReaderSize(conn, 32*1024)
	w := bufio.NewWriterSize(conn, 32*1024)

	flush := func() error {
		return w.Flush()
	}

	// Extend the per-read deadline on each successful read to implement
	// an idle timeout rather than an absolute connection-level deadline.
	// (The absolute deadline is set by server.go as a backstop.)
	resetDeadline := func() {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}

	resetDeadline()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cmd, err := ReadCommand(r)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "timeout") {
				// Protocol error or connection reset — normal for scanners.
			}
			return
		}
		resetDeadline()
		counters.commands.Add(1)

		if err := handleCmd(cmd, w, store, fp, version, ip, port, &counters.commands, &counters.received); err != nil {
			return
		}
		if err := flush(); err != nil {
			return
		}
	}
}

func handleCmd(
	cmd *Command,
	w io.Writer,
	store *capture.Store,
	fp *fingerprint.FP,
	version, ip string,
	port int,
	totalCmds *atomic.Int64,
	totalConns *atomic.Int64,
) error {
	switch cmd.Name {
	case "HELLO":
		// HELLO [protover [AUTH username password] [SETNAME clientname]]
		// Capture embedded credentials before declining the protocol upgrade.
		args := cmd.Args[1:]
		for i := 0; i+2 < len(args); i++ {
			if strings.ToUpper(args[i]) == "AUTH" {
				store.Log(capture.Event{
					Protocol: capture.ProtoRedis,
					SrcIP:    ip,
					SrcPort:  port,
					Username: args[i+1],
					Password: args[i+2],
					Command:  "HELLO AUTH",
				})
				break
			}
		}
		return WriteError(w, "NOPROTO sorry, this server does not support HELLO")

	case "COMMAND":
		return WriteSimple(w, "OK")

	case "PING":
		if len(cmd.Args) > 1 {
			return WriteBulk(w, cmd.Args[1])
		}
		return WriteSimple(w, "PONG")

	case "AUTH":
		if len(cmd.Args) < 2 {
			return WriteError(w, "wrong number of arguments for 'auth' command")
		}
		password := cmd.Args[1]
		store.Log(capture.Event{
			Protocol: capture.ProtoRedis,
			SrcIP:    ip,
			SrcPort:  port,
			Password: password,
			Command:  "AUTH",
		})
		return WriteSimple(w, "OK")

	case "SELECT":
		return WriteSimple(w, "OK")

	case "QUIT":
		WriteSimple(w, "OK")
		return io.EOF

	case "INFO":
		section := ""
		if len(cmd.Args) > 1 {
			section = strings.ToLower(cmd.Args[1])
		}
		return WriteBulk(w, buildInfo(fp, version, section, totalCmds.Load(), totalConns.Load()))

	case "CONFIG":
		return handleConfig(cmd, w)

	case "KEYS":
		return WriteArray(w, []string{})

	case "DBSIZE":
		return WriteInt(w, 0)

	case "SET":
		if len(cmd.Args) < 3 {
			return WriteError(w, "wrong number of arguments for 'set' command")
		}
		store.Log(capture.Event{
			Protocol: capture.ProtoRedis,
			SrcIP:    ip,
			SrcPort:  port,
			Command:  fmt.Sprintf("SET %s", cmd.Args[1]),
		})
		return WriteSimple(w, "OK")

	case "GET":
		if len(cmd.Args) < 2 {
			return WriteError(w, "wrong number of arguments for 'get' command")
		}
		return WriteNull(w)

	case "DEL":
		return WriteInt(w, 0)

	case "EXISTS":
		return WriteInt(w, 0)

	case "TTL":
		return WriteInt(w, -1)

	case "FLUSHALL", "FLUSHDB":
		store.Log(capture.Event{
			Protocol: capture.ProtoRedis,
			SrcIP:    ip,
			SrcPort:  port,
			Command:  cmd.Name,
		})
		return WriteSimple(w, "OK")

	case "CLIENT":
		if len(cmd.Args) > 1 && strings.ToUpper(cmd.Args[1]) == "SETNAME" {
			return WriteSimple(w, "OK")
		}
		if len(cmd.Args) > 1 && strings.ToUpper(cmd.Args[1]) == "GETNAME" {
			return WriteNull(w)
		}
		return WriteSimple(w, "OK")

	case "CLUSTER":
		return WriteError(w, "This instance has cluster support disabled")

	case "DEBUG", "MONITOR", "SLOWLOG", "OBJECT", "WAIT":
		store.Log(capture.Event{
			Protocol: capture.ProtoRedis,
			SrcIP:    ip,
			SrcPort:  port,
			Command:  cmd.Name,
		})
		return WriteError(w, "unknown command '"+strings.ToLower(cmd.Name)+"'")

	default:
		store.Log(capture.Event{
			Protocol: capture.ProtoRedis,
			SrcIP:    ip,
			SrcPort:  port,
			Command:  cmd.Name,
		})
		return WriteError(w, "unknown command '"+strings.ToLower(cmd.Name)+"', with args beginning with: ")
	}
}

func handleConfig(cmd *Command, w io.Writer) error {
	if len(cmd.Args) < 2 {
		return WriteError(w, "wrong number of arguments for 'config' command")
	}
	sub := strings.ToUpper(cmd.Args[1])
	switch sub {
	case "GET":
		if len(cmd.Args) < 3 {
			return WriteError(w, "wrong number of arguments for 'config|get' command")
		}
		// Return empty array for any config key request.
		return WriteArray(w, []string{})
	case "SET":
		if len(cmd.Args) < 4 {
			return WriteError(w, "wrong number of arguments for 'config|set' command")
		}
		return WriteSimple(w, "OK")
	case "RESETSTAT":
		return WriteSimple(w, "OK")
	case "REWRITE":
		return WriteError(w, "The server is running without a config file")
	default:
		return WriteError(w, "unknown subcommand '"+strings.ToLower(sub)+"'")
	}
}

func buildInfo(fp *fingerprint.FP, version, section string, totalCmds, totalConns int64) string {
	uptime := fp.UptimeSeconds()
	uptimeDays := uptime / 86400

	server := fmt.Sprintf(`# Server
redis_version:%s
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:%s
redis_mode:standalone
os:Linux 5.15.0-1057-aws x86_64
arch_bits:64
monotonic_clock:POSIX clock_gettime
multiplexing_api:epoll
atomicvar_api:c11-builtin
gcc_version:11.4.0
process_id:%d
run_id:%s
tcp_port:6379
server_time_usec:%d
uptime_in_seconds:%d
uptime_in_days:%d
hz:10
configured_hz:10
aof_rewrites:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:%d
rdb_last_bgsave_status:ok
aof_enabled:0
`, version, fp.RedisRunID[:16], fp.RedisProcessID, fp.RedisRunID,
		time.Now().UnixMicro(), uptime, uptimeDays, fp.RedisSaveEpoch)

	clients := `# Clients
connected_clients:1
cluster_connections:0
maxclients:10000
client_recent_max_input_buffer:20480
client_recent_max_output_buffer:0
`

	stats := fmt.Sprintf(`# Stats
total_connections_received:%d
total_commands_processed:%d
instantaneous_ops_per_sec:0
total_net_input_bytes:0
total_net_output_bytes:0
rejected_connections:0
`, totalConns, totalCmds)

	replication := fmt.Sprintf(`# Replication
role:master
connected_slaves:0
master_failover_state:no-failover
master_replid:%s
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
`, fp.RedisMasterReplID)

	cpu := `# CPU
used_cpu_sys:0.000000
used_cpu_user:0.000000
`

	keyspace := `# Keyspace
`

	sections := map[string]string{
		"server":      server,
		"clients":     clients,
		"stats":       stats,
		"replication": replication,
		"cpu":         cpu,
		"keyspace":    keyspace,
	}

	if section == "" || section == "all" || section == "default" || section == "everything" {
		var b strings.Builder
		for _, k := range []string{"server", "clients", "stats", "replication", "cpu", "keyspace"} {
			b.WriteString(sections[k])
		}
		return b.String()
	}

	if v, ok := sections[section]; ok {
		return v
	}
	return ""
}
