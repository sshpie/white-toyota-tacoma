// Package postgres implements the PostgreSQL wire protocol v3 for Tacoma.
package postgres

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/sshpie/white-toyota-tacoma/internal/capture"
	"github.com/sshpie/white-toyota-tacoma/internal/fingerprint"
)

const (
	maxStartupLen = 10000 // PostgreSQL spec allows up to 10 kB startup message
	maxMsgLen     = 1024 * 1024

	sslRequest      = 80877103
	cancelRequest   = 80877102
	protoVersion    = 196608 // 3.0
)

// Handler handles one PostgreSQL client connection.
func Handler(
	ctx context.Context,
	conn net.Conn,
	store *capture.Store,
	fp *fingerprint.FP,
	version string,
) {
	ip, portStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// Phase 1: startup / SSL negotiation.
	username, database, err := doStartup(conn)
	if err != nil {
		return
	}

	// Phase 2: authentication — MD5 with random salt.
	salt := fingerprint.PGSalt()
	if err := sendAuthMD5(conn, salt); err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	hash, err := readPasswordMessage(conn)
	if err != nil {
		return
	}

	store.Log(capture.Event{
		Protocol: capture.ProtoPostgres,
		SrcIP:    ip,
		SrcPort:  port,
		Username: username,
		Database: database,
		AuthHash: hash,
		Command:  "CONNECT",
	})

	// Phase 3: send startup responses.
	backendPID := fingerprint.PGPID()
	cancelKey := fingerprint.RandUint32()

	if err := sendAuthOK(conn); err != nil {
		return
	}
	params := map[string]string{
		"server_version":   version,
		"server_encoding":  "UTF8",
		"client_encoding":  "UTF8",
		"DateStyle":        "ISO, MDY",
		"TimeZone":         "UTC",
		"integer_datetimes": "on",
	}
	for k, v := range params {
		if err := sendParamStatus(conn, k, v); err != nil {
			return
		}
	}
	if err := sendBackendKeyData(conn, backendPID, int32(cancelKey)); err != nil {
		return
	}
	if err := sendReadyForQuery(conn, 'I'); err != nil {
		return
	}

	// Phase 4: accept queries.
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgType, payload, err := readMessage(conn)
		if err != nil {
			return
		}

		switch msgType {
		case 'Q': // SimpleQuery
			query := nullTermString(payload)
			store.Log(capture.Event{
				Protocol: capture.ProtoPostgres,
				SrcIP:    ip,
				SrcPort:  port,
				Username: username,
				Database: database,
				Command:  truncate(query, 2048),
			})
			// Return empty result.
			if err := sendEmptyQueryResponse(conn); err != nil {
				return
			}
			if err := sendReadyForQuery(conn, 'I'); err != nil {
				return
			}

		case 'X': // Terminate
			return

		case 'P', 'B', 'D', 'E', 'S': // Extended query protocol messages
			// Consume silently, return ErrorResponse for simplicity.
			if err := sendErrorResponse(conn, "XX000", "extended query protocol not supported"); err != nil {
				return
			}
			if err := sendReadyForQuery(conn, 'I'); err != nil {
				return
			}

		default:
			// Unknown message type — ignore.
		}
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
}

// doStartup handles the initial startup message, including SSL negotiation.
func doStartup(conn net.Conn) (username, database string, err error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	for {
		// Read the 4-byte message length.
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", "", err
		}
		msgLen := int(binary.BigEndian.Uint32(lenBuf[:]))

		// Validate before any allocation.
		if msgLen < 8 || msgLen > maxStartupLen {
			return "", "", fmt.Errorf("invalid startup message length: %d", msgLen)
		}

		// Read the remaining message body.
		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return "", "", err
		}

		if len(body) < 4 {
			return "", "", fmt.Errorf("startup message body too short")
		}

		protocolOrRequest := int(binary.BigEndian.Uint32(body[:4]))

		switch protocolOrRequest {
		case sslRequest:
			// Decline SSL: client should reconnect without SSL.
			if _, err := conn.Write([]byte("N")); err != nil {
				return "", "", err
			}
			// Loop to read the next startup message.
			continue

		case cancelRequest:
			// Silently discard cancel requests.
			return "", "", fmt.Errorf("cancel request")

		case protoVersion:
			// Parse key=value parameters (null-terminated pairs).
			params := parseStartupParams(body[4:])
			username = params["user"]
			database = params["database"]
			if database == "" {
				database = username
			}
			return username, database, nil

		default:
			return "", "", fmt.Errorf("unknown startup request: %d", protocolOrRequest)
		}
	}
}

// parseStartupParams parses the null-terminated key=value sequence in
// a PostgreSQL startup message. It checks all bounds before accessing
// any index.
func parseStartupParams(data []byte) map[string]string {
	params := make(map[string]string)
	for len(data) > 1 {
		// Read key.
		ki := indexByte(data, 0)
		if ki < 0 {
			break
		}
		key := string(data[:ki])
		data = data[ki+1:]
		if len(data) == 0 {
			break
		}

		// Read value.
		vi := indexByte(data, 0)
		if vi < 0 {
			break
		}
		val := string(data[:vi])
		data = data[vi+1:]

		if key != "" {
			params[key] = val
		}
	}
	return params
}

// readMessage reads one frontend message: type byte + 4-byte length + payload.
func readMessage(r io.Reader) (msgType byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	msgType = hdr[0]
	msgLen := int(binary.BigEndian.Uint32(hdr[1:])) - 4 // length includes itself

	if msgLen < 0 || msgLen > maxMsgLen {
		return 0, nil, fmt.Errorf("invalid message length: %d", msgLen+4)
	}
	if msgLen == 0 {
		return msgType, nil, nil
	}

	payload = make([]byte, msgLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

// readPasswordMessage reads a PasswordMessage ('p' + length + hash string).
func readPasswordMessage(r io.Reader) (string, error) {
	msgType, payload, err := readMessage(r)
	if err != nil {
		return "", err
	}
	if msgType != 'p' {
		return "", fmt.Errorf("expected PasswordMessage, got %q", msgType)
	}
	return nullTermString(payload), nil
}

func sendAuthMD5(w io.Writer, salt [4]byte) error {
	// AuthenticationMD5Password: type=R, length=12, authType=5, salt(4)
	msg := make([]byte, 9+4)
	msg[0] = 'R'
	binary.BigEndian.PutUint32(msg[1:], 12) // length
	binary.BigEndian.PutUint32(msg[5:], 5)  // MD5
	copy(msg[9:], salt[:])
	_, err := w.Write(msg)
	return err
}

func sendAuthOK(w io.Writer) error {
	msg := []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}
	_, err := w.Write(msg)
	return err
}

func sendParamStatus(w io.Writer, key, val string) error {
	body := []byte(key + "\x00" + val + "\x00")
	return sendMsg(w, 'S', body)
}

func sendBackendKeyData(w io.Writer, pid, key int32) error {
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:], uint32(pid))
	binary.BigEndian.PutUint32(body[4:], uint32(key))
	return sendMsg(w, 'K', body)
}

func sendReadyForQuery(w io.Writer, status byte) error {
	return sendMsg(w, 'Z', []byte{status})
}

func sendEmptyQueryResponse(w io.Writer) error {
	return sendMsg(w, 'I', nil)
}

func sendErrorResponse(w io.Writer, code, msg string) error {
	body := []byte{'S', 'E', 'R', 'R', 'O', 'R', 0,
		'C'}
	body = append(body, []byte(code)...)
	body = append(body, 0, 'M')
	body = append(body, []byte(msg)...)
	body = append(body, 0, 0)
	return sendMsg(w, 'E', body)
}

func sendMsg(w io.Writer, msgType byte, body []byte) error {
	length := 4 + len(body)
	buf := make([]byte, 1+length)
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:], uint32(length))
	copy(buf[5:], body)
	_, err := w.Write(buf)
	return err
}

// nullTermString returns the null-terminated string at the start of b,
// or all of b if no null byte is found.
func nullTermString(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// indexByte returns the index of b in s, or -1.
func indexByte(s []byte, b byte) int {
	for i, v := range s {
		if v == b {
			return i
		}
	}
	return -1
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

