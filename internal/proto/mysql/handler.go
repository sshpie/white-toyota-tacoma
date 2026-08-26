// Package mysql implements the MySQL wire protocol v10 for Tacoma.
package mysql

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"white-toyota-tacoma/internal/capture"
	"white-toyota-tacoma/internal/fingerprint"
)

const (
	maxPacketSize = 16*1024*1024 - 1 // 16 MB - 1, MySQL wire max
	capLongPwd    = 0x00000001
	capConnWithDB = 0x00000008
	capSecureConn = 0x00008000
	capPluginAuth = 0x00080000

	serverCaps = capLongPwd | capConnWithDB | capSecureConn | capPluginAuth
)

// Handler handles one MySQL client connection.
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

	connID := fingerprint.MySQLConnID()
	scramble := fingerprint.MySQLScramble()

	// Send HandshakeV10.
	if err := sendHandshake(conn, version, connID, scramble); err != nil {
		return
	}

	// Reset deadline for the client response.
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read HandshakeResponse41.
	username, database, authResp, err := readHandshakeResponse(conn)
	if err != nil {
		return
	}

	store.Log(capture.Event{
		Protocol: capture.ProtoMySQL,
		SrcIP:    ip,
		SrcPort:  port,
		Username: username,
		Database: database,
		AuthHash: fmt.Sprintf("%x", authResp),
		Command:  "CONNECT",
	})

	// Send OK packet.
	if err := sendOK(conn, 2); err != nil {
		return
	}

	// Read and log subsequent COM_QUERY packets.
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		seq, payload, err := readPacket(conn)
		if err != nil {
			return
		}
		_ = seq

		if len(payload) == 0 {
			continue
		}

		comType := payload[0]
		switch comType {
		case 0x01: // COM_QUIT
			return
		case 0x03: // COM_QUERY
			query := string(payload[1:])
			store.Log(capture.Event{
				Protocol: capture.ProtoMySQL,
				SrcIP:    ip,
				SrcPort:  port,
				Username: username,
				Database: database,
				Command:  truncate(query, 2048),
			})
			// Return empty result set.
			if err := sendEmptyResultSet(conn, 2); err != nil {
				return
			}
		case 0x02: // COM_INIT_DB
			database = string(payload[1:])
			if err := sendOK(conn, 2); err != nil {
				return
			}
		default:
			// Unknown command — send OK to stay alive.
			if err := sendOK(conn, 2); err != nil {
				return
			}
		}
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
}

// sendHandshake writes a MySQL HandshakeV10 packet.
func sendHandshake(w io.Writer, version string, connID uint32, scramble [20]byte) error {
	// version string + null + connID (4) + scramble part1 (8) + filler (1) +
	// caps low (2) + charset (1) + status (2) + caps high (2) + auth plugin len (1) +
	// reserved (10) + scramble part2 (12+1) + plugin name + null
	plugin := "mysql_native_password"
	verBytes := []byte(version)

	payloadLen := 1 + len(verBytes) + 1 + 4 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10 + 13 + len(plugin) + 1
	pkt := make([]byte, 4+payloadLen)

	// Packet header: 3-byte length LE + 1-byte sequence
	pkt[0] = byte(payloadLen)
	pkt[1] = byte(payloadLen >> 8)
	pkt[2] = byte(payloadLen >> 16)
	pkt[3] = 0 // sequence 0

	p := pkt[4:]
	pos := 0

	p[pos] = 10 // protocol version
	pos++

	copy(p[pos:], verBytes)
	pos += len(verBytes)
	p[pos] = 0 // null terminator
	pos++

	binary.LittleEndian.PutUint32(p[pos:], connID)
	pos += 4

	copy(p[pos:], scramble[:8])
	pos += 8
	p[pos] = 0 // filler
	pos++

	caps := uint32(serverCaps)
	p[pos] = byte(caps)
	p[pos+1] = byte(caps >> 8)
	pos += 2

	p[pos] = 0x21 // utf8_general_ci
	pos++

	p[pos] = 0x02 // server status: autocommit
	p[pos+1] = 0x00
	pos += 2

	p[pos] = byte(caps >> 16)
	p[pos+1] = byte(caps >> 24)
	pos += 2

	p[pos] = byte(len(scramble) + 1) // auth plugin data length = 21
	pos++

	// Reserved (10 zero bytes)
	pos += 10

	// Auth plugin data part 2: remaining 12 bytes + null
	copy(p[pos:], scramble[8:])
	pos += 12
	p[pos] = 0
	pos++

	// Auth plugin name
	copy(p[pos:], []byte(plugin))
	pos += len(plugin)
	p[pos] = 0

	_, err := w.Write(pkt)
	return err
}

// readHandshakeResponse parses a HandshakeResponse41 packet.
func readHandshakeResponse(r io.Reader) (username, database string, authResp []byte, err error) {
	_, payload, err := readPacket(r)
	if err != nil {
		return "", "", nil, err
	}

	if len(payload) < 32 {
		return "", "", nil, fmt.Errorf("handshake response too short")
	}

	pos := 0
	// capabilities (4 bytes)
	caps := binary.LittleEndian.Uint32(payload[pos:])
	pos += 4
	// max packet size (4 bytes)
	pos += 4
	// charset (1 byte)
	pos++
	// reserved (23 bytes)
	pos += 23

	if pos >= len(payload) {
		return "", "", nil, fmt.Errorf("handshake response truncated at reserved")
	}

	// username: null-terminated
	end := indexByte(payload[pos:], 0)
	if end < 0 {
		return "", "", nil, fmt.Errorf("username not null-terminated")
	}
	username = string(payload[pos : pos+end])
	pos += end + 1

	if pos >= len(payload) {
		return "", "", nil, fmt.Errorf("handshake response truncated after username")
	}

	// auth response: length-prefixed (1 byte len if !CLIENT_SECURE_CONNECTION,
	// but with CAP_SECURE_CONN it's a length-encoded integer)
	if caps&capSecureConn != 0 {
		authLen := int(payload[pos])
		pos++
		if pos+authLen > len(payload) {
			return "", "", nil, fmt.Errorf("auth response out of bounds")
		}
		authResp = make([]byte, authLen)
		copy(authResp, payload[pos:pos+authLen])
		pos += authLen
	} else {
		end := indexByte(payload[pos:], 0)
		if end < 0 {
			end = len(payload) - pos
		}
		authResp = []byte(payload[pos : pos+end])
		pos += end + 1
	}

	// optional database
	if caps&capConnWithDB != 0 && pos < len(payload) {
		end := indexByte(payload[pos:], 0)
		if end >= 0 {
			database = string(payload[pos : pos+end])
		}
	}

	return username, database, authResp, nil
}

// readPacket reads one MySQL length-prefixed packet.
func readPacket(r io.Reader) (seq byte, payload []byte, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}

	size := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq = hdr[3]

	if size > maxPacketSize {
		return 0, nil, fmt.Errorf("packet too large: %d", size)
	}
	if size == 0 {
		return seq, nil, nil
	}

	payload = make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return seq, payload, nil
}

// sendOK writes a MySQL OK packet with the given sequence number.
func sendOK(w io.Writer, seq byte) error {
	payload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	return writePacket(w, seq, payload)
}

// sendEmptyResultSet writes a minimal valid empty result set.
func sendEmptyResultSet(w io.Writer, seq byte) error {
	// Field count = 0, followed by EOF
	if err := writePacket(w, seq, []byte{0x00}); err != nil {
		return err
	}
	// EOF packet
	return writePacket(w, seq+1, []byte{0xfe, 0x00, 0x00, 0x02, 0x00})
}

// writePacket writes a length-prefixed MySQL packet.
func writePacket(w io.Writer, seq byte, payload []byte) error {
	n := len(payload)
	hdr := [4]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// indexByte returns the index of b in s, or -1 if not found.
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

// stripControl removes ASCII control characters from attacker strings.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
