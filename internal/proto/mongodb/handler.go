// Package mongodb implements the MongoDB wire protocol for Tacoma.
// Handles both OP_QUERY (2004, legacy) and OP_MSG (2013, current) opcodes.
package mongodb

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/sshpie/white-toyota-tacoma/internal/capture"
	"github.com/sshpie/white-toyota-tacoma/internal/fingerprint"
)

const (
	opReply    = 1
	opQuery    = 2004
	opMsg      = 2013
	opGetMore  = 2005
	opDelete   = 2006
	opInsert   = 2002
	opUpdate   = 2001

	maxMsgSize = 48 * 1024 * 1024 // 48 MB — MongoDB wire limit
	maxBSONDoc = 16 * 1024 * 1024 // 16 MB — BSON document limit
)

// msgHeader is the standard MongoDB wire protocol message header.
type msgHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// Handler handles one MongoDB client connection.
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

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		hdr, payload, err := readMessage(conn)
		if err != nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		switch hdr.OpCode {
		case opQuery:
			if err := handleOpQuery(conn, hdr, payload, store, fp, version, ip, port); err != nil {
				return
			}
		case opMsg:
			if err := handleOpMsg(conn, hdr, payload, store, fp, version, ip, port); err != nil {
				return
			}
		case opGetMore, opInsert, opDelete, opUpdate:
			// Log and ignore legacy mutating operations.
			store.Log(capture.Event{
				Protocol: capture.ProtoMongoDB,
				SrcIP:    ip,
				SrcPort:  port,
				Command:  fmt.Sprintf("opcode:%d", hdr.OpCode),
			})
		default:
			// Unknown opcode — close.
			return
		}
	}
}

// readMessage reads one complete MongoDB wire protocol message.
// It enforces the 48 MB size limit before any allocation.
func readMessage(r io.Reader) (msgHeader, []byte, error) {
	var hdrBuf [16]byte
	if _, err := io.ReadFull(r, hdrBuf[:]); err != nil {
		return msgHeader{}, nil, err
	}

	hdr := msgHeader{
		MessageLength: int32(binary.LittleEndian.Uint32(hdrBuf[0:])),
		RequestID:     int32(binary.LittleEndian.Uint32(hdrBuf[4:])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(hdrBuf[8:])),
		OpCode:        int32(binary.LittleEndian.Uint32(hdrBuf[12:])),
	}

	if hdr.MessageLength < 16 || hdr.MessageLength > maxMsgSize {
		return msgHeader{}, nil, fmt.Errorf("invalid message length: %d", hdr.MessageLength)
	}

	bodyLen := int(hdr.MessageLength) - 16
	if bodyLen == 0 {
		return hdr, nil, nil
	}

	payload := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return msgHeader{}, nil, err
	}
	return hdr, payload, nil
}

// handleOpQuery handles the legacy OP_QUERY opcode (2004).
// Format: flags(4) + fullCollectionName(cstring) + numberToSkip(4) + numberToReturn(4) + query(BSON)
func handleOpQuery(conn net.Conn, hdr msgHeader, payload []byte, store *capture.Store, fp *fingerprint.FP, version, ip string, port int) error {
	if len(payload) < 4 {
		return nil
	}

	pos := 4 // skip flags

	// Read collection name (null-terminated).
	nameEnd := indexByte(payload[pos:], 0)
	if nameEnd < 0 {
		return nil // malformed — no null terminator
	}
	collection := string(payload[pos : pos+nameEnd])
	pos += nameEnd + 1

	// numberToSkip and numberToReturn — validate bounds before reading.
	if pos+8 > len(payload) {
		return nil
	}
	pos += 8 // skip numberToSkip + numberToReturn

	// Parse BSON query document.
	doc, _ := parseBSONDoc(payload[pos:])

	// Log the query.
	store.Log(capture.Event{
		Protocol: capture.ProtoMongoDB,
		SrcIP:    ip,
		SrcPort:  port,
		Command:  fmt.Sprintf("OP_QUERY %s", sanitize(collection)),
		Payload:  truncate(jsonMarshal(doc), 2048),
	})

	// Check for isMaster / hello / $cmd.sys.inprog
	lc := strings.ToLower(collection)
	if strings.HasSuffix(lc, ".$cmd") || strings.HasSuffix(lc, ".system.namespaces") {
		return sendOpReply(conn, hdr.RequestID, buildIsMasterDoc(fp, version))
	}

	// Empty cursor response.
	return sendOpReply(conn, hdr.RequestID, nil)
}

// handleOpMsg handles the current OP_MSG opcode (2013).
// Format: flagBits(4) + sections(variable)
func handleOpMsg(conn net.Conn, hdr msgHeader, payload []byte, store *capture.Store, fp *fingerprint.FP, version, ip string, port int) error {
	if len(payload) < 4 {
		return nil
	}

	pos := 4 // skip flagBits (uint32)

	// Sections: each section starts with a kind byte.
	// Kind 0: single BSON document.
	// Kind 1: sequence of documents with identifier.
	command := ""
	var doc map[string]interface{}

	for pos < len(payload) {
		if pos >= len(payload) {
			break
		}
		kind := payload[pos]
		pos++

		switch kind {
		case 0: // Body section: one BSON document.
			// Extract command name from the wire bytes (deterministic first key),
			// not from the parsed map (Go map iteration order is random).
			command = bsonFirstKey(payload[pos:])
			parsed, n := parseBSONDoc(payload[pos:])
			if n < 0 {
				break
			}
			pos += n
			doc = parsed

		case 1: // Document sequence.
			if pos+4 > len(payload) {
				break
			}
			seqLen := int(binary.LittleEndian.Uint32(payload[pos:]))
			if seqLen < 4 || pos+seqLen > len(payload) {
				break
			}
			pos += seqLen

		default:
			// Unknown section kind — stop parsing.
			pos = len(payload)
		}
	}

	// Log the command.
	store.Log(capture.Event{
		Protocol: capture.ProtoMongoDB,
		SrcIP:    ip,
		SrcPort:  port,
		Command:  fmt.Sprintf("OP_MSG %s", sanitize(command)),
		Payload:  truncate(jsonMarshal(doc), 2048),
	})

	// Capture SASL authentication.
	if command == "saslstart" || command == "saslcontinue" || command == "authenticate" {
		if user, ok := extractString(doc, "user"); ok {
			store.Log(capture.Event{
				Protocol: capture.ProtoMongoDB,
				SrcIP:    ip,
				SrcPort:  port,
				Username: user,
				Command:  "AUTH " + command,
			})
		}
	}

	// Respond to isMaster / hello.
	switch command {
	case "ismaster", "hello", "isMaster":
		return sendOpMsgReply(conn, hdr.RequestID, buildIsMasterDoc(fp, version))
	case "ping":
		return sendOpMsgReply(conn, hdr.RequestID, map[string]interface{}{"ok": 1})
	case "buildinfo", "buildInfo":
		return sendOpMsgReply(conn, hdr.RequestID, buildInfoDoc(fp, version))
	case "listdatabases", "listDatabases":
		return sendOpMsgReply(conn, hdr.RequestID, map[string]interface{}{
			"databases": []interface{}{},
			"totalSize": 0,
			"ok":        1,
		})
	case "authenticate", "saslstart", "saslcontinue":
		return sendOpMsgReply(conn, hdr.RequestID, map[string]interface{}{"ok": 1})
	default:
		return sendOpMsgReply(conn, hdr.RequestID, map[string]interface{}{
			"ok":    0,
			"errmsg": "not authorized on admin to execute command",
			"code":  13,
		})
	}
}

func sendOpReply(w io.Writer, responseTo int32, doc map[string]interface{}) error {
	var docBytes []byte
	if doc != nil {
		var err error
		docBytes, err = encodeBSON(doc)
		if err != nil {
			docBytes = minimalBSON()
		}
	}

	numDocs := int32(0)
	if docBytes != nil {
		numDocs = 1
	}

	// OP_REPLY: header(16) + responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + documents
	bodyLen := 4 + 8 + 4 + 4 + len(docBytes)
	msg := make([]byte, 16+bodyLen)

	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))   // messageLength
	binary.LittleEndian.PutUint32(msg[4:], 0)                  // requestID
	binary.LittleEndian.PutUint32(msg[8:], uint32(responseTo)) // responseTo
	binary.LittleEndian.PutUint32(msg[12:], uint32(opReply))   // opCode

	pos := 16
	binary.LittleEndian.PutUint32(msg[pos:], 8) // responseFlags: CursorNotFound|AwaitCapable
	pos += 4
	binary.LittleEndian.PutUint64(msg[pos:], 0) // cursorID
	pos += 8
	binary.LittleEndian.PutUint32(msg[pos:], 0) // startingFrom
	pos += 4
	binary.LittleEndian.PutUint32(msg[pos:], uint32(numDocs)) // numberReturned
	pos += 4
	copy(msg[pos:], docBytes)

	_, err := w.Write(msg)
	return err
}

func sendOpMsgReply(w io.Writer, responseTo int32, doc map[string]interface{}) error {
	docBytes, err := encodeBSON(doc)
	if err != nil {
		docBytes = minimalBSON()
	}

	// OP_MSG: header(16) + flagBits(4) + kind(1) + body(docBytes)
	bodyLen := 4 + 1 + len(docBytes)
	msg := make([]byte, 16+bodyLen)

	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))   // messageLength
	binary.LittleEndian.PutUint32(msg[4:], 0)                  // requestID
	binary.LittleEndian.PutUint32(msg[8:], uint32(responseTo)) // responseTo
	binary.LittleEndian.PutUint32(msg[12:], uint32(opMsg))     // opCode

	pos := 16
	binary.LittleEndian.PutUint32(msg[pos:], 0) // flagBits
	pos += 4
	msg[pos] = 0 // kind=0 (body)
	pos++
	copy(msg[pos:], docBytes)

	_, err2 := w.Write(msg)
	return err2
}

func buildIsMasterDoc(fp *fingerprint.FP, version string) map[string]interface{} {
	return map[string]interface{}{
		"ismaster":                     true,
		"maxBsonObjectSize":            16777216,
		"maxMessageSizeBytes":          48000000,
		"maxWriteBatchSize":            100000,
		"localTime":                    map[string]interface{}{"$date": time.Now().UnixMilli()},
		"logicalSessionTimeoutMinutes": 30,
		"minWireVersion":               0,
		"maxWireVersion":               17,
		"readOnly":                     false,
		"ok":                           1,
		"hosts":                        []string{},
	}
}

func buildInfoDoc(fp *fingerprint.FP, version string) map[string]interface{} {
	return map[string]interface{}{
		"version":           version,
		"gitVersion":        fp.ESBuildHash,
		"sysInfo":           "Linux",
		"versionArray":      []int{7, 0, 8, 0},
		"bits":              64,
		"debug":             false,
		"maxBsonObjectSize": 16777216,
		"ok":                1,
	}
}

// bsonFirstKey returns the first key in a BSON document from the raw wire bytes.
// This is deterministic (first element on the wire) unlike Go map iteration.
func bsonFirstKey(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	docLen := int(binary.LittleEndian.Uint32(data[0:]))
	if docLen < 5 || docLen > len(data) {
		return ""
	}
	pos := 4 // skip docLen
	if pos >= docLen {
		return ""
	}
	pos++ // skip elemType byte
	end := indexByte(data[pos:], 0)
	if end < 0 || pos+end >= docLen {
		return ""
	}
	return strings.ToLower(string(data[pos : pos+end]))
}

// parseBSONDoc parses a BSON document and returns a Go map and the number of bytes consumed.
// Returns nil, -1 on error. Enforces the maxBSONDoc size limit.
func parseBSONDoc(data []byte) (map[string]interface{}, int) {
	if len(data) < 5 {
		return nil, -1
	}
	docLen := int(binary.LittleEndian.Uint32(data[0:]))
	if docLen < 5 || docLen > maxBSONDoc || docLen > len(data) {
		return nil, -1
	}

	doc := make(map[string]interface{})
	pos := 4 // skip docLen

parseLoop:
	for pos < docLen-1 {
		if pos >= len(data) {
			break
		}
		elemType := data[pos]
		pos++

		// Read null-terminated key.
		keyEnd := indexByte(data[pos:], 0)
		if keyEnd < 0 || pos+keyEnd >= docLen {
			break
		}
		key := string(data[pos : pos+keyEnd])
		pos += keyEnd + 1

		// Parse value based on type.
		switch elemType {
		case 0x02: // UTF-8 string
			if pos+4 > docLen || pos+4 > len(data) {
				break parseLoop
			}
			strLen := int(binary.LittleEndian.Uint32(data[pos:]))
			pos += 4
			if strLen < 1 || pos+strLen > docLen || pos+strLen > len(data) {
				break parseLoop
			}
			doc[key] = string(data[pos : pos+strLen-1]) // strip null
			pos += strLen

		case 0x10: // int32
			if pos+4 > docLen || pos+4 > len(data) {
				break parseLoop
			}
			doc[key] = int32(binary.LittleEndian.Uint32(data[pos:]))
			pos += 4

		case 0x12: // int64
			if pos+8 > docLen || pos+8 > len(data) {
				break parseLoop
			}
			doc[key] = int64(binary.LittleEndian.Uint64(data[pos:]))
			pos += 8

		case 0x08: // boolean
			if pos >= docLen || pos >= len(data) {
				break parseLoop
			}
			doc[key] = data[pos] != 0
			pos++

		case 0x01: // double
			if pos+8 > len(data) {
				break parseLoop
			}
			pos += 8

		case 0x03, 0x04: // embedded document or array — skip
			if pos+4 > len(data) {
				break parseLoop
			}
			subLen := int(binary.LittleEndian.Uint32(data[pos:]))
			if subLen < 5 || pos+subLen > len(data) {
				break parseLoop
			}
			pos += subLen

		case 0x05: // binary
			if pos+4 > len(data) {
				break parseLoop
			}
			binLen := int(binary.LittleEndian.Uint32(data[pos:]))
			if pos+5+binLen > len(data) {
				break parseLoop
			}
			pos += 5 + binLen // 4 (len) + 1 (subtype) + data

		case 0x07: // ObjectId
			if pos+12 > len(data) {
				break parseLoop
			}
			pos += 12

		case 0x09: // UTC datetime
			if pos+8 > len(data) {
				break parseLoop
			}
			pos += 8

		case 0x0A: // null — no value bytes

		default:
			// Unknown type — stop parsing to avoid misalignment.
			break parseLoop
		}
	}

	return doc, docLen
}

// encodeBSON encodes a Go map as a minimal BSON document.
// Only supports string and numeric values; unsupported values use JSON string fallback.
func encodeBSON(doc map[string]interface{}) ([]byte, error) {
	var elems []byte

	for k, v := range doc {
		key := []byte(k)
		key = append(key, 0) // null terminator

		switch val := v.(type) {
		case string:
			s := []byte(val)
			lenBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBuf, uint32(len(s)+1))
			elems = append(elems, 0x02)
			elems = append(elems, key...)
			elems = append(elems, lenBuf...)
			elems = append(elems, s...)
			elems = append(elems, 0)

		case int:
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(int32(val)))
			elems = append(elems, 0x10)
			elems = append(elems, key...)
			elems = append(elems, buf...)

		case int32:
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(val))
			elems = append(elems, 0x10)
			elems = append(elems, key...)
			elems = append(elems, buf...)

		case int64:
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, uint64(val))
			elems = append(elems, 0x12)
			elems = append(elems, key...)
			elems = append(elems, buf...)

		case bool:
			elems = append(elems, 0x08)
			elems = append(elems, key...)
			if val {
				elems = append(elems, 1)
			} else {
				elems = append(elems, 0)
			}

		case float64:
			// Store as int32 for integer-valued floats (covers all values in our responses).
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(int32(val)))
			elems = append(elems, 0x10)
			elems = append(elems, key...)
			elems = append(elems, buf...)

		case map[string]interface{}:
			subDoc, err := encodeBSON(val)
			if err != nil {
				subDoc = minimalBSON()
			}
			elems = append(elems, 0x03) // embedded document
			elems = append(elems, key...)
			elems = append(elems, subDoc...)

		case []interface{}:
			arrMap := make(map[string]interface{}, len(val))
			for i, v := range val {
				arrMap[fmt.Sprintf("%d", i)] = v
			}
			subDoc, _ := encodeBSON(arrMap)
			elems = append(elems, 0x04) // array
			elems = append(elems, key...)
			elems = append(elems, subDoc...)

		case []string:
			arrMap := make(map[string]interface{}, len(val))
			for i, s := range val {
				arrMap[fmt.Sprintf("%d", i)] = s
			}
			subDoc, _ := encodeBSON(arrMap)
			elems = append(elems, 0x04) // array
			elems = append(elems, key...)
			elems = append(elems, subDoc...)

		case []int:
			arrMap := make(map[string]interface{}, len(val))
			for i, v := range val {
				arrMap[fmt.Sprintf("%d", i)] = int32(v)
			}
			subDoc, _ := encodeBSON(arrMap)
			elems = append(elems, 0x04) // array
			elems = append(elems, key...)
			elems = append(elems, subDoc...)

		default:
			// Fallback: encode as JSON string.
			jb, _ := json.Marshal(val)
			lenBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBuf, uint32(len(jb)+1))
			elems = append(elems, 0x02)
			elems = append(elems, key...)
			elems = append(elems, lenBuf...)
			elems = append(elems, jb...)
			elems = append(elems, 0)
		}
	}

	elems = append(elems, 0) // document terminator

	docLen := 4 + len(elems)
	buf := make([]byte, docLen)
	binary.LittleEndian.PutUint32(buf[0:], uint32(docLen))
	copy(buf[4:], elems)
	return buf, nil
}

func minimalBSON() []byte {
	// Empty BSON document: length(4) + terminator(1) = 5 bytes.
	return []byte{5, 0, 0, 0, 0}
}

func indexByte(s []byte, b byte) int {
	for i, v := range s {
		if v == b {
			return i
		}
	}
	return -1
}

func jsonMarshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func extractString(doc map[string]interface{}, key string) (string, bool) {
	if doc == nil {
		return "", false
	}
	v, ok := doc[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
