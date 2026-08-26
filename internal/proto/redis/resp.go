// Package redis implements the Redis RESP protocol for Tacoma.
package redis

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	maxBulkLen   = 16 * 1024 * 1024 // 16 MB — Redis max bulk string
	maxInlineLen = 65536
	maxArgs      = 1024
)

// Command holds a parsed RESP command.
type Command struct {
	Name string
	Args []string // Args[0] is always Name (uppercase); Args[1:] are arguments
}

// ErrProto signals a protocol-level error (not EOF).
var ErrProto = errors.New("redis: protocol error")

// ReadCommand reads one RESP command from r.
// It handles both multi-bulk (*N\r\n) and inline commands.
func ReadCommand(r *bufio.Reader) (*Command, error) {
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, ErrProto
	}

	switch line[0] {
	case '*':
		return readMultiBulk(r, line)
	default:
		return readInline(line)
	}
}

func readMultiBulk(r *bufio.Reader, header string) (*Command, error) {
	count, err := strconv.Atoi(header[1:])
	if err != nil || count < 1 || count > maxArgs {
		return nil, fmt.Errorf("%w: invalid array count %q", ErrProto, header)
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		bulk, err := readBulkString(r)
		if err != nil {
			return nil, err
		}
		args = append(args, bulk)
	}

	if len(args) == 0 {
		return nil, ErrProto
	}
	return &Command{Name: strings.ToUpper(args[0]), Args: args}, nil
}

func readBulkString(r *bufio.Reader) (string, error) {
	line, err := readLine(r)
	if err != nil {
		return "", err
	}
	if len(line) < 1 || line[0] != '$' {
		return "", fmt.Errorf("%w: expected bulk string, got %q", ErrProto, line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < -1 || n > maxBulkLen {
		return "", fmt.Errorf("%w: invalid bulk length %q", ErrProto, line)
	}
	if n == -1 {
		return "", nil // null bulk string
	}

	// Read exactly n bytes + CRLF.
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read bulk data: %w", err)
	}
	if buf[n] != '\r' || buf[n+1] != '\n' {
		return "", fmt.Errorf("%w: missing CRLF after bulk data", ErrProto)
	}
	return string(buf[:n]), nil
}

func readInline(line string) (*Command, error) {
	if len(line) > maxInlineLen {
		return nil, fmt.Errorf("%w: inline command too long", ErrProto)
	}
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil, ErrProto
	}
	return &Command{Name: strings.ToUpper(parts[0]), Args: parts}, nil
}

// readLine reads a \r\n-terminated line and returns it without the terminator.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

// Write helpers — safe RESP response builders.

func WriteSimple(w io.Writer, s string) error {
	_, err := fmt.Fprintf(w, "+%s\r\n", s)
	return err
}

func WriteError(w io.Writer, s string) error {
	_, err := fmt.Fprintf(w, "-ERR %s\r\n", s)
	return err
}

func WriteInt(w io.Writer, n int64) error {
	_, err := fmt.Fprintf(w, ":%d\r\n", n)
	return err
}

func WriteBulk(w io.Writer, s string) error {
	_, err := fmt.Fprintf(w, "$%d\r\n%s\r\n", len(s), s)
	return err
}

func WriteNull(w io.Writer) error {
	_, err := fmt.Fprintf(w, "$-1\r\n")
	return err
}

func WriteArray(w io.Writer, items []string) error {
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(items)); err != nil {
		return err
	}
	for _, item := range items {
		if err := WriteBulk(w, item); err != nil {
			return err
		}
	}
	return nil
}
