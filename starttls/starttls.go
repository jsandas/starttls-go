package starttls

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
)

// Protocol specific errors.
var (
	ErrStartTLSNotSupported = errors.New("STARTTLS not supported by server")
	ErrInvalidResponse      = errors.New("invalid server response")
	ErrUnsupportedProtocol  = errors.New("unsupported protocol")
)

// StartTLSProtocol defines the interface for protocol-specific STARTTLS implementations.
type StartTLSProtocol interface {
	// Handshake performs the protocol-specific STARTTLS negotiation
	Handshake(ctx context.Context, rw *bufio.ReadWriter) error
	// Name returns the protocol name
	Name() string
}

// baseProtocol implements common functionality for all STARTTLS protocols.
type baseProtocol struct {
	name     string
	greetMsg *regexp.Regexp
	authMsg  string
	respMsg  *regexp.Regexp
}

func newBaseProtocol(name, greetPattern, auth, respPattern string) baseProtocol {
	return baseProtocol{
		name:     name,
		greetMsg: regexp.MustCompile(greetPattern),
		authMsg:  auth,
		respMsg:  regexp.MustCompile(respPattern),
	}
}

// SMTP protocol implementation.
type smtpProtocol struct {
	baseProtocol
}

func newSMTPProtocol() *smtpProtocol {
	return &smtpProtocol{
		baseProtocol: newBaseProtocol("smtp", "^220 ", "STARTTLS\r\n", "^220 "),
	}
}

func (p *smtpProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("smtp: greeting failed: %w", err)
	}

	if err := p.sendEHLO(ctx, rw); err != nil {
		return fmt.Errorf("smtp: EHLO failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("smtp: STARTTLS failed: %w", err)
	}

	return nil
}

func (p *smtpProtocol) Name() string {
	return p.name
}

func (p *smtpProtocol) sendEHLO(ctx context.Context, rw *bufio.ReadWriter) error {
	if _, err := rw.WriteString("EHLO tlstools.com\r\n"); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}

	for {
		line, err := readLine(ctx, rw.Reader)
		if err != nil {
			return err
		}

		if !strings.HasPrefix(line, "250") {
			return fmt.Errorf("%w: unexpected EHLO response: %s", ErrInvalidResponse, line)
		}

		if rw.Reader.Buffered() == 0 {
			break
		}
	}

	return nil
}

// IMAP protocol implementation.
type imapProtocol struct {
	baseProtocol
}

func newIMAPProtocol() *imapProtocol {
	return &imapProtocol{
		baseProtocol: newBaseProtocol("imap", "^\\* ", "a001 STARTTLS\r\n", "^a001 OK "),
	}
}

func (p *imapProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("imap: greeting failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("imap: STARTTLS failed: %w", err)
	}

	return nil
}

func (p *imapProtocol) Name() string {
	return p.name
}

// POP3 protocol implementation.
type pop3Protocol struct {
	baseProtocol
}

func newPOP3Protocol() *pop3Protocol {
	return &pop3Protocol{
		baseProtocol: newBaseProtocol("pop3", "^\\+OK ", "STLS\r\n", "^\\+OK "),
	}
}

func (p *pop3Protocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("pop3: greeting failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("pop3: STARTTLS failed: %w", err)
	}

	return nil
}

func (p *pop3Protocol) Name() string {
	return p.name
}

// FTP protocol implementation.
type ftpProtocol struct {
	baseProtocol
}

func newFTPProtocol() *ftpProtocol {
	return &ftpProtocol{
		baseProtocol: newBaseProtocol("ftp", "^220 ", "AUTH TLS\r\n", "^234 "),
	}
}

func (p *ftpProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := expectGreeting(ctx, rw, p.greetMsg); err != nil {
		return fmt.Errorf("ftp: greeting failed: %w", err)
	}

	if err := sendStartTLS(ctx, rw, p.authMsg, p.respMsg); err != nil {
		return fmt.Errorf("ftp: AUTH TLS failed: %w", err)
	}

	return nil
}

func (p *ftpProtocol) Name() string {
	return p.name
}

// MySQL protocol implementation.
type mysqlProtocol struct {
	name string
}

func newMySQLProtocol() *mysqlProtocol {
	return &mysqlProtocol{
		name: "mysql",
	}
}

func (p *mysqlProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	// Read initial handshake packet header
	header := make([]byte, 4)
	if _, err := io.ReadFull(rw.Reader, header); err != nil {
		return fmt.Errorf("mysql: failed to read packet header: %w", err)
	}

	// Get packet length (3 bytes, little-endian)
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)

	// Read the packet body
	body := make([]byte, length)
	if _, err := io.ReadFull(rw.Reader, body); err != nil {
		return fmt.Errorf("mysql: failed to read packet body: %w", err)
	}

	// Check protocol version (should be 10)
	if body[0] != 10 {
		return fmt.Errorf("mysql: unsupported protocol version: %d", body[0])
	}

	// Skip server version string (null-terminated)
	pos := 1
	for pos < len(body) && body[pos] != 0 {
		pos++
	}

	pos++ // skip null terminator

	// Skip thread ID (4 bytes)
	pos += 4

	// Skip auth plugin data part 1 (8 bytes + null terminator)
	pos += 8
	for pos < len(body) && body[pos] != 0 {
		pos++
	}

	pos++

	// Skip filler (1 byte)
	pos++

	// Read capability flags (lower 2 bytes)
	if pos+2 > len(body) {
		return fmt.Errorf("mysql: packet too short for capability flags")
	}

	capabilities := uint32(body[pos]) | uint32(body[pos+1])<<8

	// Check if server supports SSL
	const CLIENT_SSL = 0x800
	if capabilities&CLIENT_SSL == 0 {
		return fmt.Errorf("%w: MySQL server does not support SSL", ErrStartTLSNotSupported)
	}

	// Send SSL request packet with minimum required capabilities
	const (
		CLIENT_PROTOCOL_41       = 0x00000200
		CLIENT_SECURE_CONNECTION = 0x00008000
	)

	clientFlags := uint32(CLIENT_SSL | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION)

	sslRequest := make([]byte, 4+32) // Header + SSL request packet
	// Packet header (4 bytes)
	sslRequest[0] = 32 // payload length
	sslRequest[1] = 0
	sslRequest[2] = 0
	sslRequest[3] = 1 // sequence number

	// Client flags (4 bytes)
	sslRequest[4] = byte(clientFlags)
	sslRequest[5] = byte(clientFlags >> 8)
	sslRequest[6] = byte(clientFlags >> 16)
	sslRequest[7] = byte(clientFlags >> 24)

	// Max packet size (4 bytes)
	maxPacketSize := uint32(16777215)
	sslRequest[8] = byte(maxPacketSize)
	sslRequest[9] = byte(maxPacketSize >> 8)
	sslRequest[10] = byte(maxPacketSize >> 16)
	sslRequest[11] = byte(maxPacketSize >> 24)

	// Character set (1 byte)
	sslRequest[12] = 33 // utf8_general_ci

	// Reserved (23 bytes)
	for i := 13; i < 36; i++ {
		sslRequest[i] = 0
	}

	if _, err := rw.Write(sslRequest); err != nil {
		return fmt.Errorf("mysql: failed to write SSL request: %w", err)
	}
	if err := rw.Flush(); err != nil {
		return fmt.Errorf("mysql: failed to flush SSL request: %w", err)
	}

	return nil
}

func (p *mysqlProtocol) Name() string {
	return p.name
}

// Helper functions.
func expectGreeting(ctx context.Context, rw *bufio.ReadWriter, pattern *regexp.Regexp) error {
	for {
		line, err := readLine(ctx, rw.Reader)
		if err != nil {
			return err
		}

		if pattern.MatchString(line) {
			return nil
		}
	}
}

func sendStartTLS(ctx context.Context, rw *bufio.ReadWriter, authMsg string, respPattern *regexp.Regexp) error {
	if _, err := rw.WriteString(authMsg); err != nil {
		return err
	}
	if err := rw.Flush(); err != nil {
		return err
	}

	line, err := readLine(ctx, rw.Reader)
	if err != nil {
		return err
	}

	if !respPattern.MatchString(line) {
		return fmt.Errorf("%w: %s", ErrStartTLSNotSupported, strings.TrimSpace(line))
	}

	return nil
}

func readLine(ctx context.Context, r *bufio.Reader) (string, error) {
	// Create a channel for the read operation
	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		line, err := r.ReadString('\n')
		if err != nil {
			errCh <- err
			return
		}

		lineCh <- line
	}()

	// Wait for either the context to be done or the read to complete
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case err := <-errCh:
		return "", err
	case line := <-lineCh:
		return line, nil
	}
}

// Protocol registry.
var protocols = map[string]func() StartTLSProtocol{
	"21":   func() StartTLSProtocol { return newFTPProtocol() },
	"25":   func() StartTLSProtocol { return newSMTPProtocol() },
	"587":  func() StartTLSProtocol { return newSMTPProtocol() },
	"110":  func() StartTLSProtocol { return newPOP3Protocol() },
	"143":  func() StartTLSProtocol { return newIMAPProtocol() },
	"3306": func() StartTLSProtocol { return newMySQLProtocol() },
}

// StartTLS initiates a STARTTLS handshake for supported protocols.
func StartTLS(ctx context.Context, conn net.Conn, port string) error {
	// Check if this is a STARTTLS protocol
	protocolFactory, ok := protocols[port]
	if !ok {
		// These ports use direct TLS connections
		switch port {
		case "443", "465", "993", "995", "3389":
			return nil
		default:
			return fmt.Errorf("%w: port %s", ErrUnsupportedProtocol, port)
		}
	}

	protocol := protocolFactory()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	return protocol.Handshake(ctx, rw)
}
