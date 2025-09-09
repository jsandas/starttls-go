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
	err := expectGreeting(ctx, rw, p.greetMsg)
	if err != nil {
		return fmt.Errorf("smtp: greeting failed: %w", err)
	}

	err = p.sendEHLO(ctx, rw)
	if err != nil {
		return fmt.Errorf("smtp: EHLO failed: %w", err)
	}

	err = sendStartTLS(ctx, rw, p.authMsg, p.respMsg)
	if err != nil {
		return fmt.Errorf("smtp: STARTTLS failed: %w", err)
	}

	return nil
}

func (p *smtpProtocol) Name() string {
	return p.name
}

func (p *smtpProtocol) sendEHLO(ctx context.Context, rw *bufio.ReadWriter) error {
	_, err := rw.WriteString("EHLO tlstools.com\r\n")
	if err != nil {
		return err
	}

	err = rw.Flush()
	if err != nil {
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
	err := expectGreeting(ctx, rw, p.greetMsg)
	if err != nil {
		return fmt.Errorf("imap: greeting failed: %w", err)
	}

	err = sendStartTLS(ctx, rw, p.authMsg, p.respMsg)
	if err != nil {
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
	err := expectGreeting(ctx, rw, p.greetMsg)
	if err != nil {
		return fmt.Errorf("pop3: greeting failed: %w", err)
	}

	err = sendStartTLS(ctx, rw, p.authMsg, p.respMsg)
	if err != nil {
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
	err := expectGreeting(ctx, rw, p.greetMsg)
	if err != nil {
		return fmt.Errorf("ftp: greeting failed: %w", err)
	}

	err = sendStartTLS(ctx, rw, p.authMsg, p.respMsg)
	if err != nil {
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

// MySQL protocol constants.
const (
	clientSSL            = 0x800
	clientProtocol41     = 0x00000200
	clientSecureConn     = 0x00008000
	mysqlProtocolVersion = 10
	maxMySQLPacketSize   = 16777215
	utf8GeneralCI        = 33
)

func (p *mysqlProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	// Read and parse handshake packet
	body, err := p.readMySQLPacket(rw)
	if err != nil {
		return err
	}

	capabilities, err := p.parseHandshakePacket(body)
	if err != nil {
		return err
	}

	// Check if server supports SSL
	if capabilities&clientSSL == 0 {
		return fmt.Errorf("%w: MySQL server does not support SSL", ErrStartTLSNotSupported)
	}

	// Send SSL request
	sslRequest := p.createSSLRequestPacket()

	_, err = rw.Write(sslRequest)
	if err != nil {
		return fmt.Errorf("mysql: failed to write SSL request: %w", err)
	}

	err = rw.Flush()
	if err != nil {
		return fmt.Errorf("mysql: failed to flush SSL request: %w", err)
	}

	return nil
}

func (p *mysqlProtocol) Name() string {
	return p.name
}

// readMySQLPacket reads a MySQL packet and returns its body.
func (p *mysqlProtocol) readMySQLPacket(rw *bufio.ReadWriter) ([]byte, error) {
	header := make([]byte, 4)

	_, err := io.ReadFull(rw.Reader, header)
	if err != nil {
		return nil, fmt.Errorf("mysql: failed to read packet header: %w", err)
	}

	// Get packet length (3 bytes, little-endian)
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)

	body := make([]byte, length)

	_, err = io.ReadFull(rw.Reader, body)
	if err != nil {
		return nil, fmt.Errorf("mysql: failed to read packet body: %w", err)
	}

	return body, nil
}

// parseHandshakePacket parses the initial handshake packet and returns server capabilities.
func (p *mysqlProtocol) parseHandshakePacket(body []byte) (uint32, error) {
	if len(body) == 0 || body[0] != mysqlProtocolVersion {
		return 0, fmt.Errorf("mysql: unsupported protocol version: %d", body[0])
	}

	// Skip server version string and other fields
	pos := 1
	// Skip to end of server version (null-terminated)
	for pos < len(body) && body[pos] != 0 {
		pos++
	}

	pos++ // skip null terminator

	// Skip thread ID and auth data
	pos += 4 // thread ID
	pos += 8 // auth plugin data part 1

	for pos < len(body) && body[pos] != 0 {
		pos++
	}

	pos++ // null terminator
	pos++ // filler

	// Read capability flags
	if pos+2 > len(body) {
		return 0, fmt.Errorf("mysql: packet too short for capability flags")
	}

	return uint32(body[pos]) | uint32(body[pos+1])<<8, nil
}

// createSSLRequestPacket creates the SSL request packet.
func (p *mysqlProtocol) createSSLRequestPacket() []byte {
	clientFlags := uint32(clientSSL | clientProtocol41 | clientSecureConn)
	packet := make([]byte, 4+32) // Header + SSL request packet

	// Packet header
	packet[0] = 32 // payload length
	packet[3] = 1  // sequence number

	// Client flags (4 bytes)
	packet[4] = byte(clientFlags)
	packet[5] = byte(clientFlags >> 8)
	packet[6] = byte(clientFlags >> 16)
	packet[7] = byte(clientFlags >> 24)

	// Max packet size (4 bytes)
	maxSize := uint32(maxMySQLPacketSize)
	packet[8] = byte(maxSize)
	packet[9] = byte(maxSize >> 8)
	packet[10] = byte(maxSize >> 16)
	packet[11] = byte(maxSize >> 24)

	// Character set
	packet[12] = utf8GeneralCI

	return packet
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
	_, err := rw.WriteString(authMsg)
	if err != nil {
		return err
	}

	err = rw.Flush()
	if err != nil {
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
