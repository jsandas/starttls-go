package starttls

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
)

// Protocol specific errors.
var (
	ErrStartTLSNotSupported = errors.New("STARTTLS not supported by server")
	ErrInvalidResponse      = errors.New("invalid server response")
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

// LDAP protocol implementation.
type ldapProtocol struct {
	name string
}

const ldapStartTLS_OID = "1.3.6.1.4.1.1466.20037"

var ldapMessageIDCounter uint32

func newLDAPProtocol() *ldapProtocol {
	return &ldapProtocol{
		name: "ldap",
	}
}

func (p *ldapProtocol) Handshake(ctx context.Context, rw *bufio.ReadWriter) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	messageID := int(atomic.AddUint32(&ldapMessageIDCounter, 1))
	request := encodeStartTLSRequest(messageID)

	_, err := rw.Write(request)
	if err != nil {
		return fmt.Errorf("ldap: failed to write StartTLS request: %w", err)
	}

	err = rw.Flush()
	if err != nil {
		return fmt.Errorf("ldap: failed to flush StartTLS request: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	receivedID, err := parseLDAPResponse(rw)
	if err != nil {
		return fmt.Errorf("ldap: failed to parse StartTLS response: %w", err)
	}

	if receivedID != messageID {
		return fmt.Errorf("ldap: messageID mismatch: sent=%d received=%d", messageID, receivedID)
	}

	return nil
}

func encodeStartTLSRequest(messageID int) []byte {
	messageIDField := encodeBERTLV(0x02, encodeBERIntegerValue(messageID))
	// LDAP StartTLS ExtendedRequest uses [APPLICATION 23] (0x77) and
	// requestName is context-specific [0] (0x80) carrying the OID value bytes.
	requestNameField := encodeBERTLV(0x80, []byte(ldapStartTLS_OID))
	protocolOpField := encodeBERTLV(0x77, requestNameField)

	return encodeBERTLV(0x30, append(messageIDField, protocolOpField...))
}

func parseLDAPResponse(rw *bufio.ReadWriter) (int, error) {
	tag, payload, err := readBERElement(rw.Reader)
	if err != nil {
		return 0, err
	}

	if tag != 0x30 {
		return 0, fmt.Errorf("%w: expected LDAPMessage SEQUENCE, got tag 0x%02x", ErrInvalidResponse, tag)
	}

	messageIDTag, messageIDValue, rest, err := parseBERElement(payload)
	if err != nil {
		return 0, err
	}

	if messageIDTag != 0x02 {
		return 0, fmt.Errorf("%w: expected messageID INTEGER, got tag 0x%02x", ErrInvalidResponse, messageIDTag)
	}

	messageID, err := decodeBERInteger(messageIDValue)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid messageID: %w", ErrInvalidResponse, err)
	}

	_, protocolOpValue, _, err := parseBERElement(rest)
	if err != nil {
		return messageID, err
	}

	resultCodeTag, resultCodeValue, _, err := parseBERElement(protocolOpValue)
	if err != nil {
		return messageID, err
	}

	if resultCodeTag != 0x0a && resultCodeTag != 0x02 {
		return messageID, fmt.Errorf("%w: expected resultCode ENUMERATED, got tag 0x%02x", ErrInvalidResponse, resultCodeTag)
	}

	resultCode, err := decodeBERInteger(resultCodeValue)
	if err != nil {
		return messageID, fmt.Errorf("%w: invalid resultCode: %w", ErrInvalidResponse, err)
	}

	if resultCode != 0 {
		return messageID, fmt.Errorf("ldap resultCode=%d", resultCode)
	}

	return messageID, nil
}

func encodeBERTLV(tag byte, value []byte) []byte {
	length := encodeBERLength(len(value))
	tlv := make([]byte, 1+len(length)+len(value))
	tlv[0] = tag
	copy(tlv[1:], length)
	copy(tlv[1+len(length):], value)

	return tlv
}

func encodeBERLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}

	var tmp [4]byte
	pos := len(tmp)
	for l := length; l > 0; l >>= 8 {
		pos--
		tmp[pos] = byte(l)
	}

	content := tmp[pos:]
	result := make([]byte, 1+len(content))
	result[0] = 0x80 | byte(len(content))
	copy(result[1:], content)

	return result
}

func encodeBERIntegerValue(n int) []byte {
	if n == 0 {
		return []byte{0x00}
	}

	var tmp [8]byte
	i := len(tmp)
	v := n
	for v > 0 {
		i--
		tmp[i] = byte(v)
		v >>= 8
	}

	value := append([]byte(nil), tmp[i:]...)
	if value[0]&0x80 != 0 {
		value = append([]byte{0x00}, value...)
	}

	return value
}

func readBERElement(r *bufio.Reader) (byte, []byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, nil, fmt.Errorf("%w: failed to read BER tag: %v", ErrInvalidResponse, err)
	}

	length, err := readBERLength(r)
	if err != nil {
		return 0, nil, err
	}

	value := make([]byte, length)
	_, err = io.ReadFull(r, value)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: failed to read BER value: %v", ErrInvalidResponse, err)
	}

	return tag, value, nil
}

func readBERLength(r *bufio.Reader) (int, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("%w: failed to read BER length: %v", ErrInvalidResponse, err)
	}

	if first&0x80 == 0 {
		return int(first), nil
	}

	numBytes := int(first & 0x7f)
	if numBytes == 0 {
		return 0, fmt.Errorf("%w: BER indefinite length is not supported", ErrInvalidResponse)
	}

	if numBytes > 4 {
		return 0, fmt.Errorf("%w: BER length too large", ErrInvalidResponse)
	}

	buf := make([]byte, numBytes)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to read BER length bytes: %v", ErrInvalidResponse, err)
	}

	length := 0
	for _, b := range buf {
		length = (length << 8) | int(b)
	}

	return length, nil
}

func parseBERElement(data []byte) (byte, []byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("%w: BER element too short", ErrInvalidResponse)
	}

	tag := data[0]
	length, lengthBytes, err := parseBERLength(data[1:])
	if err != nil {
		return 0, nil, nil, err
	}

	start := 1 + lengthBytes
	end := start + length
	if end > len(data) {
		return 0, nil, nil, fmt.Errorf("%w: BER element length exceeds payload", ErrInvalidResponse)
	}

	return tag, data[start:end], data[end:], nil
}

func parseBERLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("%w: missing BER length", ErrInvalidResponse)
	}

	first := data[0]
	if first&0x80 == 0 {
		return int(first), 1, nil
	}

	numBytes := int(first & 0x7f)
	if numBytes == 0 {
		return 0, 0, fmt.Errorf("%w: BER indefinite length is not supported", ErrInvalidResponse)
	}

	if numBytes > 4 {
		return 0, 0, fmt.Errorf("%w: BER length too large", ErrInvalidResponse)
	}

	if len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("%w: incomplete BER length", ErrInvalidResponse)
	}

	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}

	return length, 1 + numBytes, nil
}

func decodeBERInteger(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty BER integer")
	}

	if len(data) > 4 {
		return 0, fmt.Errorf("BER integer too large")
	}

	value := 0
	for _, b := range data {
		value = (value << 8) | int(b)
	}

	return value, nil
}

func (p *ldapProtocol) Name() string {
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
	binary.LittleEndian.PutUint32(packet[4:8], clientFlags)

	// Max packet size (4 bytes)
	maxSize := uint32(maxMySQLPacketSize)
	binary.LittleEndian.PutUint32(packet[8:12], maxSize)

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
	"389":  func() StartTLSProtocol { return newLDAPProtocol() },
	"3306": func() StartTLSProtocol { return newMySQLProtocol() },
}

// StartTLS initiates a STARTTLS handshake for supported protocols.
func StartTLS(ctx context.Context, conn net.Conn, port string) error {
	// Check if this is a STARTTLS protocol
	protocolFactory, ok := protocols[port]
	if !ok {
		// If the port is not recognized, we assume STARTTLS not required and return nil.
		return nil
	}

	protocol := protocolFactory()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	return protocol.Handshake(ctx, rw)
}
