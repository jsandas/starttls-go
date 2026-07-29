package starttls

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	hangMessage = "HANG"
)

type testServer struct {
	listener net.Listener
	port     string
	messages []string
	received []string
	errors   chan error
}

// portMap maps protocol ports to high-numbered ports for testing.
var portMap = map[string]string{
	"21":   "10021", // FTP
	"25":   "10025", // SMTP
	"110":  "10110", // POP3
	"143":  "10143", // IMAP
	"389":  "10389", // LDAP
	"3306": "13306", // MySQL
}

func newTestServer(ctx context.Context, port string, messages []string) (*testServer, error) {
	// Use high-numbered port for testing
	testPort := portMap[port]
	if testPort == "" {
		testPort = port // Use original port if no mapping exists
	}

	lc := net.ListenConfig{}

	listener, err := lc.Listen(ctx, "tcp", ":"+testPort)
	if err != nil {
		return nil, fmt.Errorf("failed to start test server: %w", err)
	}

	return &testServer{
		listener: listener,
		port:     port, // Keep original port for protocol identification
		messages: messages,
		errors:   make(chan error, 1),
	}, nil
}

func (s *testServer) start(ctx context.Context) {
	go func() {
		conn, err := s.listener.Accept()
		if err != nil {
			s.errors <- fmt.Errorf("accept failed: %w", err)
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)

		// Send greeting for text-based protocols
		if len(s.messages) > 0 && s.port != "389" {
			_, err := conn.Write([]byte(s.messages[0]))
			if err != nil {
				s.errors <- fmt.Errorf("failed to write greeting: %w", err)
				return
			}
		}

		// Read client messages and respond
		switch s.port {
		case "3306":
			buf := make([]byte, 36) // Size of MySQL SSL request packet

			_, err := io.ReadFull(reader, buf)
			if err != nil && !errors.Is(err, io.EOF) {
				s.errors <- fmt.Errorf("failed to read MySQL SSL request: %w", err)
				return
			}

			s.received = append(s.received, string(buf))
		case "389":
			_, payload, err := readBERElement(reader)
			if err != nil {
				s.errors <- fmt.Errorf("failed to read LDAP request: %w", err)
				return
			}

			s.received = append(s.received, fmt.Sprintf("ldap:%x", payload))

			messageID, _, _, err := parseLDAPMessageIDAndProtocolOp(payload)
			if err != nil {
				s.errors <- fmt.Errorf("failed to decode LDAP messageID: %w", err)
				return
			}

			ldapResult := append(encodeBERTLV(0x0a, []byte{0x00}), encodeBERTLV(0x04, []byte{})...)
			ldapResult = append(ldapResult, encodeBERTLV(0x04, []byte{})...)
			extendedResponse := encodeBERTLV(0x78, ldapResult)
			response := encodeBERTLV(0x30, append(encodeBERTLV(0x02, encodeBERIntegerValue(messageID)), extendedResponse...))

			_, err = conn.Write(response)
			if err != nil {
				s.errors <- fmt.Errorf("failed to write LDAP response: %w", err)
				return
			}
		default:
			for i := 1; i < len(s.messages); i++ {
				// For text protocols, read until newline
				msg, err := reader.ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					s.errors <- fmt.Errorf("failed to read client message: %w", err)
					return
				}

				s.received = append(s.received, msg)

				// If message is "HANG", simulate a hang by sleeping indefinitely
				if s.messages[i] == hangMessage {
					select {
					case <-ctx.Done():
						s.errors <- ctx.Err()
						return
					case <-time.After(24 * time.Hour): // effectively forever
						// This will never execute due to context cancellation
					}
				}
				// Send response for non-HANG messages
				if s.messages[i] != hangMessage {
					_, err := conn.Write([]byte(s.messages[i]))
					if err != nil {
						s.errors <- fmt.Errorf("failed to write response: %w", err)
						return
					}
				}
			}
		}

		s.errors <- nil
	}()
}

func (s *testServer) stop() error {
	return s.listener.Close()
}

func (s *testServer) addr() string {
	return s.listener.Addr().String()
}

const (
	serverMessagesStart        = "220 test.test.test server\r\n"
	serverMessagesFTP          = "234 ready\r\n"
	serverMessagesSMTP         = "250-test.test.test\r\n250 STARTTLS\r\n"
	serverMessagesSMTPNoTLS    = "250-test.test.test\r\n250 NO-STARTTLS\r\n"
	serverMessagesIMAP         = "* OK IMAP server ready\r\n"
	serverMessagesIMAPSuccess  = "a001 OK Begin TLS negotiation now\r\n"
	serverMessagesPOP3         = "+OK POP3 server ready\r\n"
	serverMessagesPOP3Success  = "+OK Begin TLS negotiation\r\n"
	serverMessagesNotSupported = "500 Not supported\r\n"
)

func TestStartTLS(t *testing.T) {
	tests := []struct {
		name           string
		port           string
		serverMessages []string
		expectError    bool
		expectedError  error
		timeout        time.Duration
	}{
		{
			name: "ftp success",
			port: "21",
			serverMessages: []string{
				serverMessagesStart,
				serverMessagesFTP,
			},
			timeout: 2 * time.Second,
		},
		{
			name: "smtp success",
			port: "25",
			serverMessages: []string{
				serverMessagesStart,
				serverMessagesSMTP,
				"220 ready for TLS\r\n",
			},
			timeout: 2 * time.Second,
		},
		{
			name: "imap success",
			port: "143",
			serverMessages: []string{
				serverMessagesIMAP,
				serverMessagesIMAPSuccess,
			},
			timeout: 2 * time.Second,
		},
		{
			name: "pop3 success",
			port: "110",
			serverMessages: []string{
				serverMessagesPOP3,
				serverMessagesPOP3Success,
			},
			timeout: 2 * time.Second,
		},
		{
			name: "smtp starttls not supported",
			port: "25",
			serverMessages: []string{
				serverMessagesStart,
				serverMessagesSMTPNoTLS,
				serverMessagesNotSupported,
			},
			expectError:   true,
			expectedError: ErrStartTLSNotSupported,
			timeout:       2 * time.Second,
		},
		{
			name:    "ldap success",
			port:    "389",
			timeout: 2 * time.Second,
		},
		{
			name: "mysql success",
			port: "3306",
			serverMessages: []string{
				string([]byte{
					0x31, 0x00, 0x00, 0x00, // Packet length (49 bytes) and sequence number 0
					0x0a,                          // Protocol version (10)
					'5', '.', '7', '.', '0', 0x00, // Server version (null terminated)
					0x01, 0x02, 0x03, 0x04, // Thread ID
					'1', '2', '3', '4', '5', '6', '7', '8', // Salt part 1
					0x00,       // null terminator
					0x00,       // Filler
					0x00, 0x08, // Capability flags lower (includes SERVER_SSL 0x800)
					0x21,       // Character set
					0x02, 0x00, // Status flags
					0x00, 0x00, // Capability flags upper
					0x08,                                                       // Auth plugin data length (just first part)
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
					'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00, // auth plugin name
				}),
			},
			timeout: 2 * time.Second,
		},
		{
			name: "mysql ssl not supported",
			port: "3306",
			serverMessages: []string{
				string([]byte{
					0x31, 0x00, 0x00, 0x00, // Packet length (49 bytes) and sequence number 0
					0x0a,                          // Protocol version (10)
					'5', '.', '7', '.', '0', 0x00, // Server version (null terminated)
					0x01, 0x02, 0x03, 0x04, // Thread ID
					'1', '2', '3', '4', '5', '6', '7', '8', // Salt part 1
					0x00,       // null terminator
					0x00,       // Filler
					0x00, 0x00, // Capability flags lower (no SERVER_SSL flag)
					0x21,       // Character set
					0x02, 0x00, // Status flags
					0x00, 0x00, // Capability flags upper
					0x08,                                                       // Auth plugin data length (just first part)
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
					'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00, // auth plugin name
				}),
			},
			expectError:   true,
			expectedError: ErrStartTLSNotSupported,
			timeout:       2 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			server, err := newTestServer(ctx, tt.port, tt.serverMessages)
			if err != nil {
				t.Fatalf("Failed to create test server: %v", err)
			}

			defer func() {
				err := server.stop()
				if err != nil {
					t.Errorf("Failed to stop test server: %v", err)
				}
			}()

			// Start server
			server.start(ctx)

			// Connect client
			dialer := &net.Dialer{}

			conn, err := dialer.DialContext(ctx, "tcp", server.addr())
			if err != nil {
				t.Fatalf("Failed to connect to test server: %v", err)
			}
			defer conn.Close()

			// Attempt STARTTLS
			err = StartTLS(ctx, conn, tt.port)

			// Check error cases
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}

				if !errors.Is(err, tt.expectedError) {
					t.Errorf("Expected error %v but got %v", tt.expectedError, err)
				}

				return
			}

			// Check success cases
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check for server errors
			select {
			case err := <-server.errors:
				if err != nil {
					t.Errorf("Server error: %v", err)
				}
			case <-time.After(tt.timeout):
				t.Error("Test timed out waiting for server")
			}
		})
	}
}

func TestDirectTLSPorts(t *testing.T) {
	directTLSPorts := []string{"443", "465", "993", "995", "3389", "8443", "9443"}

	for _, port := range directTLSPorts {
		t.Run(fmt.Sprintf("port_%s", port), func(t *testing.T) {
			ctx := context.Background()

			err := StartTLS(ctx, nil, port)
			if err != nil {
				t.Errorf("Expected nil error for direct TLS port %s, got: %v", port, err)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	// Create a server that responds to greeting but hangs on EHLO
	ctx := context.Background()

	server, err := newTestServer(ctx, "25", []string{
		"220 test.test.test server\r\n",
		"HANG", // Special message that causes server to hang
	})
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	defer func() {
		err := server.stop()
		if err != nil {
			t.Errorf("Failed to stop test server: %v", err)
		}
	}()

	server.start(ctx)

	// Create a connection
	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", server.addr())
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer conn.Close()

	// Set a short timeout for the STARTTLS operation
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	// The server will acknowledge the connection but hang on EHLO,
	// which should trigger the context timeout
	err = StartTLS(ctx, conn, "25")
	if err == nil {
		t.Error("Expected timeout error but got none")
		return
	}

	// The error should be a context deadline exceeded error
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context deadline exceeded error, got: %v", err)
	}
}

func TestLDAPHandshakeMessageIDMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	atomic.StoreUint32(&ldapMessageIDCounter, 0)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverErr := make(chan error, 1)

	go func() {
		defer close(serverErr)

		reader := bufio.NewReader(serverConn)
		_, payload, err := readBERElement(reader)
		if err != nil {
			serverErr <- err
			return
		}

		messageID, _, _, err := parseLDAPMessageIDAndProtocolOp(payload)
		if err != nil {
			serverErr <- err
			return
		}

		// Reply with a different message ID to trigger the mismatch branch.
		response := buildLDAPExtendedResponse(messageID+1, 0)
		_, err = serverConn.Write(response)
		serverErr <- err
	}()

	err := StartTLS(ctx, clientConn, "389")
	if err == nil {
		t.Fatal("expected LDAP messageID mismatch error, got nil")
	}

	if !strings.Contains(err.Error(), "messageID mismatch") {
		t.Fatalf("expected messageID mismatch error, got: %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestParseLDAPResponseErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		response    []byte
		errContains string
	}{
		{
			name:        "invalid top-level tag",
			response:    encodeBERTLV(0x31, []byte{}),
			errContains: "expected LDAPMessage SEQUENCE",
		},
		{
			name:        "non-success result code",
			response:    buildLDAPExtendedResponse(1, 2),
			errContains: "ldap resultCode=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := bufio.NewReadWriter(bufio.NewReader(bytes.NewReader(tt.response)), bufio.NewWriter(io.Discard))

			_, err := parseLDAPResponse(rw)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestParseBERLengthErrorCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "missing length", data: []byte{}},
		{name: "indefinite length", data: []byte{0x80}},
		{name: "length too large", data: []byte{0x85, 0x01, 0x02, 0x03, 0x04, 0x05}},
		{name: "incomplete long-form length", data: []byte{0x82, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseBERLength(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("expected ErrInvalidResponse, got: %v", err)
			}
		})
	}
}

func TestReadBERLengthErrorCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "missing first byte", data: []byte{}},
		{name: "indefinite length", data: []byte{0x80}},
		{name: "length too large", data: []byte{0x85, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{name: "incomplete length bytes", data: []byte{0x82, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewReader(tt.data))
			_, err := readBERLength(r)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("expected ErrInvalidResponse, got: %v", err)
			}
		})
	}
}

func TestDecodeBERIntegerErrorCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "too large", data: []byte{0x00, 0x00, 0x00, 0x00, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeBERInteger(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func buildLDAPExtendedResponse(messageID, resultCode int) []byte {
	ldapResult := append(encodeBERTLV(0x0a, encodeBERIntegerValue(resultCode)), encodeBERTLV(0x04, []byte{})...)
	ldapResult = append(ldapResult, encodeBERTLV(0x04, []byte{})...)
	extendedResponse := encodeBERTLV(0x78, ldapResult)

	return encodeBERTLV(0x30, append(encodeBERTLV(0x02, encodeBERIntegerValue(messageID)), extendedResponse...))
}

type failWriter struct {
	err error
}

func (w *failWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func TestLDAPHandshakeWriteAndFlushErrors(t *testing.T) {
	tests := []struct {
		name        string
		writerSize  int
		errContains string
	}{
		{
			name:        "write error",
			writerSize:  1,
			errContains: "failed to write StartTLS request",
		},
		{
			name:        "flush error",
			writerSize:  4096,
			errContains: "failed to flush StartTLS request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newLDAPProtocol()
			rw := bufio.NewReadWriter(
				bufio.NewReader(bytes.NewReader(nil)),
				bufio.NewWriterSize(&failWriter{err: errors.New("boom")}, tt.writerSize),
			)

			err := p.Handshake(context.Background(), rw)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestLDAPHandshakeMalformedResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverErr := make(chan error, 1)

	go func() {
		defer close(serverErr)

		reader := bufio.NewReader(serverConn)
		_, _, err := readBERElement(reader)
		if err != nil {
			serverErr <- err
			return
		}

		// Invalid LDAP message tag to trigger parse failure path in Handshake.
		_, err = serverConn.Write(encodeBERTLV(0x31, []byte{}))
		serverErr <- err
	}()

	err := StartTLS(ctx, clientConn, "389")
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}

	if !strings.Contains(err.Error(), "failed to parse StartTLS response") {
		t.Fatalf("expected parse failure prefix, got: %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestParseLDAPMessageIDAndProtocolOpErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		errContains string
	}{
		{
			name: "invalid message id tag",
			payload: append(
				encodeBERTLV(0x04, []byte{0x01}),
				encodeBERTLV(0x78, encodeBERTLV(0x0a, []byte{0x00}))...,
			),
			errContains: "expected messageID INTEGER",
		},
		{
			name: "invalid message id value",
			payload: append(
				encodeBERTLV(0x02, []byte{}),
				encodeBERTLV(0x78, encodeBERTLV(0x0a, []byte{0x00}))...,
			),
			errContains: "invalid messageID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parseLDAPMessageIDAndProtocolOp(tt.payload)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestValidateLDAPResultCodeErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		tag         byte
		value       []byte
		errContains string
	}{
		{
			name:        "invalid protocol op tag",
			tag:         0x77,
			value:       []byte{},
			errContains: "expected ExtendedResponse tag 0x78",
		},
		{
			name:        "invalid result code tag",
			tag:         0x78,
			value:       encodeBERTLV(0x04, []byte{0x00}),
			errContains: "expected resultCode ENUMERATED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLDAPResultCode(tt.tag, tt.value)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestMySQLParseHandshakePacketErrorCases(t *testing.T) {
	p := newMySQLProtocol()

	tests := []struct {
		name        string
		body        []byte
		errContains string
	}{
		{
			name:        "unsupported protocol version",
			body:        []byte{0x09},
			errContains: "unsupported protocol version",
		},
		{
			name: "packet too short for capability flags",
			// protocol version + empty server version + threadID + auth part + null + filler
			body:        []byte{0x0a, 0x00, 0, 0, 0, 0, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 0x00, 0x00},
			errContains: "packet too short for capability flags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.parseHandshakePacket(tt.body)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestMySQLReadPacketErrorCases(t *testing.T) {
	p := newMySQLProtocol()

	tests := []struct {
		name        string
		packet      []byte
		errContains string
	}{
		{
			name:        "short header",
			packet:      []byte{0x01, 0x02},
			errContains: "failed to read packet header",
		},
		{
			name:        "short body",
			packet:      []byte{0x04, 0x00, 0x00, 0x00, 0x01},
			errContains: "failed to read packet body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := bufio.NewReadWriter(bufio.NewReader(bytes.NewReader(tt.packet)), bufio.NewWriter(io.Discard))
			_, err := p.readMySQLPacket(rw)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestProtocolNames(t *testing.T) {
	tests := []struct {
		name     string
		protocol StartTLSProtocol
		expected string
	}{
		{name: "smtp", protocol: newSMTPProtocol(), expected: "smtp"},
		{name: "imap", protocol: newIMAPProtocol(), expected: "imap"},
		{name: "pop3", protocol: newPOP3Protocol(), expected: "pop3"},
		{name: "ftp", protocol: newFTPProtocol(), expected: "ftp"},
		{name: "ldap", protocol: newLDAPProtocol(), expected: "ldap"},
		{name: "mysql", protocol: newMySQLProtocol(), expected: "mysql"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.protocol.Name(); got != tt.expected {
				t.Fatalf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestEncodeBERLengthLongFormBranches(t *testing.T) {
	tests := []struct {
		name     string
		length   int
		expected []byte
	}{
		{name: "short form", length: 127, expected: []byte{0x7f}},
		{name: "long form 1 byte", length: 128, expected: []byte{0x81, 0x80}},
		{name: "long form 2 bytes", length: 256, expected: []byte{0x82, 0x01, 0x00}},
		{name: "long form 3 bytes", length: 65536, expected: []byte{0x83, 0x01, 0x00, 0x00}},
		{name: "long form 4 bytes", length: 16777216, expected: []byte{0x84, 0x01, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeBERLength(tt.length)
			if !bytes.Equal(got, tt.expected) {
				t.Fatalf("expected %x, got %x", tt.expected, got)
			}
		})
	}
}

func TestSendStartTLSErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		writerSize  int
		errContains string
	}{
		{name: "write error", writerSize: 1, errContains: "boom"},
		{name: "flush error", writerSize: 4096, errContains: "boom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := bufio.NewReadWriter(
				bufio.NewReader(bytes.NewReader(nil)),
				bufio.NewWriterSize(&failWriter{err: errors.New("boom")}, tt.writerSize),
			)

			err := sendStartTLS(context.Background(), rw, "STARTTLS\r\n", regexp.MustCompile("^220 "))
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestExpectGreetingReadError(t *testing.T) {
	rw := bufio.NewReadWriter(bufio.NewReader(bytes.NewReader(nil)), bufio.NewWriter(io.Discard))
	err := expectGreeting(context.Background(), rw, regexp.MustCompile("^220 "))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestReadBERElementErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errContains string
	}{
		{name: "missing tag", data: []byte{}, errContains: "failed to read BER tag"},
		{name: "incomplete value", data: []byte{0x04, 0x03, 0x01}, errContains: "failed to read BER value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(bytes.NewReader(tt.data))
			_, _, err := readBERElement(r)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestParseBERElementErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errContains string
	}{
		{name: "too short", data: []byte{0x04}, errContains: "BER element too short"},
		{name: "missing length", data: []byte{0x04}, errContains: "BER element too short"},
		{name: "length exceeds payload", data: []byte{0x04, 0x02, 0x01}, errContains: "BER element length exceeds payload"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parseBERElement(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}
}
