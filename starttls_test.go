package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type testServer struct {
	listener net.Listener
	port     string
	messages []string
	received []string
	errors   chan error
}

// portMap maps protocol ports to high-numbered ports for testing
var portMap = map[string]string{
	"21":   "10021", // FTP
	"25":   "10025", // SMTP
	"110":  "10110", // POP3
	"143":  "10143", // IMAP
	"3306": "13306", // MySQL
}

func newTestServer(port string, messages []string) (*testServer, error) {
	// Use high-numbered port for testing
	testPort := portMap[port]
	if testPort == "" {
		testPort = port // Use original port if no mapping exists
	}

	listener, err := net.Listen("tcp", ":"+testPort)
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

		// Send greeting
		if len(s.messages) > 0 {
			if _, err := conn.Write([]byte(s.messages[0])); err != nil {
				s.errors <- fmt.Errorf("failed to write greeting: %w", err)
				return
			}
		}

		// Read client messages and respond
		for i := 1; i < len(s.messages); i++ {
			// For MySQL, just read the SSL request packet and don't respond
			if s.port == "3306" {
				buf := make([]byte, 36) // Size of MySQL SSL request packet
				if _, err := io.ReadFull(reader, buf); err != nil && !errors.Is(err, io.EOF) {
					s.errors <- fmt.Errorf("failed to read MySQL SSL request: %w", err)
					return
				}
				s.received = append(s.received, string(buf))
				break // MySQL doesn't expect a response after SSL request
			} else {
				// For text protocols, read until newline
				msg, err := reader.ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					s.errors <- fmt.Errorf("failed to read client message: %w", err)
					return
				}
				s.received = append(s.received, msg)

				// If message is "HANG", simulate a hang by sleeping indefinitely
				if s.messages[i] == "HANG" {
					select {
					case <-ctx.Done():
						s.errors <- ctx.Err()
						return
					case <-time.After(24 * time.Hour): // effectively forever
						// This will never execute due to context cancellation
					}
				}
				// Send response for non-HANG messages
				if s.messages[i] != "HANG" {
					if _, err := conn.Write([]byte(s.messages[i])); err != nil {
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
				"220 test.test.test server\r\n",
				"234 ready\r\n",
			},
			timeout: 2 * time.Second,
		},
		{
			name: "smtp success",
			port: "25",
			serverMessages: []string{
				"220 test.test.test server\r\n",
				"250-test.test.test\r\n250 STARTTLS\r\n",
				"220 ready for TLS\r\n",
			},
			timeout: 2 * time.Second,
		},
		{
			name: "imap success",
			port: "143",
			serverMessages: []string{
				"* OK IMAP server ready\r\n",
				"a001 OK Begin TLS negotiation now\r\n",
			},
			timeout: 2 * time.Second,
		},
		{
			name: "pop3 success",
			port: "110",
			serverMessages: []string{
				"+OK POP3 server ready\r\n",
				"+OK Begin TLS negotiation\r\n",
			},
			timeout: 2 * time.Second,
		},
		{
			name:           "unsupported protocol",
			port:           "1234",
			serverMessages: []string{},
			expectError:    true,
			expectedError:  ErrUnsupportedProtocol,
			timeout:        1 * time.Second,
		},
		{
			name: "smtp starttls not supported",
			port: "25",
			serverMessages: []string{
				"220 test.test.test server\r\n",
				"250-test.test.test\r\n250 NO-STARTTLS\r\n",
				"500 Not supported\r\n",
			},
			expectError:   true,
			expectedError: ErrStartTLSNotSupported,
			timeout:       2 * time.Second,
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
			server, err := newTestServer(tt.port, tt.serverMessages)
			if err != nil {
				t.Fatalf("Failed to create test server: %v", err)
			}
			defer func() {
				if err := server.stop(); err != nil {
					t.Errorf("Failed to stop test server: %v", err)
				}
			}()

			// Start server
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()
			server.start(ctx)

			// Connect client
			conn, err := net.Dial("tcp", server.addr())
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
	directTLSPorts := []string{"443", "465", "993", "995", "3389"}

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
	server, err := newTestServer("25", []string{
		"220 test.test.test server\r\n",
		"HANG", // Special message that causes server to hang
	})
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer func() {
		if err := server.stop(); err != nil {
			t.Errorf("Failed to stop test server: %v", err)
		}
	}()

	ctx := context.Background()
	server.start(ctx)

	// Create a connection with no timeout
	conn, err := net.Dial("tcp", server.addr())
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
