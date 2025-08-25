package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
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

func newTestServer(port string, messages []string) (*testServer, error) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return nil, fmt.Errorf("failed to start test server: %w", err)
	}

	return &testServer{
		listener: listener,
		port:     port,
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
			// Read client message
			msg, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				s.errors <- fmt.Errorf("failed to read client message: %w", err)
				return
			}
			s.received = append(s.received, msg)

			// Send response
			if _, err := conn.Write([]byte(s.messages[i])); err != nil {
				s.errors <- fmt.Errorf("failed to write response: %w", err)
				return
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
					0x4a, 0x00, 0x00, 0x00, // Packet length (74 bytes) and sequence
					0x0a,                          // Protocol version (10)
					'5', '.', '7', '.', '0', 0x00, // Server version
					0x01, 0x02, 0x03, 0x04, // Thread ID
					'1', '2', '3', '4', '5', '6', '7', '8', 0x00, // Auth plugin data
					0x00,       // Filler
					0x08, 0x82, // Capability flags lower (includes SERVER_SSL 0x800)
					0x21,       // Character set
					0x02, 0x00, // Status flags
					0x00, 0x00, // Capability flags upper
					0x00,                                                       // Auth plugin data length
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
				}),
			},
			timeout: 2 * time.Second,
		},
		{
			name: "mysql ssl not supported",
			port: "3306",
			serverMessages: []string{
				string([]byte{
					0x4a, 0x00, 0x00, 0x00, // Packet length (74 bytes) and sequence
					0x0a,                          // Protocol version (10)
					'5', '.', '7', '.', '0', 0x00, // Server version
					0x01, 0x02, 0x03, 0x04, // Thread ID
					'1', '2', '3', '4', '5', '6', '7', '8', 0x00, // Auth plugin data
					0x00,       // Filler
					0x00, 0x82, // Capability flags lower (no SERVER_SSL flag)
					0x21,       // Character set
					0x02, 0x00, // Status flags
					0x00, 0x00, // Capability flags upper
					0x00,                                                       // Auth plugin data length
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
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
	// Create a server that never responds
	server, err := newTestServer("25", []string{"220 test.test.test server\r\n"})
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

	// Connect with very short timeout
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	conn, err := net.Dial("tcp", server.addr())
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	defer conn.Close()

	err = StartTLS(ctx, conn, "25")
	if err == nil {
		t.Error("Expected timeout error but got none")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("Expected context deadline error, got: %v", err)
	}
}
