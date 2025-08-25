package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	// Set up connection timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect to Postfix SMTP server
	conn, err := net.Dial("tcp", "smtp.gmail.com:25")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Perform STARTTLS handshake
	if err := StartTLS(ctx, conn, "25"); err != nil {
		log.Fatalf("STARTTLS failed: %v", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName:         "mail.example.com", // Must match the server's certificate
		InsecureSkipVerify: false,              // Set to true only for testing
		MinVersion:         tls.VersionTLS12,   // Minimum TLS version
	}

	// Upgrade connection to TLS
	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	// Perform TLS handshake
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Fatalf("TLS handshake failed: %v", err)
	}

	// Verify the connection state
	state := tlsConn.ConnectionState()
	fmt.Printf("TLS connection established:\n")
	fmt.Printf("  Version: %x\n", state.Version)
	fmt.Printf("  CipherSuite: %x\n", state.CipherSuite)
	fmt.Printf("  Server Name: %s\n", state.ServerName)

	// At this point, you can use the tlsConn for secure SMTP communication
	// For example:
	// fmt.Fprintf(tlsConn, "EHLO example.com\r\n")
	// etc...
}
