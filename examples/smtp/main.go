package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jsandas/starttls-go/starttls"
)

func main() {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to SMTP server
	conn, err := net.Dial("tcp", "smtp.gmail.com:587")
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Perform STARTTLS handshake
	if err := starttls.StartTLS(ctx, conn, "587"); err != nil {
		log.Fatalf("STARTTLS failed: %v", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName: "smtp.gmail.com",
		MinVersion: tls.VersionTLS12,
	}

	// Upgrade connection to TLS
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Fatalf("TLS handshake failed: %v", err)
	}

	fmt.Println("Successfully established TLS connection!")

	// Connection is now encrypted with TLS
	// Use tlsConn for further SMTP communication
}
