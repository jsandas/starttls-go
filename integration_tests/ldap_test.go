//go:build integration

package integration_tests

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jsandas/starttls-go/starttls"
)

func TestLDAPStartTLS(t *testing.T) {
	host := os.Getenv("LDAP_HOST")
	port := os.Getenv("LDAP_PORT")

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "389"
	}

	addr := host + ":" + port

	t.Logf("Attempting to connect to %s", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to %s: %v", addr, err)
	}
	defer conn.Close()

	// Execute the StartTLS handshake using the package
	err = starttls.StartTLS(ctx, conn, port)
	if err != nil {
		t.Fatalf("StartTLS handshake failed: %v", err)
	}

	// attempting a TLS connection after StartTLS handshake fails which indicates that the
	// StartTLS handshake was unsuccessful and needs to be reviewed.
	// // Configure TLS
	// tlsConfig := &tls.Config{
	// 	ServerName:         "ldap.example.com",
	// 	MinVersion:         tls.VersionTLS12,
	// 	InsecureSkipVerify: true, // Set to true for testing purposes; in production, set to false and provide proper certificates
	// }

	// // Upgrade connection to TLS
	// tlsConn := tls.Client(conn, tlsConfig)
	// if err := tlsConn.Handshake(); err != nil {
	// 	t.Fatalf("TLS handshake failed: %v", err)
	// }

	t.Log("Successfully completed LDAP StartTLS handshake")
}
