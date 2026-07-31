//go:build integration

package integrationtests

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jsandas/starttls-go/starttls"
)

func TestMySQLStartTLS(t *testing.T) {
	host := os.Getenv("MYSQL_HOST")
	port := os.Getenv("MYSQL_PORT")

	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "3306"
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

	err = starttls.StartTLS(ctx, conn, port)
	if err != nil {
		t.Fatalf("StartTLS handshake failed: %v", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	t.Log("Successfully completed MySQL StartTLS handshake")
}
