# starttls-go

[![CI](https://github.com/jsandas/starttls-go/actions/workflows/ci.yml/badge.svg)](https://github.com/jsandas/starttls-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jsandas/starttls-go)](https://goreportcard.com/report/github.com/jsandas/starttls-go)
[![GoDoc](https://godoc.org/github.com/jsandas/starttls-go?status.svg)](https://godoc.org/github.com/jsandas/starttls-go)

A Go module that handles STARTTLS negotiation for various protocols. STARTTLS allows upgrading a plain text connection to use TLS encryption after the initial connection is established.

## Supported Protocols

- SMTP (ports 25, 587)
- IMAP (port 143)
- POP3 (port 110)
- FTP (port 21)
- MySQL (port 3306)
- Direct TLS ports (443, 465, 993, 995, 3389)

## Installation

```bash
go get github.com/jsandas/starttls-go
```

## Usage

Basic usage with SMTP:

```go
import (
    "context"
    "crypto/tls"
    "net"
    
    "github.com/jsandas/starttls-go/starttls"
)

func main() {
    // Connect to server
    conn, err := net.Dial("tcp", "mail.example.com:25")
    if err != nil {
        // Handle error
    }
    defer conn.Close()

    // Perform STARTTLS handshake
    if err := starttls.StartTLS(context.Background(), conn, "25"); err != nil {
        // Handle error
    }

    // Configure TLS
    tlsConfig := &tls.Config{
        ServerName: "mail.example.com",
        MinVersion: tls.VersionTLS12,
    }

    // Upgrade to TLS
    tlsConn := tls.Client(conn, tlsConfig)
    if err := tlsConn.Handshake(); err != nil {
        // Handle error
    }

    // Use tlsConn for secure communication
}
```

For more examples, see the [examples](./examples) directory.

## Features

- Protocol-specific STARTTLS negotiation
- Context support for timeouts and cancellation
- Clean interface design
- Comprehensive error handling
- No external dependencies
- Well-tested with high coverage

## Protocol Support Details

### SMTP
- Supports both port 25 and 587
- Performs EHLO negotiation
- Verifies STARTTLS capability

### IMAP
- Handles initial greeting
- Supports STARTTLS command
- Verifies server capability

### POP3
- Supports STLS command
- Handles server greeting
- Verifies successful upgrade

### FTP
- Supports AUTH TLS
- Handles server response codes
- Manages control channel upgrade

### MySQL
- Handles initial handshake packet
- Checks SSL capability flags
- Manages SSL request packet

### Direct TLS
- Automatically handles ports that use direct TLS
- No negotiation needed for ports 443, 465, 993, 995, 3389

## Error Handling

The module provides specific error types:
- `ErrStartTLSNotSupported`: Server doesn't support STARTTLS
- `ErrInvalidResponse`: Invalid server response
- `ErrUnsupportedProtocol`: Protocol/port not supported

## Security Considerations

1. **TLS Version**: Always use TLS 1.2 or later in production.
2. **Certificate Verification**: Enable certificate verification by default.
3. **Timeouts**: Use context with appropriate timeouts.
4. **Error Checking**: Always check for errors during negotiation.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Acknowledgments

This module was inspired by the need for a reusable STARTTLS implementation across different protocols. Special thanks to the Go community for their feedback and contributions.
