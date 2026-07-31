#!/bin/bash
set -e

echo "Running setup script..."

CURRENT_DIR=$(pwd)
if [ $(basename "$CURRENT_DIR") != "integration_tests" ]; then
    echo "Please run this script from the integration_tests directory."
    exit 1
fi

# Ensure directory exists
mkdir -p openldap/certs
mkdir -p mailserver/certs
mkdir -p mailserver/config
mkdir -p mysql/certs
mkdir -p ftp/certs

# Generate certificates if they don't exist (or just overwrite for simplicity in test environment)
echo "Generating certificates..."

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=ldap.example.com" \
    -keyout openldap/certs/tls.key \
    -out openldap/certs/tls.crt

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=mail.example.com" \
    -keyout mailserver/certs/tls.key \
    -out mailserver/certs/tls.crt

cat > mailserver/config/hostname.txt <<'EOF'
mail.example.com
EOF
cat > mailserver/config/postfix-accounts.cf <<'EOF'
user@mail.example.com|{SHA512-CRYPT}$6$rounds=5000$abc$def
EOF

cat > mailserver/config/relay-hosts.conf <<'EOF'
EOF

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost" \
    -keyout mysql/certs/server-key.pem \
    -out mysql/certs/server-cert.pem

cp mysql/certs/server-cert.pem mysql/certs/ca.pem

# Generate FTP cert+key bundle for Pure-FTPd (expects combined PEM)
openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost" \
    -keyout ftp/certs/pure-ftpd.key \
    -out ftp/certs/pure-ftpd.crt

cat ftp/certs/pure-ftpd.key ftp/certs/pure-ftpd.crt > ftp/certs/pure-ftpd.pem
rm -f ftp/certs/pure-ftpd.key ftp/certs/pure-ftpd.crt

# Download DH parameters if they don't exist (or just overwrite for simplicity in test environment)
echo "Setting up DH parameters for Dovecot and OpenLDAP..."
if [ ! -f "dhparam.pem" ]; then
    echo "DH parameters do not exist. Downloading..."
    curl -fsSL https://ssl-config.mozilla.org/ffdhe2048.txt -o dhparam.pem

    # cp dhparam.pem mailserver/certs/dhparam.pem
    cp dhparam.pem openldap/certs/dhparam.pem
else  
    echo "DH parameters already exist. Overwriting..."

    # cp dhparam.pem mailserver/certs/dhparam.pem
    cp dhparam.pem openldap/certs/dhparam.pem
fi

echo "Setup complete."
