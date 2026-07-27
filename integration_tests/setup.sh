#!/bin/bash
set -e

echo "Running setup script..."

CURRENT_DIR=$(pwd)
if [ $(basename "$CURRENT_DIR") != "integration_tests" ]; then
    echo "Please run this script from the integration_tests directory."
    exit 1
fi

# Ensure directory exists
mkdir -p dovecot/certs
mkdir -p openldap/certs
mkdir -p postfix/certs

# Generate certificates if they don't exist (or just overwrite for simplicity in test environment)
echo "Generating certificates..."

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=dovecot.example.com" \
    -keyout dovecot/certs/tls.key \
    -out dovecot/certs/tls.crt

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=ldap.example.com" \
    -keyout openldap/certs/tls.key \
    -out openldap/certs/tls.crt

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=smtp.example.com" \
    -keyout postfix/certs/tls.key \
    -out postfix/certs/tls.crt

# Download DH parameters if they don't exist (or just overwrite for simplicity in test environment)
echo "Setting up DH parameters for Dovecot and OpenLDAP..."
if [ ! -f "dhparam.pem" ]; then
    echo "DH parameters do not exist. Downloading..."
    curl -fsSL https://ssl-config.mozilla.org/ffdhe2048.txt -o dhparam.pem

    cp dhparam.pem dovecot/certs/dhparam.pem
    cp dhparam.pem openldap/certs/dhparam.pem
else  
    echo "DH parameters already exist. Overwriting..."

    cp dhparam.pem dovecot/certs/dhparam.pem
    cp dhparam.pem openldap/certs/dhparam.pem
fi

echo "Setup complete."
