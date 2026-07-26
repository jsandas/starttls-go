#!/bin/bash
set -e

echo "Running setup script..."

# Ensure directory exists
mkdir -p openldap/certs
mkdir -p postfix/certs

# Generate certificates if they don't exist (or just overwrite for simplicity in test environment)
echo "Generating certificates..."

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=ldap.example.com" \
    -keyout openldap/certs/tls.key \
    -out openldap/certs/tls.crt

openssl genpkey -genparam -algorithm DH \
    -out openldap/certs/dhparam.pem \
    -pkeyopt dh_paramgen_prime_len:2048

openssl req -x509 -newkey rsa:2048 \
    -days 3650 -nodes \
    -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=smtp.example.com" \
    -keyout postfix/certs/tls.key \
    -out postfix/certs/tls.crt

echo "Setup complete."
