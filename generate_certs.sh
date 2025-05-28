#!/bin/bash

set -e

# Directory for certificates
CERT_DIR="./certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[+] Generating Certificate Authority (CA)..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=My CA"

echo "[+] Generating Server Certificate..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
-out server.crt -days 365 -sha256

echo "[+] Generating Client Certificate..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=Client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
-out client.crt -days 365 -sha256

# Output fingerprint for pinning in Go code
echo "[+] Calculating certificate fingerprint for pinning..."
FINGERPRINT=$(openssl x509 -in client.crt -outform DER | sha256sum | awk '{print $1}' | xxd -r -p | base64)
echo "-----------------------------------------------------"
echo "Paste this into your Go code as the expected fingerprint:"
echo ""
echo "const expectedCertFingerprint = \"SHA256:$FINGERPRINT\""
echo ""
echo "-----------------------------------------------------"

# # Copy required files to the project root for Go server
# cp server.crt ../server.crt
# cp server.key ../server.key
# cp ca.crt ../ca.crt

echo "[✓] Certificates generated successfully."

echo ""
echo "📡 To test the connection with OpenSSL as the client:"
echo ""
echo "openssl s_client -connect 127.0.0.1:420 \\"
echo "  -cert certs/client.crt -key certs/client.key \\"
echo "  -CAfile certs/ca.crt"
echo ""
