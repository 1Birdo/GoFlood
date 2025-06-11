#!/bin/bash

# Configuration
IP_ADDRESS="172.17.126.64"
SERVER_CN="CNC Server"
CLIENT_CN="CNC Client"
DAYS_VALID=3650
KEY_SIZE=4096
PASSWORD="changeit"  # Password for PKCS12 files, change as needed

# Create certs directory
mkdir -p certs
cd certs || exit

# Generate CA private key
echo "Generating CA private key..."
openssl genrsa -out ca.key $KEY_SIZE

# Generate CA certificate
echo "Generating CA certificate..."
openssl req -new -x509 -days $DAYS_VALID -key ca.key -out ca.crt -subj "/CN=CNC Server CA"

# Create CA chain file (same as ca.crt in this case)
cp ca.crt ca-chain.crt

# Generate server private key
echo "Generating server private key..."
openssl genrsa -out server.key $KEY_SIZE

# Generate server config file for SAN
echo "Creating server SAN config..."
cat > server.cnf <<EOL
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]
commonName = $SERVER_CN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $IP_ADDRESS
EOL

# Generate server CSR
echo "Generating server CSR..."
openssl req -new -key server.key -out server.csr -config server.cnf

# Sign server certificate with CA
echo "Signing server certificate..."
openssl x509 -req -days $DAYS_VALID -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -extensions v3_req -extfile server.cnf

# Create pinned.crt (fingerprint of server certificate)
echo "Creating pinned.crt..."
openssl x509 -in server.crt -out pinned.crt

# Create properly formatted server.pem
echo "Creating server.pem..."
cat server.crt > server.pem
echo "" >> server.pem
cat server.key >> server.pem

# Create server PKCS12 file
echo "Creating server.p12..."
openssl pkcs12 -export -out server.p12 -inkey server.key -in server.crt -certfile ca.crt -passout pass:$PASSWORD

# Generate client private key
echo "Generating client private key..."
openssl genrsa -out client.key $KEY_SIZE

# Generate client config file for SAN
echo "Creating client SAN config..."
cat > client.cnf <<EOL
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]
commonName = $CLIENT_CN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $IP_ADDRESS
EOL

# Generate client CSR
echo "Generating client CSR..."
openssl req -new -key client.key -out client.csr -config client.cnf

# Sign client certificate with CA
echo "Signing client certificate..."
openssl x509 -req -days $DAYS_VALID -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -extensions v3_req -extfile client.cnf

# Create properly formatted client.pem
echo "Creating client.pem..."
cat client.crt > client.pem
echo "" >> client.pem
cat client.key >> client.pem

# Create client PKCS12 file
echo "Creating client.p12..."
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt -passout pass:$PASSWORD

# Create combined truststore (CA certificate)
echo "Creating truststore.p12..."
keytool -import -trustcacerts -noprompt -alias ca -file ca.crt -keystore truststore.p12 -storetype PKCS12 -storepass $PASSWORD

# Create full chain files
echo "Creating full chain files..."
cat server.crt ca.crt > server-full-chain.crt
cat client.crt ca.crt > client-full-chain.crt

# Set proper permissions
chmod 600 *.key *.pem *.p12 *.crt

# Clean up
rm -f *.csr *.cnf *.srl

echo ""
echo "============================================"
echo "Certificate generation complete!"
echo "Files generated in certs/ directory:"
echo "--------------------------------------------"
ls -l
echo "============================================"