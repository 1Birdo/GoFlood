#!/bin/bash
set -e

# ===== CONFIGURATION =====
# IP Addresses (Replace with yours)
C2_IP="104.194.144.77"
PROXY_IP="104.194.140.54"
CLIENT_IP="45.61.152.21"

# Certificate Settings
DAYS_VALID=3650           # 10 years
KEY_SIZE=4096             # RSA key size
PASSWORD="changeit"       # Password for PKCS12 files

# Common Names (CN)
CA_CN="CNC Root CA"
SERVER_CN="CNC Server"
PROXY_CN="CNC Proxy"
CLIENT_CN="CNC Client"

# ===== CERTIFICATE GENERATION =====
CERTS_DIR="certs"
mkdir -p $CERTS_DIR
cd $CERTS_DIR

# 1. Generate Certificate Authority (CA)
echo -e "\n\033[1;36m[+] Generating CA Certificate\033[0m"
mkdir -p ca && cd ca
openssl genrsa -out ca.key $KEY_SIZE
openssl req -new -x509 -days $DAYS_VALID -key ca.key -out ca.crt -subj "/CN=$CA_CN"
cp ca.crt ../
cd ..

# 2. Generate C2 Server Certificates
echo -e "\n\033[1;36m[+] Generating C2 Server Certificate\033[0m"
mkdir -p server && cd server
openssl genrsa -out server.key $KEY_SIZE
openssl req -new -key server.key -out server.csr -subj "/CN=$SERVER_CN" -addext "subjectAltName=IP:$C2_IP,DNS:cnc.example.com"
openssl x509 -req -days $DAYS_VALID -in server.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial -out server.crt -extfile <(printf "subjectAltName=IP:$C2_IP,DNS:cnc.example.com")

# Create pinned.crt (copy of server.crt)
cp server.crt pinned.crt

# Create combined PEM and PKCS12
cat server.crt server.key > server.pem
openssl pkcs12 -export -out server.p12 -inkey server.key -in server.crt -certfile ../ca/ca.crt -passout pass:$PASSWORD
cd ..



# 3. Generate Proxy Certificates
echo -e "\n\033[1;36m[+] Generating Proxy Certificate\033[0m"
mkdir -p proxy && cd proxy
openssl genrsa -out proxy.key $KEY_SIZE
openssl req -new -key proxy.key -out proxy.csr -subj "/CN=$PROXY_CN" -addext "subjectAltName=IP:$PROXY_IP,DNS:proxy.example.com"
openssl x509 -req -days $DAYS_VALID -in proxy.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial -out proxy.crt -extfile <(printf "subjectAltName=IP:$PROXY_IP,DNS:proxy.example.com")
cat proxy.crt proxy.key > proxy.pem
openssl pkcs12 -export -out proxy.p12 -inkey proxy.key -in proxy.crt -certfile ../ca/ca.crt -passout pass:$PASSWORD
cd ..

# 4. Generate Client Certificates
echo -e "\n\033[1;36m[+] Generating Client Certificate\033[0m"
mkdir -p client && cd client
openssl genrsa -out client.key $KEY_SIZE
openssl req -new -key client.key -out client.csr -subj "/CN=$CLIENT_CN" -addext "subjectAltName=IP:$CLIENT_IP"
openssl x509 -req -days $DAYS_VALID -in client.csr -CA ../ca/ca.crt -CAkey ../ca/ca.key -CAcreateserial -out client.crt -extfile <(printf "subjectAltName=IP:$CLIENT_IP")
cat client.crt client.key > client.pem
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ../ca/ca.crt -passout pass:$PASSWORD
cd ..

# ===== FINAL SETUP =====
# Set strict permissions
chmod 600 */*.key */*.pem */*.crt

# Generate truststore (for Java-based apps)
echo -e "\n\033[1;36m[+] Generating Truststore\033[0m"
keytool -import -trustcacerts -noprompt -alias ca -file ca/ca.crt -keystore truststore.p12 -storetype PKCS12 -storepass $PASSWORD

# Cleanup temporary files
rm -f */*.csr */*.srl

echo -e "\n\033[1;32m✅ Certificates generated successfully!\033[0m"
echo -e "📁 Directory Structure:"
tree .

echo -e "\n\033[1;33m🔐 Password for PKCS12 files: $PASSWORD\033[0m"