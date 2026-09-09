#!/bin/sh
set -eu

server_ip="${1:-}"
if [ -z "$server_ip" ]; then
    echo "Usage: $0 SERVER_IP" >&2
    exit 2
fi

umask 077
mkdir -p certs tls caddy-data caddy-config

if [ -e tls/nct-lab-ca.key ] || [ -e tls/nct-server.key ]; then
    echo "Certificate keys already exist. Refusing to overwrite them." >&2
    exit 1
fi

openssl genrsa -out tls/nct-lab-ca.key 3072
openssl req -x509 -new -key tls/nct-lab-ca.key -sha256 -days 3650 \
    -out certs/nct-lab-root.crt \
    -subj "/CN=Network-Characterization-Tool-Lab-CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl genrsa -out tls/nct-server.key 2048
openssl req -new -key tls/nct-server.key -out tls/nct-server.csr \
    -subj "/CN=$server_ip"

cat > tls/server.ext <<EOF
subjectAltName=IP:$server_ip
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in tls/nct-server.csr \
    -CA certs/nct-lab-root.crt -CAkey tls/nct-lab-ca.key -CAcreateserial \
    -out tls/nct-server.crt -days 825 -sha256 -extfile tls/server.ext

chmod 600 tls/nct-lab-ca.key tls/nct-server.key
chmod 644 certs/nct-lab-root.crt tls/nct-server.crt

docker compose up -d --build

echo "HTTPS is ready at https://$server_ip/"
echo "Install http://$server_ip/nct-lab-root.crt in each operator's Trusted Root Certification Authorities store once."
