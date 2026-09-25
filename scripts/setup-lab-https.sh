#!/bin/sh
set -eu

# Generate private Range/Test TLS material only. Deployment is deliberately
# handled by nct-deploy.sh so certificate creation can never start or rebuild
# containers as a side effect.

server_name="${1:-}"
output_root="${2:-.}"
if [ -z "$server_name" ]; then
    printf '%s\n' "Usage: $0 SERVER_IP_OR_NAME [OUTPUT_ROOT]" >&2
    exit 2
fi

command -v openssl >/dev/null 2>&1 || {
    printf '%s\n' "OpenSSL is required to generate lab TLS material." >&2
    exit 1
}

cert_dir="$output_root/certs"
tls_dir="$output_root/tls"
umask 077
mkdir -p "$cert_dir" "$tls_dir"

if [ -e "$tls_dir/nct-lab-ca.key" ] || [ -e "$tls_dir/nct-server.key" ] || \
   [ -e "$tls_dir/nct-server.crt" ] || [ -e "$cert_dir/nct-lab-root.crt" ]; then
    printf '%s\n' "TLS material already exists under $output_root. Refusing to overwrite it." >&2
    exit 1
fi

openssl genrsa -out "$tls_dir/nct-lab-ca.key" 3072
openssl req -x509 -new -key "$tls_dir/nct-lab-ca.key" -sha256 -days 3650 \
    -out "$cert_dir/nct-lab-root.crt" \
    -subj "/CN=Network-Characterization-Tool-Lab-CA"

openssl genrsa -out "$tls_dir/nct-server.key" 2048
openssl req -new -key "$tls_dir/nct-server.key" -out "$tls_dir/nct-server.csr" \
    -subj "/CN=$server_name"

case "$server_name" in
    *:*) san="IP:$server_name" ;;
    *[!0-9.]*) san="DNS:$server_name" ;;
    *) san="IP:$server_name" ;;
esac
printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    "$san" > "$tls_dir/server.ext"

openssl x509 -req -in "$tls_dir/nct-server.csr" \
    -CA "$cert_dir/nct-lab-root.crt" -CAkey "$tls_dir/nct-lab-ca.key" -CAcreateserial \
    -out "$tls_dir/nct-server.crt" -days 825 -sha256 -extfile "$tls_dir/server.ext"

openssl verify -CAfile "$cert_dir/nct-lab-root.crt" "$tls_dir/nct-server.crt" >/dev/null || {
    printf '%s\n' "Generated TLS material did not pass local CA verification." >&2
    exit 1
}

chmod 600 "$tls_dir/nct-lab-ca.key" "$tls_dir/nct-server.key"
chmod 644 "$cert_dir/nct-lab-root.crt" "$tls_dir/nct-server.crt"

printf '%s\n' "NCT lab TLS material generated for $server_name."
printf '%s\n' "Certificate: $tls_dir/nct-server.crt"
printf '%s\n' "Private key: $tls_dir/nct-server.key"
printf '%s\n' "Operator trust certificate: $cert_dir/nct-lab-root.crt"
