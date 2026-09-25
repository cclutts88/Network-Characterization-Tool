#!/bin/sh
set -eu


server_ip="${1:-}"
source_cidr="${2:-}"
admin_user="${3:-clutts}"
image="network-characterization-tool:0.15.9-range-20260924"
https_port="${4:-8445}"

if [ -z "$server_ip" ] || [ -z "$source_cidr" ]; then
    printf '%s\n' "Usage: sh $0 RANGE_IP APPROVED_ANALYST_CIDR [ADMIN_USERNAME] [HTTPS_PORT]" >&2
    exit 2
fi

[ "$(id -u)" -eq 0 ] || { printf '%s\n' "Run this deployment as root." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { printf '%s\n' "Docker is required." >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { printf '%s\n' "OpenSSL is required." >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { printf '%s\n' "curl is required." >&2; exit 1; }
command -v firewall-cmd >/dev/null 2>&1 || { printf '%s\n' "firewalld is required." >&2; exit 1; }
docker info >/dev/null 2>&1 || { printf '%s\n' "Docker is not reachable." >&2; exit 1; }

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bundle_dir=$(dirname "$base_dir")
archive="$bundle_dir/offline-images/nct-range-images.tar"
archive_checksum="$bundle_dir/offline-images/nct-range-images.tar.sha256"
tls_helper="$bundle_dir/scripts/setup-lab-https.sh"
state_dir="$bundle_dir/nct-deployment"
tls_root="$state_dir/tls-material"
password_file="$state_dir/initial-admin-password.txt"

[ -f "$archive" ] || { printf '%s\n' "Missing $archive" >&2; exit 1; }
[ -f "$archive_checksum" ] || { printf '%s\n' "Missing $archive_checksum" >&2; exit 1; }
[ -f "$tls_helper" ] || { printf '%s\n' "Missing $tls_helper" >&2; exit 1; }

(cd "$bundle_dir/offline-images" && sha256sum -c nct-range-images.tar.sha256 >/dev/null) || {
    printf '%s\n' "The offline image archive checksum does not match." >&2
    exit 1
}

if docker inspect nct >/dev/null 2>&1; then
    printf '%s\n' "A container named nct already exists. This script will not replace it." >&2
    exit 1
fi

if command -v ss >/dev/null 2>&1 && ss -ltn | awk -v p="$https_port" 'NR > 1 && $4 ~ (":" p "$") { found=1 } END { exit(found ? 0 : 1) }'; then
    printf '%s\n' "TCP port $https_port is already in use. Choose another HTTPS port." >&2
    exit 1
fi

printf '%s\n' "Loading the verified NCT image..."
docker load -i "$archive"
docker image inspect "$image" >/dev/null 2>&1 || {
    printf '%s\n' "The expected image tag was not loaded from the archive." >&2
    exit 1
}

mkdir -p "$state_dir"
if [ -e "$tls_root/tls/nct-server.crt" ] || [ -e "$tls_root/tls/nct-server.key" ]; then
    printf '%s\n' "TLS material already exists at $tls_root; refusing to overwrite it." >&2
    exit 1
fi
sh "$tls_helper" "$server_ip" "$tls_root"

docker volume create nct-data >/dev/null
docker run --rm "$image" python -c 'import secrets; print(secrets.token_urlsafe(24), end="")' > "$password_file"
chmod 600 "$password_file"

printf '%s\n' "Creating the initial Administrator and starting NCT..."
docker run -d --name nct --restart unless-stopped \
    --cap-add NET_RAW --security-opt seccomp=unconfined \
    -p "$server_ip:$https_port:$https_port" \
    -v nct-data:/data \
    -v "$tls_root/tls/nct-server.crt:/run/tls/nct-server.crt:ro" \
    -v "$tls_root/tls/nct-server.key:/run/tls/nct-server.key:ro" \
    -v "$password_file:/run/secrets/nct_bootstrap_password:ro" \
    -e NCT_AUTH_MODE=local -e NCT_SESSION_HOURS=12 -e NCT_COOKIE_SECURE=1 \
    -e NCT_BOOTSTRAP_ADMIN="$admin_user" \
    -e NCT_BOOTSTRAP_PASSWORD_FILE=/run/secrets/nct_bootstrap_password \
    "$image" uvicorn app.main:app --host 0.0.0.0 --port "$https_port" \
    --loop asyncio --http h11 --ssl-certfile /run/tls/nct-server.crt \
    --ssl-keyfile /run/tls/nct-server.key >/dev/null

attempt=0
until curl -kfsS "https://$server_ip:$https_port/health" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        printf '%s\n' "NCT did not become healthy. Review: docker logs nct" >&2
        exit 1
    fi
    sleep 1
done

docker exec nct python -c 'import sqlite3,sys; db=sqlite3.connect("/data/analyzer.db"); row=db.execute("SELECT role FROM analyst_users WHERE username = ?", (sys.argv[1],)).fetchone(); assert row and row[0] == "admin"' "$admin_user"

# Recreate the same container without retaining the one-time bootstrap secret.
docker stop nct >/dev/null
docker rm nct >/dev/null
docker run -d --name nct --restart unless-stopped \
    --cap-add NET_RAW --security-opt seccomp=unconfined \
    -p "$server_ip:$https_port:$https_port" \
    -v nct-data:/data \
    -v "$tls_root/tls/nct-server.crt:/run/tls/nct-server.crt:ro" \
    -v "$tls_root/tls/nct-server.key:/run/tls/nct-server.key:ro" \
    -e NCT_AUTH_MODE=local -e NCT_SESSION_HOURS=12 -e NCT_COOKIE_SECURE=1 \
    "$image" uvicorn app.main:app --host 0.0.0.0 --port "$https_port" \
    --loop asyncio --http h11 --ssl-certfile /run/tls/nct-server.crt \
    --ssl-keyfile /run/tls/nct-server.key >/dev/null

attempt=0
until curl -kfsS "https://$server_ip:$https_port/health" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        printf '%s\n' "NCT did not become healthy after removing the bootstrap secret. Review: docker logs nct" >&2
        exit 1
    fi
    sleep 1
done

firewall_rule="rule family=ipv4 source address=$source_cidr destination address=$server_ip port port=$https_port protocol=tcp accept"
if ! firewall-cmd --query-rich-rule="$firewall_rule" >/dev/null 2>&1; then
    firewall-cmd --permanent --add-rich-rule="$firewall_rule"
    firewall-cmd --reload
fi
firewall-cmd --query-rich-rule="$firewall_rule" >/dev/null 2>&1 || {
    printf '%s\n' "NCT is healthy, but the restricted firewall rule could not be verified." >&2
    exit 1
}

printf '%s\n' "NCT is healthy at https://$server_ip:$https_port"
printf '%s\n' "Administrator username: $admin_user"
printf '%s\n' "Initial password file: $password_file"
printf '%s\n' "Display it once with: cat $password_file"
printf '%s\n' "Set a chosen password with: sh $bundle_dir/scripts/nct-set-admin-password.sh $admin_user"
printf '%s\n' "After successful sign-in, delete that password file."
printf '%s\n' "Analyst CA certificate: $tls_root/certs/nct-lab-root.crt"
