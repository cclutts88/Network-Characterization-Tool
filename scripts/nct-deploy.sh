#!/bin/sh
set -eu

# NCT rapid deployment and rollback launcher for Linux Docker hosts.
# It intentionally uses the Docker API directly after validating Compose so the
# same swap behavior works on modern Compose, legacy Compose, and Engine-only hosts.

profile="test"
access="local"
bind_address=""
app_port="8766"
https_port="443"
image="network-characterization-tool:latest"
image_archive=""
image_sha256=""
container="nct"
data_volume="nct-data"
volume_supplied="no"
source_cidr=""
tls_cert=""
tls_key=""
tls_ca=""
configure_firewall="no"
check_only="no"
assume_yes="no"
offline="no"
skip_backup="no"
state_dir="./nct-deployment"
minimum_api="1.41"
lock_dir="${TMPDIR:-/tmp}/nct-deploy.lock"

say() { printf '%s\n' "[NCT] $*"; }
warn() { printf '%s\n' "[NCT] WARNING: $*" >&2; }
die() { printf '%s\n' "[NCT] ERROR: $*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sh scripts/nct-deploy.sh [options]

  --profile test|range|mission     Deployment acceptance profile
  --access local|lan               Bind only to loopback or a chosen LAN address
  --bind ADDRESS                   Required for deterministic LAN deployments
  --port PORT                      Direct HTTP/application port (default 8766)
  --https-port PORT                HTTPS proxy port when TLS is configured
  --image IMAGE                    Immutable/versioned NCT image reference
  --image-archive FILE             Load an air-gapped Docker image archive
  --image-sha256 SHA256            Verify the archive before loading it
  --container NAME                 Active analyzer container name
  --volume NAME                    Persistent NCT data volume
  --tls-cert FILE --tls-key FILE   Enable the Caddy HTTPS proxy
  --tls-ca FILE                    CA file used for the final trusted HTTPS check
  --source-cidr CIDR               Restrict a firewall rule to approved sources
  --configure-firewall             Create a narrow UFW/firewalld rule
  --state-dir DIR                  Deployment logs, proxy config, and backups
  --offline                        Never pull images or require internet
  --skip-backup                    Skip pre-upgrade backup (not allowed for mission)
  --check-only                     Run preflight without changing containers
  --yes                            Approve the container swap non-interactively
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile) profile=${2:?missing profile}; shift 2 ;;
        --access) access=${2:?missing access mode}; shift 2 ;;
        --bind) bind_address=${2:?missing address}; shift 2 ;;
        --port) app_port=${2:?missing port}; shift 2 ;;
        --https-port) https_port=${2:?missing HTTPS port}; shift 2 ;;
        --image) image=${2:?missing image}; shift 2 ;;
        --image-archive) image_archive=${2:?missing archive}; shift 2 ;;
        --image-sha256) image_sha256=${2:?missing checksum}; shift 2 ;;
        --container) container=${2:?missing container}; shift 2 ;;
        --volume) data_volume=${2:?missing volume}; volume_supplied="yes"; shift 2 ;;
        --tls-cert) tls_cert=${2:?missing certificate}; shift 2 ;;
        --tls-key) tls_key=${2:?missing key}; shift 2 ;;
        --tls-ca) tls_ca=${2:?missing CA}; shift 2 ;;
        --source-cidr) source_cidr=${2:?missing CIDR}; shift 2 ;;
        --state-dir) state_dir=${2:?missing directory}; shift 2 ;;
        --configure-firewall) configure_firewall="yes"; shift ;;
        --check-only) check_only="yes"; shift ;;
        --yes) assume_yes="yes"; shift ;;
        --offline) offline="yes"; shift ;;
        --skip-backup) skip_backup="yes"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

case "$profile" in test|range|mission) ;; *) die "Profile must be test, range, or mission." ;; esac
case "$access" in local|lan) ;; *) die "Access must be local or lan." ;; esac
case "$app_port:$https_port" in *[!0-9:]*|:*) die "Ports must be numeric." ;; esac
[ "$app_port" -ge 1 ] && [ "$app_port" -le 65535 ] || die "Application port is outside 1-65535."
[ "$https_port" -ge 1 ] && [ "$https_port" -le 65535 ] || die "HTTPS port is outside 1-65535."
[ "$profile" != "mission" ] || [ "$skip_backup" = "no" ] || die "Mission upgrades cannot skip the backup."
[ "$profile" != "mission" ] || die "Mission deployment is intentionally fail-closed until NCT authentication and the mission promotion gate are implemented. Use Test or Range for the current evaluation build."

if ! mkdir "$lock_dir" 2>/dev/null; then
    die "Another deployment launcher appears active at $lock_dir."
fi
cleanup_lock() { rmdir "$lock_dir" 2>/dev/null || true; }
trap cleanup_lock EXIT
trap 'cleanup_lock; exit 130' HUP INT TERM

command -v docker >/dev/null 2>&1 || die "Docker Engine is not installed or is not on PATH."
docker info >/dev/null 2>&1 || die "Docker is installed but its daemon is not reachable. Start Docker or correct the active context."
command -v curl >/dev/null 2>&1 || die "curl is required for the final access-path health check."

server_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || printf unknown)
server_api=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || printf unknown)
docker_context=$(docker context show 2>/dev/null || printf unknown)
case "$server_api" in
    unknown|'') [ "$profile" = "range" ] || die "Docker server API version could not be read." ;;
    *)
        api_supported=$(awk -v have="$server_api" -v need="$minimum_api" 'BEGIN {
            split(have, h, "."); split(need, n, ".")
            ok = (h[1] + 0 > n[1] + 0) || (h[1] + 0 == n[1] + 0 && h[2] + 0 >= n[2] + 0)
            print ok ? "yes" : "no"
        }')
        [ "$api_supported" = "yes" ] || die "Docker API $server_api is older than supported API $minimum_api. Use the documented offline NCT appliance fallback on this host." ;;
esac

compose_mode="absent"
compose_version="not installed"
if docker compose version >/dev/null 2>&1; then
    compose_mode="plugin"
    compose_version=$(docker compose version --short 2>/dev/null || docker compose version 2>/dev/null)
elif command -v docker-compose >/dev/null 2>&1; then
    compose_mode="legacy"
    compose_version=$(docker-compose version --short 2>/dev/null || docker-compose version 2>/dev/null)
fi

architecture=$(docker info --format '{{.Architecture}}' 2>/dev/null || uname -m)
case "$architecture" in amd64|x86_64|arm64|aarch64) ;; *) die "Unsupported Docker architecture: $architecture" ;; esac
os_type=$(docker info --format '{{.OSType}}' 2>/dev/null || printf unknown)
[ "$os_type" = "linux" ] || die "NCT requires Docker Linux containers; the current daemon reports $os_type."

available_kb=$(df -Pk . 2>/dev/null | awk 'NR==2 {print $4}')
case "$available_kb" in ''|*[!0-9]*) warn "Free disk space could not be measured." ;; *) [ "$available_kb" -ge 2097152 ] || die "At least 2 GiB free space is required for image staging, evidence, and rollback." ;; esac

if [ "$access" = "local" ]; then
    [ -z "$bind_address" ] || [ "$bind_address" = "127.0.0.1" ] || [ "$bind_address" = "::1" ] || die "Local access may bind only to a loopback address."
    bind_address=${bind_address:-127.0.0.1}
else
    if [ -z "$bind_address" ]; then
        bind_address=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    [ -n "$bind_address" ] || die "LAN access requires --bind with the approved host address."
    [ "$bind_address" != "0.0.0.0" ] || die "Choose one LAN address instead of exposing NCT on every interface."
fi

tls_enabled="no"
if [ -n "$tls_cert$tls_key" ]; then
    [ -n "$tls_cert" ] && [ -n "$tls_key" ] || die "TLS requires both --tls-cert and --tls-key."
    [ -r "$tls_cert" ] && [ -r "$tls_key" ] || die "The TLS certificate or key is not readable."
    command -v openssl >/dev/null 2>&1 || die "OpenSSL is required to validate the supplied TLS certificate."
    openssl x509 -in "$tls_cert" -noout -checkend 86400 >/dev/null 2>&1 || die "The TLS certificate is invalid or expires within 24 hours."
    if ! openssl x509 -in "$tls_cert" -noout -text 2>/dev/null | grep -F "$bind_address" >/dev/null 2>&1; then
        [ "$profile" != "mission" ] || die "The TLS certificate does not contain the mission host address/name $bind_address."
        warn "The certificate text does not visibly contain $bind_address; confirm its SAN before use."
    fi
    tls_enabled="yes"
fi
[ "$profile" != "mission" ] || [ "$access" = "lan" ] || die "Mission profile requires a declared LAN address."
[ "$profile" != "mission" ] || [ "$tls_enabled" = "yes" ] || die "Mission profile requires a validated TLS certificate and key."
[ "$profile" != "mission" ] || [ -n "$tls_ca" ] || die "Mission profile requires --tls-ca for a trusted final HTTPS check."

mkdir -p "$state_dir" "$state_dir/backups" "$state_dir/logs" "$state_dir/proxy"
log_file="$state_dir/logs/deploy-$(date -u +%Y%m%dT%H%M%SZ).log"
umask 077
{
    printf 'profile=%s\naccess=%s\nbind=%s\napp_port=%s\nhttps_port=%s\n' "$profile" "$access" "$bind_address" "$app_port" "$https_port"
    printf 'docker_server=%s\ndocker_api=%s\ndocker_context=%s\ncompose=%s\ncompose_version=%s\narchitecture=%s\n' "$server_version" "$server_api" "$docker_context" "$compose_mode" "$compose_version" "$architecture"
    printf 'image=%s\nvolume=%s\ntls=%s\nstarted=%s\n' "$image" "$data_volume" "$tls_enabled" "$(date -u +%FT%TZ)"
} > "$log_file"

if [ -n "$image_archive" ]; then
    [ -r "$image_archive" ] || die "Offline image archive is not readable: $image_archive"
    if [ -n "$image_sha256" ]; then
        command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to verify the image archive."
        actual_sha=$(sha256sum "$image_archive" | awk '{print $1}')
        [ "$actual_sha" = "$image_sha256" ] || die "Image archive checksum does not match."
    elif [ "$profile" = "mission" ]; then
        die "Mission offline images require --image-sha256."
    else
        warn "The supplied offline image archive has no checksum."
    fi
    [ "$check_only" = "yes" ] || docker load -i "$image_archive" >/dev/null
fi

if ! docker image inspect "$image" >/dev/null 2>&1; then
    [ "$check_only" = "yes" ] && warn "Image $image is not local; check-only did not pull or load it." || {
        [ "$offline" = "no" ] || die "Image $image is unavailable locally and offline mode forbids a pull."
        docker pull "$image"
    }
fi

existing_id=$(docker ps -aq --filter "name=^/${container}$" | head -n 1)
existing_image="none"
if [ -n "$existing_id" ]; then
    existing_image=$(docker inspect --format '{{.Config.Image}}' "$container")
    set +e
    docker exec "$container" python -c 'import glob,json,sys; active=[]
for p in glob.glob("/data/**/manifest.json",recursive=True):
    try:
        d=json.load(open(p,encoding="utf-8"))
        if d.get("status") in {"queued","running","awaiting_fallback_approval","updating","migrating"}: active.append((p,d.get("status")))
    except Exception: pass
sys.exit(42 if active else 0)' >/dev/null 2>&1
    active_rc=$?
    set -e
    if [ "$active_rc" -ne 0 ]; then
        [ "$active_rc" -ne 42 ] || die "The existing NCT instance has an active scan, collection, update, or migration. Finish or stop it before upgrading."
        warn "The existing container could not prove that no operation is active."
        [ "$profile" = "test" ] || die "Range and Mission upgrades require a successful active-operation check."
    fi

    existing_volume=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{if eq .Type "volume"}}{{.Name}}{{end}}{{end}}{{end}}' "$container" 2>/dev/null || printf '')
    if [ -n "$existing_volume" ]; then
        if [ "$volume_supplied" = "yes" ] && [ "$existing_volume" != "$data_volume" ]; then
            die "Existing NCT data is in volume $existing_volume, not requested volume $data_volume. Re-run with --volume $existing_volume or perform a documented migration."
        fi
        data_volume=$existing_volume
    else
        warn "The existing container does not expose a named /data volume that the launcher can safely preserve."
        [ "$profile" = "test" ] || die "Range and Mission upgrades require a recognized named /data volume."
    fi
fi

published_port=$app_port
[ "$tls_enabled" = "no" ] || published_port=$https_port
proxy_name="${container}-https"
conflict=$(docker ps --format '{{.Names}}|{{.Ports}}' | awk -F'|' -v keep="$container" -v proxy="$proxy_name" -v port=":$published_port->" '$1 != keep && $1 != proxy && index($2,port) {print $1; exit}')
if [ -n "$conflict" ]; then
    if [ "$profile" = "test" ] || [ "$profile" = "range" ]; then
        original=$published_port
        while [ "$published_port" -lt 65535 ] && docker ps --format '{{.Names}}|{{.Ports}}' | awk -F'|' -v keep="$container" -v proxy="$proxy_name" -v port=":$published_port->" '$1 != keep && $1 != proxy && index($2,port) {found=1} END {exit !found}'; do published_port=$((published_port + 1)); done
        [ "$published_port" -le 65535 ] || die "No alternate port could be selected."
        warn "Port $original is used by $conflict; selected $published_port for this $profile deployment."
        if [ "$tls_enabled" = "yes" ]; then https_port=$published_port; else app_port=$published_port; fi
    else
        die "Mission port $published_port is occupied by $conflict; choose an explicit stable port or resolve the conflict."
    fi
fi

firewall_tool="none"
firewall_changed="no"
if [ "$access" = "lan" ]; then
    command -v ufw >/dev/null 2>&1 && firewall_tool="ufw"
    command -v firewall-cmd >/dev/null 2>&1 && firewall_tool="firewalld"
    if [ "$configure_firewall" = "yes" ]; then
        [ "$(id -u)" -eq 0 ] || die "--configure-firewall requires an elevated/root shell."
        [ "$firewall_tool" != "none" ] || die "No supported active firewall manager was found; configure the narrow inbound rule manually."
        say "A narrow $firewall_tool rule is staged for $bind_address:$published_port and will be applied only after confirmation."
        printf 'firewall_tool=%s\nfirewall_changed=staged\n' "$firewall_tool" >> "$log_file"
    else
        warn "LAN mode needs an inbound TCP rule for $bind_address:$published_port. No firewall change was made."
        printf 'firewall_tool=%s\nfirewall_changed=no\n' "$firewall_tool" >> "$log_file"
    fi
fi

say "Profile: $profile · Docker $server_version/API $server_api · Compose $compose_mode $compose_version"
say "Image: $image · Existing: $existing_image · Data: $data_volume"
say "Access: $access on $bind_address:$published_port · TLS: $tls_enabled"
say "Deployment log: $log_file"
[ "$check_only" = "no" ] || { say "Preflight complete; no container, firewall, or image state was changed."; exit 0; }

if [ "$tls_enabled" = "yes" ]; then
    docker image inspect caddy:2-alpine >/dev/null 2>&1 || { [ "$offline" = "no" ] && docker pull caddy:2-alpine >/dev/null; }
    docker image inspect caddy:2-alpine >/dev/null 2>&1 || die "The Caddy TLS image is unavailable; no container swap was attempted."
fi

if [ "$assume_yes" != "yes" ]; then
    printf 'Proceed with the NCT container swap? [y/N] '
    read answer
    case "$answer" in y|Y|yes|YES) ;; *) die "Deployment cancelled before the swap." ;; esac
fi

backup_file="none"
if [ -n "$existing_id" ] && [ "$skip_backup" = "no" ]; then
    backup_name="nct-data-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
    backup_file="$state_dir/backups/$backup_name"
    backup_abs=$(cd "$state_dir/backups" && pwd)
    docker run --rm -v "$data_volume:/data:ro" -v "$backup_abs:/backup" "$image" sh -c "cd /data && tar -czf /backup/$backup_name ."
    [ -s "$backup_file" ] || die "The pre-upgrade backup was not created."
fi

rollback_name=""
rollback_proxy_name=""
swap_started="no"

remove_firewall_rule() {
    [ "$firewall_changed" = "yes" ] || return 0
    case "$firewall_tool" in
        ufw)
            if [ -n "$source_cidr" ]; then ufw --force delete allow from "$source_cidr" to "$bind_address" port "$published_port" proto tcp >/dev/null; else ufw --force delete allow to "$bind_address" port "$published_port" proto tcp >/dev/null; fi ;;
        firewalld)
            if [ -n "$source_cidr" ]; then firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 source address=$source_cidr destination address=$bind_address port port=$published_port protocol=tcp accept" >/dev/null; else firewall-cmd --permanent --remove-port="$published_port/tcp" >/dev/null; fi
            firewall-cmd --reload >/dev/null ;;
    esac
    firewall_changed="rolled-back"
}

apply_firewall_rule() {
    case "$firewall_tool" in
        ufw)
            if [ -n "$source_cidr" ]; then ufw allow from "$source_cidr" to "$bind_address" port "$published_port" proto tcp; else ufw allow to "$bind_address" port "$published_port" proto tcp; fi ;;
        firewalld)
            if [ -n "$source_cidr" ]; then firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$source_cidr destination address=$bind_address port port=$published_port protocol=tcp accept"; else firewall-cmd --permanent --add-port="$published_port/tcp"; fi
            firewall-cmd --reload ;;
        *) return 1 ;;
    esac
}

rollback() {
    warn "New deployment failed; restoring the previous container when available."
    remove_firewall_rule || warn "The NCT firewall rule could not be removed automatically; review $firewall_tool."
    docker rm -f "$proxy_name" >/dev/null 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
    if [ -n "$rollback_name" ] && docker inspect "$rollback_name" >/dev/null 2>&1; then
        docker rename "$rollback_name" "$container"
        docker start "$container" >/dev/null
    fi
    if [ -n "$rollback_proxy_name" ] && docker inspect "$rollback_proxy_name" >/dev/null 2>&1; then
        docker rename "$rollback_proxy_name" "$proxy_name"
        docker start "$proxy_name" >/dev/null
    fi
    exit 1
}

handle_interruption() {
    if [ "$swap_started" = "yes" ]; then rollback; fi
    exit 130
}
trap handle_interruption HUP INT TERM

if [ -n "$existing_id" ]; then
    rollback_name="${container}-rollback-$(date -u +%Y%m%d%H%M%S)"
    swap_started="yes"
    docker stop "$container" >/dev/null || rollback
    docker rename "$container" "$rollback_name" || rollback
fi
existing_proxy_id=$(docker ps -aq --filter "name=^/${proxy_name}$" | head -n 1)
if [ -n "$existing_proxy_id" ]; then
    rollback_proxy_name="${proxy_name}-rollback-$(date -u +%Y%m%d%H%M%S)"
    swap_started="yes"
    docker stop "$proxy_name" >/dev/null 2>&1 || true
    docker rename "$proxy_name" "$rollback_proxy_name" || rollback
fi
swap_started="yes"

if [ "$tls_enabled" = "yes" ]; then
    docker run -d --name "$container" --restart unless-stopped --cap-add NET_RAW \
        -v "$data_volume:/data" "$image" >/dev/null || rollback
else
    docker run -d --name "$container" --restart unless-stopped --cap-add NET_RAW \
        -p "$bind_address:$app_port:8080" -v "$data_volume:/data" "$image" >/dev/null || rollback
fi

healthy="no"
attempt=0
while [ "$attempt" -lt 30 ]; do
    if docker exec "$container" python -c 'import json,urllib.request; d=json.load(urllib.request.urlopen("http://127.0.0.1:8080/health",timeout=2)); assert d.get("status")=="ok"' >/dev/null 2>&1; then healthy="yes"; break; fi
    attempt=$((attempt + 1)); sleep 1
done
[ "$healthy" = "yes" ] || rollback

if [ "$tls_enabled" = "yes" ]; then
    network_name="${container}-network"
    docker network inspect "$network_name" >/dev/null 2>&1 || docker network create "$network_name" >/dev/null
    docker network connect "$network_name" "$container" >/dev/null 2>&1 || true
    cert_abs=$(cd "$(dirname "$tls_cert")" && pwd)/$(basename "$tls_cert")
    key_abs=$(cd "$(dirname "$tls_key")" && pwd)/$(basename "$tls_key")
    proxy_dir=$(cd "$state_dir/proxy" && pwd)
    printf ':443 {\n  tls /certs/server.crt /certs/server.key\n  reverse_proxy %s:8080\n}\n' "$container" > "$proxy_dir/Caddyfile"
    docker rm -f "$proxy_name" >/dev/null 2>&1 || true
    docker run -d --name "$proxy_name" --restart unless-stopped --network "$network_name" \
        -p "$bind_address:$https_port:443" \
        -v "$proxy_dir/Caddyfile:/etc/caddy/Caddyfile:ro" \
        -v "$cert_abs:/certs/server.crt:ro" -v "$key_abs:/certs/server.key:ro" \
        caddy:2-alpine >/dev/null || rollback
fi

if [ "$configure_firewall" = "yes" ]; then
    apply_firewall_rule || rollback
    firewall_changed="yes"
fi

reported_build=$(docker exec "$container" python -c 'import json,urllib.request; print(json.load(urllib.request.urlopen("http://127.0.0.1:8080/health"))["build_id"])' 2>/dev/null || printf unknown)
if [ "$tls_enabled" = "yes" ]; then
    access_url="https://$bind_address:$https_port"
    if [ -n "$tls_ca" ]; then
        curl --fail --silent --show-error --cacert "$tls_ca" "$access_url/health" >/dev/null || rollback
    else
        curl --fail --silent --show-error --insecure "$access_url/health" >/dev/null || rollback
    fi
else
    [ "$access" = "local" ] || warn "Direct LAN mode is HTTP only; use TLS before mission deployment."
    access_url="http://$bind_address:$app_port"
    curl --fail --silent --show-error "$access_url/health" >/dev/null || rollback
fi

printf 'completed=%s\nreported_build=%s\nbackup=%s\nurl=%s\nrollback_container=%s\n' "$(date -u +%FT%TZ)" "$reported_build" "$backup_file" "$access_url" "${rollback_name:-none}" >> "$log_file"
swap_started="no"

cat <<EOF

                 __..---..__
            _.-'             '-._
       _.-'___     /\ /\     ___'-._
     .'_______\___/  V  \___/_______'.
    /_________________________________\\
             .-============-.
            /    _      _    \\
           |    (x)    (x)    |
           |         /\        |
           |    __.-'  '-.__   |
           | .-'   \____/   '-.|
            \      ||||||     /
             '._   ||||||  _.'
                '--|_||_|--'

                    N C T
        Network Characterization Tool
       Available at $access_url

EOF
say "Verified build $reported_build. Previous container: ${rollback_name:-none}. Backup: $backup_file"
