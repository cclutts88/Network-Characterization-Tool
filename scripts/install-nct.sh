#!/bin/sh
set -eu

# Guided operator entry point for NCT Test and Range deployment. This script
# collects choices and delegates all validation, rollback, and deployment work
# to nct-deploy.sh.

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
deploy_script="$script_dir/nct-deploy.sh"
tls_script="$script_dir/setup-lab-https.sh"
state_dir="$repo_dir/nct-deployment"
preset_file=""
plan_only="no"

usage() {
    printf '%s\n' "Usage: sh scripts/install-nct.sh [--state-dir DIR] [--preset FILE] [--plan-only]"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --state-dir) state_dir=${2:?missing state directory}; shift 2 ;;
        --preset) preset_file=${2:?missing preset file}; shift 2 ;;
        --plan-only) plan_only="yes"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; printf '%s\n' "[NCT] ERROR: Unknown option: $1" >&2; exit 1 ;;
    esac
done

preset_file=${preset_file:-"$state_dir/range-preset.env"}

say() { printf '%s\n' "[NCT Installer] $*"; }
die() { printf '%s\n' "[NCT Installer] ERROR: $*" >&2; exit 1; }

preset_value() {
    [ -r "$preset_file" ] || return 0
    awk -F= -v wanted="$1" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' "$preset_file"
}

default_value() {
    saved=$(preset_value "$1")
    if [ -n "$saved" ]; then printf '%s\n' "$saved"; else printf '%s\n' "$2"; fi
}

prompt_value() {
    label=$1
    default=$2
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$label" "$default" >&2
    else
        printf '%s: ' "$label" >&2
    fi
    IFS= read -r answer || answer=""
    printf '%s\n' "${answer:-$default}"
}

prompt_yes_no() {
    label=$1
    default=$2
    if [ "$default" = "yes" ]; then hint="Y/n"; else hint="y/N"; fi
    while :; do
        printf '%s [%s]: ' "$label" "$hint" >&2
        IFS= read -r answer || answer=""
        answer=${answer:-$default}
        case "$answer" in
            y|Y|yes|YES) printf '%s\n' yes; return ;;
            n|N|no|NO) printf '%s\n' no; return ;;
            *) printf '%s\n' "Please answer yes or no." >&2 ;;
        esac
    done
}

api_at_least() {
    awk -v have="$1" -v need="$2" 'BEGIN {
        split(have, h, "."); split(need, n, ".")
        ok = (h[1] + 0 > n[1] + 0) || (h[1] + 0 == n[1] + 0 && h[2] + 0 >= n[2] + 0)
        exit(ok ? 0 : 1)
    }'
}

detect_bind_address() {
    detected=$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i !~ /^127\./ && $i !~ /:/){print $i; exit}}')
    if [ -z "$detected" ] && command -v ip >/dev/null 2>&1; then
        detected=$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')
    fi
    printf '%s\n' "$detected"
}

detect_image() {
    command -v docker >/dev/null 2>&1 || return 0
    docker image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | awk '
        $0 !~ /:<none>$/ && $0 !~ /:latest$/ &&
        tolower($0) ~ /(network-characterization|nct)/ {print; exit}'
}

detect_test_receipt() {
    receipt_dir="$state_dir/receipts"
    [ -d "$receipt_dir" ] || return 0
    find "$receipt_dir" -maxdepth 1 -type f -name 'test-*.receipt' -print 2>/dev/null | sort -r | head -n 1
}

printf '\n%s\n' "NCT - Network Characterization Tool"
printf '%s\n\n' "Guided Test / Range installer"
if [ -r "$preset_file" ]; then say "Using saved non-sensitive defaults from $preset_file"; fi

profile=$(prompt_value "Deployment profile (range/test)" "$(default_value profile range)")
case "$profile" in r|R|range|Range) profile="range" ;; t|T|test|Test) profile="test" ;; *) die "Choose range or test." ;; esac

access_default="local"
[ "$profile" != "range" ] || access_default="lan"
access=$(prompt_value "Access mode (lan/local)" "$(default_value access "$access_default")")
case "$access" in l|L|lan|LAN) access="lan" ;; local|Local) access="local" ;; *) die "Choose lan or local." ;; esac

bind_address="127.0.0.1"
if [ "$access" = "lan" ]; then
    detected_bind=$(detect_bind_address)
    bind_address=$(prompt_value "Server address analysts will use" "$(default_value bind_address "$detected_bind")")
    [ -n "$bind_address" ] || die "LAN installation requires a server address."
fi

tls_default="no"
[ "$profile" != "range" ] || tls_default="yes"
tls_enabled=$(prompt_yes_no "Use HTTPS" "$(default_value tls_enabled "$tls_default")")
tls_mode="none"
tls_cert=""
tls_key=""
tls_ca=""
tls_root="$state_dir/tls-material"
if [ "$tls_enabled" = "yes" ]; then
    existing_generated="no"
    [ -r "$tls_root/tls/nct-server.crt" ] && [ -r "$tls_root/tls/nct-server.key" ] && existing_generated="yes"
    tls_mode_default="generate"
    [ "$existing_generated" = "no" ] || tls_mode_default="existing"
    tls_mode=$(prompt_value "TLS material (generate/existing)" "$(default_value tls_mode "$tls_mode_default")")
    case "$tls_mode" in
        g|G|generate|Generate)
            tls_mode="generate"
            tls_cert="$tls_root/tls/nct-server.crt"
            tls_key="$tls_root/tls/nct-server.key"
            tls_ca="$tls_root/certs/nct-lab-root.crt"
            ;;
        e|E|existing|Existing)
            tls_mode="existing"
            tls_cert=$(prompt_value "Server certificate path" "$(default_value tls_cert "$tls_root/tls/nct-server.crt")")
            tls_key=$(prompt_value "Server private-key path" "$(default_value tls_key "$tls_root/tls/nct-server.key")")
            tls_ca=$(prompt_value "Operator trust / CA certificate path" "$(default_value tls_ca "$tls_root/certs/nct-lab-root.crt")")
            ;;
        *) die "Choose generate or existing TLS material." ;;
    esac
fi

if [ "$tls_enabled" = "yes" ]; then
    port_label="HTTPS port"
    port_default="8444"
    port_key="https_port"
else
    port_label="Application port"
    port_default="8766"
    [ "$profile" != "range" ] || port_default="8081"
    port_key="app_port"
fi
selected_port=$(prompt_value "$port_label" "$(default_value "$port_key" "$port_default")")
case "$selected_port" in ''|*[!0-9]*) die "Port must be numeric." ;; esac
[ "$selected_port" -ge 1 ] && [ "$selected_port" -le 65535 ] || die "Port must be between 1 and 65535."

configure_firewall="no"
source_cidr=""
if [ "$access" = "lan" ]; then
    firewall_default="no"
    [ "$profile" != "range" ] || firewall_default="yes"
    configure_firewall=$(prompt_yes_no "Allow NCT to create a narrow firewall rule if needed" "$(default_value configure_firewall "$firewall_default")")
    if [ "$configure_firewall" = "yes" ]; then
        source_cidr=$(prompt_value "Approved analyst source subnet (CIDR)" "$(default_value source_cidr '')")
        [ -n "$source_cidr" ] || die "A firewall change requires the approved analyst source subnet."
    fi
fi

server_api="unknown"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    server_api=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || printf unknown)
fi
allow_legacy="no"
case "$server_api" in
    unknown|'') ;;
    *)
        if ! api_at_least "$server_api" "1.41"; then
            say "Docker API $server_api matches the older Range-host pattern."
            allow_legacy=$(prompt_yes_no "Allow the verified Range-only runtime probes and workaround" "$(default_value allow_legacy_range_runtime yes)")
        fi
        ;;
esac

image_default=$(detect_image)
image=$(prompt_value "Versioned NCT image" "$(default_value image "$image_default")")
[ -n "$image" ] || die "A versioned NCT image is required."
case "$image" in *:latest|latest) die "Choose an immutable versioned image, not latest." ;; *@sha256:*|*:*) ;; *) die "Image must include a version tag or digest." ;; esac
printf '%s' "$image" | grep -F '<none>' >/dev/null 2>&1 && die "Choose a named immutable image, not an untagged image." || true

offline_default="no"
[ "$profile" != "range" ] || offline_default="yes"
offline=$(prompt_yes_no "Air-gapped / offline installation" "$(default_value offline "$offline_default")")
image_archive=""
image_sha256=""
if [ "$offline" = "yes" ]; then
    use_archive=$(prompt_yes_no "Load an offline image archive" "$(default_value use_image_archive no)")
    if [ "$use_archive" = "yes" ]; then
        image_archive=$(prompt_value "Offline image archive path" "$(default_value image_archive '')")
        [ -r "$image_archive" ] || [ "$plan_only" = "yes" ] || die "Image archive is not readable: $image_archive"
        image_sha256=$(default_value image_sha256 '')
        if [ -z "$image_sha256" ] && [ -r "$image_archive" ] && command -v sha256sum >/dev/null 2>&1; then
            say "Calculating the offline image checksum..."
            image_sha256=$(sha256sum "$image_archive" | awk '{print $1}')
        fi
        image_sha256=$(prompt_value "Expected image SHA-256" "$image_sha256")
        [ -n "$image_sha256" ] || die "Offline archives require a SHA-256 value."
    fi
fi

promotion_receipt=""
if [ "$profile" = "range" ]; then
    promotion_receipt=$(prompt_value "Matching Test acceptance receipt" "$(default_value promotion_receipt "$(detect_test_receipt)")")
    [ -n "$promotion_receipt" ] || die "Range installation requires the matching Test acceptance receipt."
    [ -r "$promotion_receipt" ] || [ "$plan_only" = "yes" ] || die "Receipt is not readable: $promotion_receipt"
fi

auth_default="local"
auth_mode=$(prompt_value "Authentication (local/disabled)" "$(default_value auth_mode "$auth_default")")
case "$auth_mode" in local|Local) auth_mode="local" ;; disabled|Disabled) auth_mode="disabled" ;; *) die "Choose local or disabled authentication." ;; esac
[ "$profile" != "range" ] || [ "$auth_mode" = "local" ] || die "Range installation requires local authentication."
admin_user=""
if [ "$auth_mode" = "local" ]; then
    admin_user=$(prompt_value "Initial Administrator username (used only if account store is empty)" "$(default_value admin_user nctadmin)")
fi

printf '\n%s\n' "Installation review"
printf '  Profile:          %s\n' "$profile"
printf '  Access:           %s on %s:%s\n' "$access" "$bind_address" "$selected_port"
printf '  HTTPS:            %s%s\n' "$tls_enabled" "${tls_mode:+ ($tls_mode)}"
printf '  Firewall:         %s%s\n' "$configure_firewall" "${source_cidr:+ from $source_cidr}"
printf '  Docker API:       %s\n' "$server_api"
printf '  Legacy workaround:%s\n' " $allow_legacy"
printf '  Image:            %s\n' "$image"
printf '  Offline:          %s\n' "$offline"
printf '  Authentication:   %s\n' "$auth_mode"
printf '  State directory:  %s\n\n' "$state_dir"

if [ "$plan_only" = "yes" ]; then
    say "Plan complete. No certificate, firewall, image, container, or preset state was changed."
    exit 0
fi

approved=$(prompt_yes_no "Run the safe preflight with these settings" yes)
[ "$approved" = "yes" ] || die "Installation cancelled before preflight."

command -v docker >/dev/null 2>&1 || die "Docker Engine is not installed or is not on PATH."
docker info >/dev/null 2>&1 || die "Docker is installed but its daemon is not reachable."
if ! docker image inspect "$image" >/dev/null 2>&1; then
    if [ -n "$image_archive" ]; then
        stage_image=$(prompt_yes_no "The selected image is not loaded. Verify and stage the offline archive now" yes)
        [ "$stage_image" = "yes" ] || die "Installation stopped before the image was staged."
        command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to stage the offline image."
        actual_sha=$(sha256sum "$image_archive" | awk '{print $1}')
        [ "$actual_sha" = "$image_sha256" ] || die "Image archive checksum does not match."
        docker load -i "$image_archive" >/dev/null
    elif [ "$offline" = "yes" ]; then
        die "The selected image is not loaded and no offline image archive was provided."
    else
        pull_image=$(prompt_yes_no "The selected image is not local. Pull it before preflight" yes)
        [ "$pull_image" = "yes" ] || die "Installation stopped before the image was pulled."
        docker pull "$image"
    fi
    docker image inspect "$image" >/dev/null 2>&1 || die "The staged archive or pull did not provide the selected image $image."
fi

if [ "$tls_mode" = "generate" ]; then
    [ ! -e "$tls_key" ] || die "Generated TLS keys already exist. Choose existing TLS material instead."
    sh "$tls_script" "$bind_address" "$tls_root"
fi

set -- "$deploy_script" --profile "$profile" --access "$access" --bind "$bind_address" --image "$image" --state-dir "$state_dir" --auth "$auth_mode"
if [ "$tls_enabled" = "yes" ]; then
    set -- "$@" --https-port "$selected_port" --tls-cert "$tls_cert" --tls-key "$tls_key" --tls-ca "$tls_ca"
else
    set -- "$@" --port "$selected_port"
fi
[ "$offline" = "no" ] || set -- "$@" --offline
if [ -n "$image_archive" ]; then set -- "$@" --image-archive "$image_archive" --image-sha256 "$image_sha256"; fi
if [ -n "$promotion_receipt" ]; then set -- "$@" --promote-from-receipt "$promotion_receipt"; fi
if [ "$configure_firewall" = "yes" ]; then set -- "$@" --source-cidr "$source_cidr" --configure-firewall; fi
if [ "$allow_legacy" = "yes" ]; then set -- "$@" --allow-legacy-range-runtime; fi
if [ "$auth_mode" = "local" ]; then set -- "$@" --admin-user "$admin_user" --generate-admin-password; fi

say "Running non-destructive deployment preflight..."
sh "$@" --check-only

deploy_now=$(prompt_yes_no "Preflight passed. Install NCT now" yes)
[ "$deploy_now" = "yes" ] || die "Installation stopped after the successful preflight; no container or firewall change was made."
sh "$@" --yes

mkdir -p "$state_dir"
mkdir -p "$(dirname -- "$preset_file")"
preset_tmp="${preset_file}.tmp.$$"
umask 077
preset_tls_mode=$tls_mode
[ "$preset_tls_mode" != "generate" ] || preset_tls_mode="existing"
saved_app_port=$(default_value app_port 8766)
saved_https_port=$(default_value https_port 8444)
if [ "$tls_enabled" = "yes" ]; then saved_https_port=$selected_port; else saved_app_port=$selected_port; fi
{
    printf 'profile=%s\naccess=%s\nbind_address=%s\napp_port=%s\nhttps_port=%s\n' "$profile" "$access" "$bind_address" "$saved_app_port" "$saved_https_port"
    printf 'tls_enabled=%s\ntls_mode=%s\ntls_cert=%s\ntls_key=%s\ntls_ca=%s\n' "$tls_enabled" "$preset_tls_mode" "$tls_cert" "$tls_key" "$tls_ca"
    printf 'configure_firewall=%s\nsource_cidr=%s\nallow_legacy_range_runtime=%s\n' "$configure_firewall" "$source_cidr" "$allow_legacy"
    printf 'image=%s\noffline=%s\nuse_image_archive=%s\nimage_archive=%s\nimage_sha256=%s\n' "$image" "$offline" "${use_archive:-no}" "$image_archive" "$image_sha256"
    printf 'promotion_receipt=%s\nauth_mode=%s\nadmin_user=%s\n' "$promotion_receipt" "$auth_mode" "$admin_user"
} > "$preset_tmp"
chmod 600 "$preset_tmp"
mv "$preset_tmp" "$preset_file"
say "Saved non-sensitive defaults for the next reset at $preset_file"
