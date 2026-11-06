#!/bin/sh
# Trusted full-package bootstrap; never accepted as a browser update payload.
set -eu
umask 077
export PYTHONDONTWRITEBYTECODE=1
NCT_PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
export NCT_WORKDIR="$NCT_PACKAGE_ROOT"
NCT_RANGE_IP=${1:-}
NCT_RECOVERY_BIND_ADDRESS=${NCT_RECOVERY_BIND_ADDRESS:-$NCT_RANGE_IP}
NCT_SETUP_MODE=${2:-all}
NCT_TARGET_CONTAINER=${NCT_CONTAINER:-nct}
export NCT_CONTAINER="$NCT_TARGET_CONTAINER"
NCT_PERSIST_ROOT=${NCT_PERSIST_ROOT:-/var/lib/nct}
NCT_RECOVERY_STATE_DIR=${NCT_RECOVERY_STATE_DIR:-$NCT_PERSIST_ROOT/deployment/recovery-console}
export NCT_PERSIST_ROOT
die() { printf '%s\n' "[NCT package] $*" >&2; exit 1; }
progress() { printf '%s\n' "[NCT setup $1] $2"; }
[ "$(id -u)" -eq 0 ] || die "Run as root."
[ -n "$NCT_RANGE_IP" ] || die "Usage: sh scripts/nct-install-range.sh NCT_HOST_IP [fresh|resume-fresh|check-fresh|all|check|enable-console]"
case "$NCT_SETUP_MODE" in fresh|resume-fresh|check-fresh|all|check|enable-console) ;; *) die "Choose fresh, resume-fresh, check-fresh, all, check or enable-console." ;; esac
for tool in docker systemctl sha256sum openssl curl ss flock; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required on the offline host. Nothing was installed or downloaded."
done
fresh_admission() {
    for location in "$NCT_PERSIST_ROOT" "$NCT_RECOVERY_STATE_DIR" "${NCT_RECOVERY_INSTALL_DIR:-/opt/nct-recovery}"; do
        case "$location" in /*) ;; *) die "Fresh storage and recovery paths must be absolute." ;; esac
        case "/${location#/}/" in *//*|*/./*|*/../*) die "Fresh storage paths must be normalized and must not use symbolic links." ;; esac
        path_part=$location
        while [ "$path_part" != / ]; do
            [ ! -L "$path_part" ] || die "Fresh storage paths must be normalized and must not use symbolic links."
            path_part=${path_part%/*}
            [ -n "$path_part" ] || path_part=/
        done
        if [ -e "$location" ]; then
            [ -d "$location" ] || die "A dedicated fresh storage or recovery path is occupied."
            first_entry=$(find "$location" -mindepth 1 -maxdepth 1 -print -quit) || die "Fresh storage could not be inspected; emptiness was not proven."
            [ -z "$first_entry" ] || die "A dedicated NCT storage or recovery folder is not empty. Fresh setup will not adopt or erase it."
        fi
    done
    docker inspect "$NCT_TARGET_CONTAINER" >/dev/null 2>&1 && die "An NCT container already exists. Fresh setup will not replace it."
    return 0
}
if [ "$NCT_SETUP_MODE" = fresh ] || [ "$NCT_SETUP_MODE" = check-fresh ]; then
    progress "1/6" "Checking the host, empty NCT locations and Docker access."
    docker info >/dev/null 2>&1 || die "Docker is not reachable; no installation changes were made."
    fresh_admission
fi
if [ "$NCT_SETUP_MODE" = resume-fresh ]; then
    progress "1/6" "Checking the exact interrupted fresh installation."
    docker info >/dev/null 2>&1 || die "Docker is not reachable; the interrupted installation was not changed."
    docker inspect "$NCT_TARGET_CONTAINER" >/dev/null 2>&1 || die "No interrupted NCT container exists. Use fresh for a new empty host."
fi
. "$NCT_PACKAGE_ROOT/scripts/nct-recovery-python.sh"
NCT_RECOVERY_PYTHON=$(nct_select_recovery_python "$NCT_PACKAGE_ROOT") || die "Recovery interpreter check failed before changing NCT."
export NCT_RECOVERY_PYTHON
NCT_UPGRADE_PYTHON="$NCT_RECOVERY_PYTHON"
export NCT_UPGRADE_PYTHON
for NCT_LOCATION in "$NCT_RECOVERY_STATE_DIR" "${NCT_RECOVERY_INSTALL_DIR:-/opt/nct-recovery}"; do
    [ ! -e "$NCT_LOCATION" ] || [ -d "$NCT_LOCATION" ] || die "Recovery location is occupied by a file. Preserve it and review the installation paths."
done
NCT_HELPER_UNIT=$(systemctl show --property=LoadState --value nct-recovery-host.service) || die "The recovery service state could not be checked. Preserve the application and review systemd."
[ "$NCT_HELPER_UNIT" = not-found ] && [ ! -e /etc/systemd/system/nct-recovery-host.service ] || die "The recovery service already exists. Preserve it and use the reviewed helper-upgrade procedure."
if [ -d "$NCT_RECOVERY_STATE_DIR" ] && [ -n "$(find "$NCT_RECOVERY_STATE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    die "Recovery state already exists. Preserve its configuration and receipts; this package does not overwrite an installed helper."
fi
if [ -f "${NCT_RECOVERY_INSTALL_DIR:-/opt/nct-recovery}/config.json" ] || docker inspect "${NCT_RECOVERY_CONTAINER:-$NCT_TARGET_CONTAINER-recovery-console}" >/dev/null 2>&1; then
    die "A recovery helper is already installed. Preserve it and use the reviewed helper-upgrade procedure before changing NCT."
fi
"$NCT_RECOVERY_PYTHON" -c 'import sys,ipaddress; [ipaddress.ip_address(value) for value in sys.argv[1:]]' "$NCT_RANGE_IP" "$NCT_RECOVERY_BIND_ADDRESS" || die "Host address check failed."
docker info >/dev/null 2>&1 || die "Docker is unavailable."
systemctl show-environment >/dev/null 2>&1 || die "A working systemd host service is required."
(cd "$NCT_PACKAGE_ROOT" && sha256sum -c PACKAGE-MANIFEST.sha256) || die "Package integrity check failed; preserve the installed NCT."
if [ "$NCT_SETUP_MODE" = fresh ] || [ "$NCT_SETUP_MODE" = check-fresh ]; then
    progress "2/6" "Package and host prerequisites passed."
fi
case "$NCT_PERSIST_ROOT" in /*) ;; *) die "NCT_PERSIST_ROOT must be an absolute dedicated NCT directory." ;; esac
case "$NCT_PERSIST_ROOT" in /|/var|/var/lib|/etc|/root) die "Choose a dedicated NCT persistent directory." ;; esac
NCT_APP_PORT=${NCT_HTTPS_PORT:-8445}
NCT_CONSOLE_PORT=${NCT_RECOVERY_PORT:-8446}
export NCT_HTTPS_PORT="$NCT_APP_PORT"
NCT_EXISTING_SOURCE=0
"$NCT_RECOVERY_PYTHON" -c 'import sys; p=list(map(int,sys.argv[1:])); assert all(1<=v<=65535 for v in p) and len(set(p))==2' "$NCT_APP_PORT" "$NCT_CONSOLE_PORT" || die "Choose two different valid application and recovery ports."
if docker inspect "$NCT_TARGET_CONTAINER" >/dev/null 2>&1; then
    NCT_EXISTING_SOURCE=1
    NCT_DATA_TYPE=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}}{{end}}{{end}}' "$NCT_TARGET_CONTAINER" )
    NCT_DATA_SOURCE=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$NCT_TARGET_CONTAINER" )
    [ "$NCT_DATA_TYPE" = bind ] && [ "$NCT_DATA_SOURCE" = "$NCT_PERSIST_ROOT/data" ] || die "Existing NCT evidence is not the qualified bind folder. Preserve it and use the documented migration procedure; this package does not reset it."
    NCT_PORT=$(docker inspect --format '{{range $p,$items := .HostConfig.PortBindings}}{{if eq $p "8445/tcp"}}{{range $items}}{{println .HostPort}}{{end}}{{end}}{{end}}' "$NCT_TARGET_CONTAINER" | sed '/^$/d')
    [ "$NCT_PORT" = "$NCT_APP_PORT" ] || die "Existing NCT port differs. Set NCT_HTTPS_PORT to its actual single HTTPS port before retrying."
    if [ "$NCT_SETUP_MODE" != enable-console ] && [ "$NCT_SETUP_MODE" != resume-fresh ]; then
        NCT_SOURCE=$(docker exec "$NCT_TARGET_CONTAINER" python -c 'from app.build_info import BUILD_ID,BUILD_COMMIT; print(BUILD_ID+"@"+BUILD_COMMIT)')
        NCT_REQUIRED_SOURCE_VERSION=$("$NCT_RECOVERY_PYTHON" -c 'import json,sys; sources=json.load(open(sys.argv[1])); matches=[s for s in sources if s["build_id"]+"@"+s["commit"]==sys.argv[2]]; assert len(matches)==1, "Unqualified source build"; print(matches[0]["schema_version"])' "$NCT_PACKAGE_ROOT/scripts/nct-package-sources.json" "$NCT_SOURCE") || die "This full-package upgrade refuses an unqualified source build. Preserve the current installation."
        export NCT_REQUIRED_SOURCE_VERSION
    fi
fi
NCT_CERT="$NCT_PERSIST_ROOT/tls-material/tls/nct-server.crt"
NCT_KEY="$NCT_PERSIST_ROOT/tls-material/tls/nct-server.key"
NCT_CA=${NCT_CA_FILE:-$NCT_PERSIST_ROOT/tls-material/certs/nct-lab-root.crt}
if [ -f "$NCT_CERT" ]; then
    [ -f "$NCT_KEY" ] && [ -f "$NCT_CA" ] || die "Existing HTTPS key or root CA is missing. Set NCT_CA_FILE to the issuing CA; do not substitute an unrelated server certificate."
    openssl verify -CAfile "$NCT_CA" "$NCT_CERT" >/dev/null || die "Existing certificate is not trusted by the selected CA."
    curl --noproxy '*' --cacert "$NCT_CA" --connect-timeout 3 --max-time 10 -fsS "https://$NCT_RANGE_IP:$NCT_APP_PORT/health" >/dev/null || die "Issuing-CA verified HTTPS to this host IP failed. Preserve existing TLS and review its address or trust chain."
fi
if ! docker inspect "$NCT_TARGET_CONTAINER" >/dev/null 2>&1; then
    if [ -e "$NCT_PERSIST_ROOT/data" ] && [ -n "$(find "$NCT_PERSIST_ROOT/data" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        die "Retained evidence exists without its exact source container. Use recovery/migration; fresh installation will not adopt or reset it."
    fi
fi
if ss -ltn | awk -v p="$NCT_CONSOLE_PORT" 'NR>1 && $4 ~ (":" p "$") {f=1} END {exit(f?0:1)}'; then
    die "Recovery port is already in use; inspect the existing console or choose NCT_RECOVERY_PORT."
fi
printf '%s\n' "Offline prerequisites and package checks passed. Existing evidence and accounts have not been changed."
"$NCT_RECOVERY_PYTHON" -c 'import sys; from pathlib import Path; root=Path(sys.argv[1]); assert root.is_absolute() and all(len(str(root/"sockets"/kind/name).encode())<108 for kind,name in (("launch","launch.sock"),("control","control.sock"))), "Recovery state path is too long; choose a shorter dedicated NCT_RECOVERY_STATE_DIR"' "$NCT_RECOVERY_STATE_DIR" || die "Recovery socket path check failed before changing NCT."
NCT_IMAGE=$("$NCT_RECOVERY_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["application_image"])' "$NCT_PACKAGE_ROOT/release.json")
NCT_CONSOLE_IMAGE=$("$NCT_RECOVERY_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["console_image"])' "$NCT_PACKAGE_ROOT/release.json")
exact_images_loaded() {
    "$NCT_RECOVERY_PYTHON" "$NCT_PACKAGE_ROOT/scripts/nct-verify-loaded-images.py" "$NCT_PACKAGE_ROOT/release.json"
}
if exact_images_loaded; then
    progress "3/6" "The exact release images are already loaded; the large archive will not be loaded again."
else
    progress "3/6" "Loading the verified offline images. This is usually the longest step."
    docker load -i "$NCT_PACKAGE_ROOT/offline-images/nct-range-images.tar"
    exact_images_loaded || die "Loaded images do not match this release manifest. NCT storage and services were not created."
fi
printf '%s\n' "Checking the loaded application and recovery runtime under normal container security..."
for NCT_RUNTIME_KIND in app console; do
    if [ "$NCT_RUNTIME_KIND" = app ]; then NCT_RUNTIME_IMAGE="$NCT_IMAGE"; else NCT_RUNTIME_IMAGE="$NCT_CONSOLE_IMAGE"; fi
    set -- docker run --rm -i --network none --read-only --cap-drop ALL
    # The app already requires NET_RAW for its collection tools. Alpine fping
    # carries that file capability, even when invoked only for its version.
    if [ "$NCT_RUNTIME_KIND" = app ]; then set -- "$@" --cap-add NET_RAW; fi
    "$@" --entrypoint python "$NCT_RUNTIME_IMAGE" - "$NCT_RUNTIME_KIND" < "$NCT_PACKAGE_ROOT/scripts/nct-runtime-admission.py" || die "The exact loaded runtime is incompatible with this Docker host. NCT storage and services were not created; no security settings were relaxed."
done
progress "4/6" "Exact application and recovery runtimes passed normal-security admission."
case "$NCT_SETUP_MODE" in
    check-fresh)
        printf '%s\n' "Fresh-install preflight passed. No NCT storage, container, account, certificate or service was created."
        exit 0
        ;;
    check) exit 0 ;;
esac
if [ "$NCT_SETUP_MODE" = all ] || [ "$NCT_SETUP_MODE" = fresh ] || [ "$NCT_SETUP_MODE" = resume-fresh ]; then
    if [ "$NCT_SETUP_MODE" = fresh ]; then
        # Image loading is lengthy: refuse newly occupied state rather than ever
        # treating a fresh request as an upgrade/adoption request.
        fresh_admission
    fi
    if [ "$NCT_SETUP_MODE" = resume-fresh ]; then
        NCT_FRESH_RECEIPT="$NCT_PERSIST_ROOT/deployment/bootstrap/fresh-resume.json"
        NCT_FRESH_PHASE=$("$NCT_RECOVERY_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["phase"])' "$NCT_FRESH_RECEIPT" 2>/dev/null || true)
        if [ "$NCT_FRESH_PHASE" = runtime_ready ]; then
            progress "5/6" "Resuming the exact completed empty runtime at recovery-console setup."
            "$NCT_RECOVERY_PYTHON" "$NCT_PACKAGE_ROOT/scripts/nct-fresh-bootstrap-state.py" verify-runtime-ready \
                --receipt "$NCT_FRESH_RECEIPT" --admin-user "${NCT_ADMIN_USER:-admin}" \
                --release "$NCT_PACKAGE_ROOT/release.json" --manifest "$NCT_PACKAGE_ROOT/PACKAGE-MANIFEST.sha256" \
                --archive "$NCT_PACKAGE_ROOT/offline-images/nct-range-images.tar" || die "The completed fresh runtime changed; preserve it for review."
        else
            progress "5/6" "Resuming only the verified empty installation at Administrator password setup."
            NCT_SKIP_IMAGE_LOAD=1 NCT_RESUME_BOOTSTRAP=1 sh "$NCT_PACKAGE_ROOT/scripts/nct-start-docker.sh" "$NCT_RANGE_IP" "${NCT_ADMIN_USER:-admin}"
        fi
    elif docker inspect "$NCT_TARGET_CONTAINER" >/dev/null 2>&1; then
        [ "$NCT_SETUP_MODE" != fresh ] || die "An NCT container appeared during fresh setup; no upgrade was attempted."
        progress "5/6" "Preserving the current release and data through the brief checked restart needed to add the independent recovery path."
    else
        progress "5/6" "Creating the new HTTPS application and Administrator account."
        NCT_SKIP_IMAGE_LOAD=1 sh "$NCT_PACKAGE_ROOT/scripts/nct-start-docker.sh" "$NCT_RANGE_IP" "${NCT_ADMIN_USER:-admin}"
    fi
fi
NCT_EXPECTED_COMMIT=$("$NCT_RECOVERY_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' "$NCT_PACKAGE_ROOT/release.json")
NCT_ACTUAL_COMMIT=$(docker exec "$NCT_TARGET_CONTAINER" python -c 'from app.build_info import BUILD_COMMIT; print(BUILD_COMMIT)')
if [ "$NCT_EXISTING_SOURCE" = 0 ] || [ "$NCT_SETUP_MODE" = fresh ] || [ "$NCT_SETUP_MODE" = resume-fresh ]; then
    [ "$NCT_ACTUAL_COMMIT" = "$NCT_EXPECTED_COMMIT" ] || die "The running application is not this exact release; recovery setup did not run."
fi
NCT_CONSOLE_ID=$(docker image inspect --format '{{.Id}}' "$NCT_CONSOLE_IMAGE")
set --
if [ "$NCT_SETUP_MODE" = fresh ] || [ "$NCT_SETUP_MODE" = resume-fresh ]; then
    set -- --fresh-expected-admin "${NCT_ADMIN_USER:-admin}" \
        --fresh-release-file "$NCT_PACKAGE_ROOT/release.json" \
        --fresh-bootstrap-receipt "$NCT_PERSIST_ROOT/deployment/bootstrap/fresh-resume.json" \
        --fresh-package-manifest "$NCT_PACKAGE_ROOT/PACKAGE-MANIFEST.sha256"
fi
"$NCT_RECOVERY_PYTHON" "$NCT_PACKAGE_ROOT/scripts/install_nct_recovery.py" --container "$NCT_TARGET_CONTAINER" --console-container "${NCT_RECOVERY_CONTAINER:-$NCT_TARGET_CONTAINER-recovery-console}" \
    --console-image "$NCT_CONSOLE_ID" --application-url "https://$NCT_RANGE_IP:$NCT_APP_PORT" \
    --console-url "https://$NCT_RANGE_IP:$NCT_CONSOLE_PORT" --bind-address "$NCT_RECOVERY_BIND_ADDRESS" \
    --data-dir "$NCT_PERSIST_ROOT/data" --state-dir "$NCT_RECOVERY_STATE_DIR" \
    --install-dir "${NCT_RECOVERY_INSTALL_DIR:-/opt/nct-recovery}" \
    --cert-file "$NCT_CERT" --key-file "$NCT_KEY" --ca-file "$NCT_CA" --enable-container "$@"
progress "6/6" "NCT and its independent recovery service are installed."
if [ "$NCT_SETUP_MODE" = fresh ] || [ "$NCT_SETUP_MODE" = resume-fresh ]; then
    printf '%s\n' "Open https://$NCT_RANGE_IP:$NCT_APP_PORT and sign in once with the new Administrator account to finish."
elif [ "$NCT_EXISTING_SOURCE" = 1 ]; then
    printf '%s\n' "The current application was not replaced. Open https://$NCT_RANGE_IP:$NCT_APP_PORT/settings/updates, launch the recovery workspace, upload the enclosed nct-update tar.gz, and complete the guarded update there."
else
    printf '%s\n' "Open https://$NCT_RANGE_IP:$NCT_APP_PORT/settings/updates and verify an existing account to finish."
fi
printf '%s\n' "The recovery management port is $NCT_CONSOLE_PORT. Apply your existing approved source-address firewall policy to that port; this installer does not open a broad firewall rule."
