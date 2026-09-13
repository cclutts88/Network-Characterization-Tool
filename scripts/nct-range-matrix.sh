#!/bin/sh
set -eu

# Repeatable, non-destructive Range compatibility matrix for the current NCT
# source tree. An optional image runs the real host/image preflight as Test;
# it never deploys, scans, changes a firewall, or contacts a network device.

image=""
output=""
state_dir=""

usage() {
    cat <<'EOF'
Usage: sh scripts/nct-range-matrix.sh [options]

  --image IMAGE     Also run the real non-mutating host/image preflight
  --output FILE     Write the matrix report to FILE
  --state-dir DIR   Preflight logs/state directory (default ./nct-deployment)
  -h, --help        Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --image) image=${2:?missing image}; shift 2 ;;
        --output) output=${2:?missing output file}; shift 2 ;;
        --state-dir) state_dir=${2:?missing state directory}; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; printf '%s\n' "[NCT] ERROR: Unknown option: $1" >&2; exit 1 ;;
    esac
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
state_dir=${state_dir:-"$repo_dir/nct-deployment"}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
output=${output:-"$state_dir/range-matrix-$stamp.txt"}
output_dir=$(dirname -- "$output")
mkdir -p "$output_dir"
tmp_report="${output}.tmp.$$"
tmp_test="${TMPDIR:-/tmp}/nct-range-matrix-tests.$$"
tmp_preflight="${TMPDIR:-/tmp}/nct-range-matrix-preflight.$$"
cleanup() { rm -f "$tmp_report" "$tmp_test" "$tmp_preflight"; }
trap cleanup EXIT HUP INT TERM

command -v python >/dev/null 2>&1 || {
    printf '%s\n' "[NCT] ERROR: python is required to run the compatibility matrix." >&2
    exit 1
}

shell_result="pass"
if ! sh -n "$script_dir/nct-deploy.sh"; then shell_result="fail"; fi

test_result="pass"
if ! (cd "$repo_dir" && python -m pytest -q -p no:cacheprovider tests/test_deploy_launcher.py tests/test_guided_installer.py) > "$tmp_test" 2>&1; then
    test_result="fail"
fi

preflight_result="not-run"
if [ -n "$image" ]; then
    if sh "$script_dir/nct-deploy.sh" --profile test --access local --image "$image" \
        --state-dir "$state_dir" --check-only > "$tmp_preflight" 2>&1; then
        preflight_result="pass"
    else
        preflight_result="fail"
    fi
fi

overall="pass"
[ "$shell_result" = "pass" ] && [ "$test_result" = "pass" ] || overall="fail"
[ "$preflight_result" != "fail" ] || overall="fail"

{
    printf 'NCT Range compatibility matrix\n'
    printf 'completed=%s\noverall=%s\nimage=%s\n' "$(date -u +%FT%TZ)" "$overall" "${image:-not-supplied}"
    printf '\n%-34s %-12s %s\n' "Scenario" "Result" "Evidence"
    printf '%-34s %-12s %s\n' "Launcher shell syntax" "$shell_result" "sh -n"
    printf '%-34s %-12s %s\n' "Automated deployment matrix" "$test_result" "deployment and guided-installer pytest"
    printf '%-34s %-12s %s\n' "Compose v2" "$test_result" "simulated supported tier"
    printf '%-34s %-12s %s\n' "Legacy Compose v1" "$test_result" "simulated degraded tier"
    printf '%-34s %-12s %s\n' "Direct Docker Engine" "$test_result" "simulated degraded tier"
    printf '%-34s %-12s %s\n' "Minimum Docker API" "$test_result" "supported and rejected boundaries"
    printf '%-34s %-12s %s\n' "Recurring Range VM API 1.39" "$test_result" "opt-in thread/seccomp workaround fixture"
    printf '%-34s %-12s %s\n' "Linux and CPU architecture" "$test_result" "supported/rejected daemon fixtures"
    printf '%-34s %-12s %s\n' "Offline image checksum" "$test_result" "valid, missing, and mismatch paths"
    printf '%-34s %-12s %s\n' "Occupied host port" "$test_result" "alternate-port selection"
    printf '%-34s %-12s %s\n' "Range firewall preflight" "$test_result" "active/present/missing/inactive fixtures"
    printf '%-34s %-12s %s\n' "Guided installer prompts" "$test_result" "Test/Range plans and TLS generation"
    printf '%-34s %-12s %s\n' "Existing NCT and active work" "$test_result" "preserve idle; reject active"
    printf '%-34s %-12s %s\n' "Promotion receipt identity" "$test_result" "exact match and mismatch"
    printf '%-34s %-12s %s\n' "Real host/image preflight" "$preflight_result" "optional --image check-only"
    printf '%-34s %-12s %s\n' "Bridge/VPN subnet overlap" "$test_result" "Test warns; Range/Mission stop"
    printf '%-34s %-12s %s\n' "Post-deploy packet/scan runtime" "deploy-gate" "NET_RAW, tcpdump -D, raw socket, health"
    printf '\nAutomated test output:\n'
    cat "$tmp_test"
    if [ -s "$tmp_preflight" ]; then
        printf '\nReal preflight output:\n'
        cat "$tmp_preflight"
    fi
} > "$tmp_report"

mv "$tmp_report" "$output"
printf '%s\n' "[NCT] Range matrix: $overall"
printf '%s\n' "[NCT] Report: $output"
[ "$overall" = "pass" ]
