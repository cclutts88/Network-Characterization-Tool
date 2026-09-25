# Recurring Range VM compatibility baseline

This baseline captures the verified recovery path from an earlier deployment on
the Range VM family that is regularly reset. It intentionally omits the host
address, credentials, NCT evidence, scans, and collected device configuration.

## Observed environment and verified resolution

| Condition | Observed result | Verified handling |
|---|---|---|
| Docker daemon API 1.39 | A transferred Compose 5.5 client required API 1.40 and could not launch the stack | Bypass Compose and use the Docker Engine path |
| Existing host services | Standard HTTP/HTTPS and application ports were already occupied | Leave those services untouched; the successful deployment used alternate HTTP 8081 and HTTPS 8444 |
| Python 3.12 image on the old runtime | Native Uvicorn transport crashed, then a bare Python thread failed under the default container profile | Force Uvicorn `asyncio` + `h11`; use `seccomp=unconfined` only when a temporary thread probe fails normally and passes with that container-scoped option |
| Host firewall | The alternate analyst-facing port needed an inbound rule | Use an explicitly approved, source-restricted firewalld rule and leave unrelated rules unchanged |
| End-to-end access | Local HTML, analyst-workstation HTTPS, CA trust, and container restart were tested | Treat this as historical Range evidence, not Mission readiness |

The current launcher represents this as the
`workaround · legacy-range-direct-engine` tier. It is opt-in, Range-only, and
cannot be promoted to Mission:

```sh
sudo sh scripts/nct-deploy.sh --profile range --access lan \
  --bind RANGE_VM_ADDRESS --https-port 8444 \
  --source-cidr APPROVED_ANALYST_CIDR --configure-firewall \
  --allow-legacy-range-runtime --offline \
  --image nct:VERSION --image-archive offline-images/nct.tar \
  --image-sha256 EXPECTED_SHA256 \
  --promote-from-receipt nct-deployment/receipts/test-BUILD-TIMESTAMP.receipt
```

Before a container swap, the launcher checks the exact image and promotion
receipt, host ports, Docker networks, active NCT work, and the legacy Python
thread behavior. The security relaxation is never applied globally: it is
added only to the NCT analyzer container, and only if the paired probe proves
that it is necessary. If the thread still cannot start, deployment stops and
directs the operator to the separately versioned offline appliance path.

## Reset acceptance record

After each Range reset, retain a new report from:

```sh
sh scripts/nct-range-matrix.sh --image nct:VERSION
```

The historical success above validates the failure pattern and workaround. A
current report is still required to prove that the reset VM and current NCT
image have not changed incompatibly.

## Proven direct recovery path

On the recurring Docker 18.09/API 1.39 Range host, the proxy-based installer
health check was incompatible with the host's TLS verification behavior. The
working recovery was to run NCT directly with Uvicorn TLS. This preserves the
existing `nct-data` volume, binds only the Range address, and applies the
seccomp relaxation only to the NCT container.

From the extracted project directory, substitute the Range address and image
tag where needed:

```sh
docker run -d --name nct --restart unless-stopped \
  --cap-add NET_RAW --security-opt seccomp=unconfined \
  -p RANGE_VM_ADDRESS:8444:8444 \
  -v nct-data:/data \
  -v "$PWD/nct-deployment/tls-material-final/tls/nct-server.crt:/run/tls/nct-server.crt:ro" \
  -v "$PWD/nct-deployment/tls-material-final/tls/nct-server.key:/run/tls/nct-server.key:ro" \
  -e NCT_AUTH_MODE=local -e NCT_SESSION_HOURS=12 -e NCT_COOKIE_SECURE=1 \
  network-characterization-tool:VERSION \
  uvicorn app.main:app --host 0.0.0.0 --port 8444 --loop asyncio --http h11 \
  --ssl-certfile /run/tls/nct-server.crt --ssl-keyfile /run/tls/nct-server.key
```

Then add the source-restricted host firewall rule:

```sh
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=APPROVED_ANALYST_CIDR destination address=RANGE_VM_ADDRESS port port=8444 protocol=tcp accept'
firewall-cmd --reload
```

Confirm the local application response with
`curl -k https://RANGE_VM_ADDRESS:8444/health`. The `-k` flag is only a local
diagnostic on this legacy host. Analyst workstations must import the generated
`nct-lab-root.crt` into their trusted-root store and then use
`https://RANGE_VM_ADDRESS:8444` without bypassing certificate verification.

For the verified 2026-09-13 deployment, the concrete values were address
`10.101.35.15`, analyst CIDR `10.101.35.0/24`, port `8444`, and image
`network-characterization-tool:0.15.4-range-20260924`.

If the initial Administrator exists but no usable password was delivered, a
host operator can generate a replacement without reinstalling NCT or replacing
the data volume:

```sh
docker exec nct python -c 'import secrets; from pathlib import Path; from app.auth import reset_user_password; p=secrets.token_urlsafe(18); reset_user_password(Path("/data/analyzer.db"), username="ADMIN_USERNAME", password=p, actor="host-recovery"); print("NEW PASSWORD:", p)'
```

Store the displayed password using the approved process and do not retain it in
deployment notes or screenshots. This direct recovery was used because the
legacy Range console did not reliably pass characters through an interactive
hidden-password prompt.
