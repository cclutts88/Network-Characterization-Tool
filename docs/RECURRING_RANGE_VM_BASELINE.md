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
