# NCT rapid deployment launcher

The launcher is intended for controlled Linux Docker hosts. It validates the
runtime, image, ports, access boundary, firewall posture, TLS material,
persistent volume, active work, backup, health, and rollback path before it
reports NCT as available.

Range images must use an explicit version tag or digest and declare their NCT
build identity. The launcher records the local content-addressed image ID and
any registry digest in its deployment log, then verifies that the running
application reports the same build. Re-running the launcher against the exact
same healthy direct-HTTP image, bind address, port, and data volume is a safe
no-op rather than an unnecessary replacement.

This checkpoint supports **Test** and **Range** deployment. The **Mission**
profile is present but intentionally stops before making changes until NCT's
authenticated access and formal mission-promotion gate are implemented. A
successful Test or Range launch must not be reported as mission readiness.

Run a non-mutating preflight first:

```sh
sh scripts/nct-deploy.sh --profile test --access local \
  --image network-characterization-tool:0.14.0-dev-42d8636 --check-only
```

Deploy a local test build:

```sh
sh scripts/nct-deploy.sh --profile test --access local --port 8766 \
  --image network-characterization-tool:0.14.0-dev-42d8636
```

For a range host, choose its exact LAN address and approved source range. The
launcher never binds to every interface and does not alter the firewall unless
`--configure-firewall` is explicitly supplied from an elevated shell:

```sh
sudo sh scripts/nct-deploy.sh --profile range --access lan \
  --bind 10.20.30.40 --port 8766 --source-cidr 10.20.30.0/24 \
  --configure-firewall --image nct:range-validated
```

Air-gapped packages should include an immutable image archive and SHA-256:

```sh
sh scripts/nct-deploy.sh --profile range --access local --offline \
  --image nct:range-validated --image-archive offline-images/nct.tar \
  --image-sha256 EXPECTED_SHA256
```

The future Mission mode additionally requires a LAN address, certificate, key,
trusted CA file, stable ports, authentication, successful active-work
detection, backup, application health, and a trusted HTTPS request. A failed
Test or Range container is removed and the previous named application and HTTPS
proxy containers are restored automatically. Any narrow firewall rule created
by the launcher is removed during rollback. The old containers remain stopped
under timestamped rollback names after success until an operator removes them
under the site's retention procedure.

The deployment log records decisions and results but never credentials or NCT
evidence. A success banner and access URL are printed only after the final
health check passes. Final readiness also proves that Nmap, FPING, tcpdump, and
SSH are installed inside the application container, packet-capture interfaces
can be enumerated, `NET_RAW` is present, and a raw ICMP socket can be created.
