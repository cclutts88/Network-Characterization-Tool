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

The selected application and HTTPS ports are stored in
`nct-deployment/current.env` after successful validation. Unless an operator
supplies a new port explicitly, later runs reuse that stable selection and also
reuse a safely recognized existing NCT binding. Port preflight checks both
other Docker containers and host listeners through `ss` or `netstat`; Test and
Range may advance to an available port, while Mission must stop rather than
silently changing its declared URL.

This checkpoint supports **Test** and **Range** deployment. The **Mission**
profile is present but intentionally stops before making changes until NCT's
formal mission-promotion gate is implemented. A
successful Test or Range launch must not be reported as mission readiness.

Authentication is optional for a local **Test** deployment and defaults to
enabled for **Range**. Range cannot be launched with authentication disabled.
On the first authenticated deployment, the launcher inspects the persistent
account store. If it is empty, it creates the operator-selected first
Administrator; NCT has no fixed default username or password. Existing accounts
are preserved on upgrade and bootstrap is not repeated.

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

Enable authentication for that Test build and securely generate its first
Administrator password:

```sh
sh scripts/nct-deploy.sh --profile test --access local --port 8766 \
  --auth local --admin-user nctadmin --generate-admin-password \
  --image network-characterization-tool:VERSION
```

The launcher prints the generated password-file path only after it verifies the
new Administrator. Sign in, store the password using the approved site process,
then delete that file. For unattended deployment, use
`--admin-password-file FILE` instead; the file is mounted read-only and its
contents never appear in container metadata or the deployment log. Interactive
deployment prompts twice without echoing the password. In every path, the
bootstrap mount is removed and NCT is restarted without it before success is
reported.

For a range host, choose its exact LAN address and approved source range. The
launcher never binds to every interface and does not alter the firewall unless
`--configure-firewall` is explicitly supplied from an elevated shell:

```sh
sudo sh scripts/nct-deploy.sh --profile range --access lan \
  --bind 10.20.30.40 --port 8766 --source-cidr 10.20.30.0/24 \
  --configure-firewall --auth local --admin-user nctadmin \
  --generate-admin-password --image nct:range-validated
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

## Administrator recovery

If every Administrator is locked out, an authorized host operator can recover
one existing Administrator without enabling an application-level back door:

```sh
sudo sh scripts/nct-admin-recover.sh --container nct \
  --admin-user nctadmin --generate-password
```

Recovery refuses to proceed while NCT has active work, verifies that the target
is an Administrator, stops the existing container when necessary, creates a
timestamped data backup, resets the password through a read-only secret-file
mount, revokes all prior sessions for that account, and returns the original
container to its previous running state. It cannot create a new account or
promote an Analyst. The generated recovery password remains in the protected
state directory only long enough for the operator to store it and confirm
sign-in; delete it afterward. A supplied `--password-file` is never deleted by
the script.
