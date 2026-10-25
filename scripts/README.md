# NCT Range Operator Scripts

This directory contains both the current small operator scripts and older
deployment automation retained for compatibility.

## Choose one operator workflow

The authoritative instructions are in
`../docs/AIR_GAPPED_RANGE_QUICKSTART.md`. Follow that guide from the beginning.
This file is a short reference for the scripts and must not replace the required
preflight and acceptance steps.

| Need | First command | Meaning |
| --- | --- | --- |
| Understand an existing unhealthy installation | `sh scripts/nct-diagnostic-report.sh` | Read-only diagnosis; always start here. |
| Recover the exact installed build after it stopped or began restarting | `sh scripts/nct-recover-installed.sh --container nct` | Preview exact-container restart recovery with a verified cold backup and stopped-data work check. |
| Repair retained unfinished work | `sh scripts/nct-reset-unfinished.sh --container nct` | Preserve completed data and prepare exact interrupted work for separate review. |
| Start an explicitly approved blank installation | `sh scripts/nct-fresh-install.sh --container nct` | Preview an empty replacement while retaining the old installation. |

Do not use a start script, upgrade, or blank installation as a recovery shortcut.

## Diagnose before changing anything

When NCT is unhealthy, stopped, or repeatedly restarting, collect a read-only
report before choosing a recovery action:

```bash
sh scripts/nct-diagnostic-report.sh
```

The default container is `nct`. To inspect another exact saved container or put
the report in another private absolute directory:

```bash
sh scripts/nct-diagnostic-report.sh --container CONTAINER_NAME --output-dir /PRIVATE/REPORT/DIRECTORY
```

The command reads saved container settings, bounded log signal counts, storage
capacity, and database/work counts through the container's exact local image. It
works while the container is running, stopped, or restarting. It does not stop,
restart, reset, repair, migrate, or upload anything. The report, JSON companion,
and checksum are owner-only and are stored in a fresh private child directory
under `/var/lib/nct/deployment/diagnostics` by default. An existing report-root
directory keeps its current permissions.

The summary uses **OK**, **Needs attention**, and **Not checked — reason**. Preserve
the report and follow the exact command in its state-specific next step. Do not delete a container,
database, WAL file, lock, or evidence during diagnosis. The report excludes
passwords, tokens, environment values, raw log text, raw device configurations,
raw evidence, and raw database rows. It can still contain container names, host
paths, IP addresses, timestamps, and log signal counts, so review it before
sharing. Every Docker query has a deadline. If Docker or the target container
cannot be identified safely, the command prints a partial result and next step
to the terminal without creating a report directory whose separation from NCT
data has not yet been proved.

## Recover the exact installed build

When the diagnostic names a stopped, restarting, or unhealthy installation, preview:

```bash
sh scripts/nct-recover-installed.sh --container nct
```

The preview records the exact saved runtime, creates and verifies a cold backup, and
inspects every unfinished-work category while the data is stopped. It changes no work
record. If the plan is clear, use the displayed `--apply` command. The same container
and local image are started, health and exact build are checked, and one restart cycle
is verified. Ports, bind folder or named volume, accounts, TLS, evidence, settings and
the full restart policy are retained. If work is stranded, the command stops and names
the separate unfinished-work repair. If any identity or work check is unavailable, it
stops instead of bypassing the check. Controller acceptance still requires a normal
sign-in and retained history/evidence review.
The apply step also resumes normal NCT workers. Existing enabled schedules,
connectors, and other saved automation may contact their configured networks when
due, so review or pause them first when that is not intended. The receipt records
that possibility.

## Start or administer an already reviewed installation

1. Confirm Docker is available:

   ```bash
   docker version --format 'Server {{.Server.Version}} / API {{.Server.APIVersion}}'
   docker compose version
   ```

2. Confirm the default NCT HTTPS port is free:

   ```bash
   ss -ltn | grep ':8445 '
   ```

   No output means the default port is not currently listening. If 8445 is in
   use, choose an approved free port and prefix the selected start command with
   `NCT_HTTPS_PORT=APPROVED_PORT`.

3. Choose one start script using both the Docker server API and Compose result:

   | What you see | Start script |
   | --- | --- |
   | API 1.41 or newer, and Compose works | `nct-start-compose.sh` |
   | API 1.41 or newer, but Compose fails | `nct-start-docker.sh` |
   | API 1.39 or 1.40 | `nct-start-legacy.sh` |
   | API older than 1.39, or Docker fails | Stop and contact the Range administrator |

4. Manage the Administrator with:

   ```bash
   sh scripts/nct-set-admin.sh
   ```

   To propose a specific username:

   ```bash
   sh scripts/nct-set-admin.sh admin
   ```

   The script shows current Administrator accounts, accepts a username, and
   prompts for the password without placing it on the command line.

## Compatibility scripts

`nct-range-direct-deploy.sh` is an older all-in-one deployment path. It is
retained so previous deployment bundles remain understandable, but it is not
the preferred recurring reset workflow. It requires an explicit Administrator
username:

```bash
sh scripts/nct-range-direct-deploy.sh RANGE_IP APPROVED_ANALYST_CIDR ADMIN_USERNAME [HTTPS_PORT]
```

`nct-set-admin-password.sh` is retained as a narrow password-reset helper. It
also requires an explicit username; it no longer assumes a personal default:

```bash
sh scripts/nct-set-admin-password.sh ADMIN_USERNAME [CONTAINER_NAME]
```

For normal Administrator creation, replacement, rename, or password changes,
prefer `nct-set-admin.sh`.

After a host-folder upgrade fails acceptance, use the exact upgrade receipt
with `nct-rollback-upgrade.sh`. The helper preserves the failed candidate,
restores the verified cold backup, compares the complete restored inventory,
verifies the exact earlier container, image, data-folder mount, and recorded web
port, and starts the earlier container only after the checks pass. Follow the
rollback section in the main quickstart rather than improvising recovery steps.

Before an upgrade changes saved data, `nct-upgrade.sh` stops NCT, uses the
retained original image to complete SQLite's normal stopped-database WAL
checkpoint, and then runs `nct-schema-preflight.py` through the replacement
image with the data mounted read-only. The audit records database integrity,
fingerprints, migration history, originating build identity, known version-4
maintenance tables, and the database SHA-256. Only exact reviewed version-4 and
version-5 Range sources are accepted. Unknown, incomplete, or altered schema stops
the upgrade and restores the earlier container.

## Explicit fresh installation

After diagnosis, use `nct-reset-unfinished.sh` when completed evidence and settings
must be preserved. Use `nct-fresh-install.sh` only for a deliberate blank replacement.
Preview first:

```bash
sh scripts/nct-fresh-install.sh --container nct
```

The preview produces a verified cold backup and exact private plan, then intentionally
holds NCT stopped so the reviewed source cannot change. Review it, then apply the
displayed plan with a new Administrator:

```bash
sh scripts/nct-fresh-install.sh --apply --plan ABSOLUTE_PLAN_PATH --admin-user NEW_ADMIN
```

To abandon the replacement and resume the old installation, run
`sh scripts/nct-fresh-install.sh --cancel --plan ABSOLUTE_PLAN_PATH`.

The helper requires a plan-specific confirmation, retains the old stopped container,
old data and image for rollback, uses a new empty bind folder or named volume, preserves
the reviewed TLS/web presentation, and verifies the blank instance and first sign-in.
It does not inherit old connectors, credentials, schedules or automatic collection.
Every temporary container has a unique bounded name and must be proven absent before
NCT can resume. TLS sign-in uses the exact certificate recorded by Preview. A failed
Apply reports restoration only after rechecking the exact old container, data, restart
policy and running state. Otherwise it attempts to stop both installations and says
they are stopped only after Docker verifies it. If Docker cannot provide that proof,
disconnect NCT network access and inspect Docker manually.
Follow the complete fresh-install section in the authoritative quickstart.

## Candidate Kubernetes storage check

`qualify_kubernetes_storage.py` performs a bounded, disposable check of one mounted
directory before it is considered for a future single-replica Kubernetes deployment.
Run it from a disposable Linux container or pod with the candidate volume mounted at an
otherwise unused path:

```bash
python scripts/qualify_kubernetes_storage.py \
  --root /candidate-data \
  --storage-identity "driver=EXACT_DRIVER;class=EXACT_CLASS;volume=EXACT_VOLUME"
```

The declared identity should describe the exact driver, storage class and volume being
tested without including credentials. The tool creates one private temporary directory,
tests separate-process locks, repeatedly replaces a preexisting file while synchronized
and continuous observer processes check every result and confirm that it never disappears
or becomes partial during replacement, syncs the files and directory,
and checks SQLite WAL behavior including writer contention, checkpoint truncation, reopen,
and integrity. The complete run has a strict time limit. Workers stay bound to the opened
directory rather than looking it up again by path. Successful cleanup removes the private
directory. A timeout or other controller failure marks cleanup unavailable and may name a
remaining private workspace for manual inspection. The tool does not open `analyzer.db`,
inspect retained evidence, or recursively inspect the mounted root.

Exit status `0` and `"overall": "pass"` mean only that the exact mounted environment
passed this bounded check. The report digest detects later alteration when compared with
a separately trusted copy; it is not a signature. A pass does not approve a storage
class or establish Kubernetes, Range, or mission readiness. Save the JSON outside the
candidate data root and retain it with the deployment evidence for later review.

## Kubernetes single-replica renderer

`render_kubernetes_single_replica.py` creates three bounded JSON packages for the
analysis-only profile: the claim, a qualification Job bound to the immutable claim and
volume UIDs, and the one-replica NCT Deployment after a matching passing report is
supplied. It requires an immutable image digest, never calls `kubectl`, never accepts a
Secret value, caps its inputs and output, and refuses mismatched or failed storage
evidence. Follow the complete operator sequence and limitations in
[`docs/KUBERNETES_SINGLE_REPLICA.md`](../docs/KUBERNETES_SINGLE_REPLICA.md).
