# NCT Range Operator Scripts

This directory contains both the current small operator scripts and older
deployment automation retained for compatibility.

## Choose one operator workflow

The authoritative instructions are in
`../AIR-GAPPED-RANGE-QUICKSTART.md`. Follow that guide from the beginning. This
file is a short reference for the scripts and must not replace the required
preflight and acceptance steps.

| Need | First command |
| --- | --- |
| Diagnose an existing installation without changing it | `sh scripts/nct-diagnostic-report.sh` |
| Recover the exact stopped or restarting installed build | `sh scripts/nct-recover-installed.sh --container nct` |
| Repair retained unfinished work | `sh scripts/nct-reset-unfinished.sh --container nct` |
| Preview an explicitly approved blank installation | `sh scripts/nct-fresh-install.sh --container nct` |

The diagnostic prints the matching next command. Do not use upgrade, a start script,
or a blank installation as a shortcut around an unknown or unreadable work check.

## Package contents

Run a script only when the main quickstart or the diagnostic names it. Python files
in this folder are internal helpers called by the shell workflow; do not run them as
standalone repair commands.

| Class | Files | Purpose |
| --- | --- | --- |
| Normal operator entry points | `nct-diagnostic-report.sh`, `nct-recover-installed.sh`, `nct-reset-unfinished.sh`, `nct-fresh-install.sh`, `nct-set-admin.sh` | Diagnose, recover, repair retained work, perform an approved blank replacement, or manage the Administrator. |
| Main quickstart only | `nct-upgrade.sh`, `nct-rollback-upgrade.sh`, `nct-recover-unhealthy-upgrade.sh`, `nct-migrate-data.sh`, `nct-start-compose.sh`, `nct-start-docker.sh`, `nct-start-legacy.sh` | Upgrade, roll back, migrate older storage, or start through the exact path selected by the guide. |
| Internal Python helpers | `nct-diagnostic-report.py`, `nct-reset-unfinished.py`, `nct-fresh-install.py`, `nct-schema-preflight.py`, `nct-range-data-check.py` | Read and verify saved state for the matching shell workflow. These are not independent operator commands. |
| Compatibility or administrator tools | `install-nct.sh`, `nct-deploy.sh`, `nct-range-direct-deploy.sh`, `nct-admin-recover.sh`, `nct-set-admin-password.sh`, `setup-lab-https.sh`, `nct-range-matrix.sh` | Preserve older deployment and lab procedures. Use only when the authoritative guide or an administrator explicitly names the exact command. |

## Exact installed-build recovery

After the diagnostic names a stopped, restarting, or unhealthy saved container, run:

```bash
sh scripts/nct-recover-installed.sh --container nct
```

Preview records the exact container, image, listener, data mount and full restart
policy, creates and independently verifies a cold backup, and inspects every work
category from stopped data. It supports bind storage and named volumes. Apply is
offered only when the work plan is clear; it starts and restart-tests the same saved
container and exact local image. Unfinished work routes to the separate repair command.
Unknown storage, work, schema, image, port or helper state stops the process. Normal
sign-in and retained history/evidence review remain required for controller acceptance.
Applying recovery resumes normal NCT workers. Existing enabled scan schedules,
Arkime pulls, and other saved automation may contact their configured networks when
due. Review or pause them first when that is not intended. The receipt records possible
network contact instead of describing normal startup as passive.

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
maintenance tables, and the database SHA-256. This Phase 5 package accepts only
the exact reviewed schema-version-6 `phase4-r5` Range source. Version-5 data must
first use `NCT-Air-Gapped-Range-Deployment-0.16.0-20261019-phase4-r5.zip` with its
matching adjacent checksum. That bridge is not included here. Stop, preserve the
current installation, obtain the exact bridge, and follow its guide through acceptance
before returning to this package. Unknown, incomplete, altered, or other schema versions
stop the upgrade and the helper restores the earlier container.

Rollback restores the matching pre-upgrade data backup before starting the earlier
image. Restarting the earlier image against schema-version-7 data is not a rollback.

If the retained earlier container itself cannot restart, begin with the
read-only diagnostic and `nct-recover-installed.sh`. Use
`nct-recover-unhealthy-upgrade.sh` only when that exact-installed recovery and
step 6A of the main guide identify the reviewed historical package-specific
migration case. It performs the same read-only schema gate without requiring
the old application to run, independently verifies a cold backup, retains both
failure sources, and does not restart an incompatible old image after
replacement-written data.

## Evidence-preserving unfinished-work repair

Use the Active Scans **Unfinished work self-check** when the page is available. If NCT
cannot open, use the terminal diagnostic and its printed repair command. Both read saved scan,
schedule, Arkime pull, device-contact, local-processing, storage-maintenance and
ownership records without changing them. If it reports unfinished work, run this
preview from the extracted package:

```bash
sh scripts/nct-reset-unfinished.sh --container nct
```

The host helper refuses a shared data mount, stops the exact container, records
its non-secret runtime identity, creates a complete cold backup outside retained
data, independently extracts and verifies every file, and recalculates the exact
recovery plan. Preview mode restores the previous running state and changes no
work record. After an administrator reviews the printed plan, apply it with:

```bash
sh scripts/nct-reset-unfinished.sh --container nct --apply
```

Apply requires the displayed plan confirmation. Completed scans, collections,
evidence, accounts, and settings remain unchanged. Waiting work retains its order.
Possible network contact is never replayed. Original local-processing attempts
remain in history and one replacement is queued when safe. NCT restarts with Nmap,
Arkime, device contact, local processing, and storage maintenance paused separately.
Review the affected rows in Active Scans, then resume only the named category that
is ready: **Resume preserved scans**, **Resume passive pulls**, **Resume device
contact**, **Resume local processing**, or **Resume storage maintenance**. Device
contact remains blocked until uncertain attempts are closed.
Storage maintenance performs a fresh retained-evidence verification before its
hold can clear. Normal scope, No-Strike, and pre-contact checks still apply.

Keep the backup, plan and receipts. The helper stops instead of guessing when it
finds an unfamiliar schema or state, an unfinished migration, unresolved
compaction, database damage, another container sharing the data, a failed backup
verification, or a plan that changed after review. NCT restarts only after Docker
successfully proves the temporary recovery helper is absent. If that inventory
cannot complete, NCT remains stopped with automatic restart disabled and reports
the manual review boundary.

## Explicit fresh installation

Use this only for an approved blank replacement, separately from unfinished-work
recovery. Create and review the exact plan first:

```bash
sh scripts/nct-fresh-install.sh --container nct
```

The successful preview holds NCT stopped so its exact reviewed data cannot change.

Then apply only that displayed plan and create a new Administrator:

```bash
sh scripts/nct-fresh-install.sh --apply --plan ABSOLUTE_PLAN_PATH --admin-user NEW_ADMIN
```

Run `sh scripts/nct-fresh-install.sh --cancel --plan ABSOLUTE_PLAN_PATH` to abandon the
replacement and resume the old installation.

The old stopped container, data and image remain available for rollback. The helper
uses a different empty bind folder or named volume, preserves the reviewed TLS and web
presentation, omits prior connector credentials and automatic collection settings,
and verifies health, empty operator data and the first Administrator sign-in.

Every temporary helper is named, time-bounded and proven absent before service can
resume. Apply repeats the container and shared-data checks immediately before the
replacement. HTTPS sign-in uses the exact certificate pinned by Preview. A failed
Apply is reported as restored only after the old identity, data mount, restart policy
and state all match. If restoration fails, the helper attempts to stop both
installations and reports that state only after Docker verifies it. When Docker cannot
provide that proof, disconnect NCT network access and inspect Docker manually.
