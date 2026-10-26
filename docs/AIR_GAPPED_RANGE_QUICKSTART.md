# NCT air-gapped Range installation and upgrade

This guide is written for an operator with little or no Docker experience.
Follow the steps in order and copy the commands exactly. Text written in
CAPITAL LETTERS is a value that you must replace, such as the Range server's IP
address.

## What this package does

NCT runs inside a Docker container. Think of the container as the program and
`/var/lib/nct/data` as its permanent filing cabinet. Replacing or upgrading the
container does not remove the filing cabinet.

The included scripts do the Docker work for you. They:

- verify the offline NCT image before using it;
- preserve accounts, settings, scans, and evidence in `/var/lib/nct/data`;
- keep the previous container as a rollback copy during an upgrade.

Do not manually delete the current `nct` container or the `nct-data` volume.

## Diagnose an unhealthy installation before recovery

If NCT is stopped, unhealthy, or repeatedly restarting, do not begin by deleting
or recreating it. From the extracted package directory, run:

```sh
cd "$NCT_WORKDIR"
sh scripts/nct-diagnostic-report.sh
```

The command works with running, stopped, and restarting containers and does not
stop, restart, reset, repair, migrate, or upload anything. It stores an owner-only
text report, JSON companion, and checksum in a fresh private child directory under
`/var/lib/nct/deployment/diagnostics`. The screen prints the exact paths, size,
SHA-256, completeness, and safe next step. An existing parent directory keeps its
current permissions.

If the saved container has another name, identify that exact name first and run:

```sh
sh scripts/nct-diagnostic-report.sh --container EXACT_CONTAINER_NAME
```

If the default name is missing and several NCT-looking containers exist, the
command lists candidates and stops instead of guessing. If Docker or the target
container cannot be identified safely, the partial result and next step appear in
the terminal and no report directory is created. After NCT's data location has
been verified, a partial result includes the text report, JSON companion and
checksum and records why the exact image, storage, or database could not be checked.
Keep NCT data, locks, WAL files, evidence, and database rows unchanged while an
administrator reviews it. The report excludes credentials, environment secret
values, raw logs, raw device configurations, raw evidence, and raw database rows.
Only bounded log signal counts are retained; review paths, IP addresses and
timestamps before sharing. Docker queries and helper runs have fixed deadlines so
an unavailable runtime cannot leave the diagnostic hanging indefinitely.

## Choose the recovery path printed by the diagnostic

Do not substitute one path for another:

| What the diagnostic says | Next action |
| --- | --- |
| Running and healthy | Continue normal investigation. Do not reset or reinstall from this result. |
| Stopped, restarting, or running but unhealthy; stopped work check is readable and clear | Run `sh scripts/nct-recover-installed.sh --container nct` to preview recovery of the exact installed container. |
| Unfinished scan, schedule, Arkime, device-contact, local-processing, or storage work | Run `sh scripts/nct-reset-unfinished.sh --container nct` to preview evidence-preserving repair. |
| Database, work state, image, mount, port, or container identity cannot be proved | Stop. Preserve the report and data. Do not bypass the check or start a blank installation. |
| An administrator explicitly approved an empty replacement after reviewing what will not carry forward | Use the separate fresh-install preview only. |

### Recover the exact stopped installation

For a stopped, restarting, or unhealthy installation whose saved work can be read
safely, run:

```sh
sh scripts/nct-recover-installed.sh --container nct
```

Preview runs the diagnostic first, records the exact container, image, port, mount,
and full restart policy, creates and independently verifies a cold backup before any
write, and inspects all unfinished-work categories from stopped data. It supports a
bind folder or named volume and stops if another container can reach overlapping data,
if one listener cannot be identified, or if saved work is unknown or unreadable.

If unfinished work exists, the command does not restart NCT. It prints the exact
unfinished-work repair command. If the plan is clear, apply the same recovery path:

```sh
sh scripts/nct-recover-installed.sh --container nct --apply
```

Apply starts the same saved container from the same local image with the same port,
data, accounts, settings, TLS material, evidence, and complete restart policy. It
checks health and exact build identity, performs one restart cycle, and creates a
private receipt plus a second diagnostic. It never creates a blank installation.
If health or the restart test fails, NCT is held stopped with automatic restart
disabled and the verified backup is preserved. Before controller acceptance, sign in
normally and confirm retained history and evidence; the receipt deliberately records
that controller sign-in remains unverified. Applying recovery resumes normal NCT
workers. Existing enabled scan schedules, Arkime pulls, and other saved automation
may contact their configured networks when due. Review or pause them before `--apply`
when that is not intended. The receipt records this as possible network contact.
that this final human sign-in check is still required.

## Repair unfinished work after diagnosis

If the diagnostic or Active Scans **Unfinished work self-check** reports stranded
scan, schedule, Arkime, device-contact, local-processing, or storage work, remain
in the extracted package directory and run the read-only preview first:

```sh
sh scripts/nct-reset-unfinished.sh --container nct
```

The helper stops the exact NCT container, verifies that no other container shares
its data, creates a complete cold backup under
`/var/lib/nct/deployment/backups`, independently extracts and verifies every file,
and recalculates the exact saved-work plan. It then restores the earlier running
state. Preview mode does not change a scan, schedule, pull, collection, processing
attempt, account, setting, or evidence record.

Review the displayed backup path, plan and item reasons. To apply that reviewed
plan, run:

```sh
sh scripts/nct-reset-unfinished.sh --container nct --apply
```

Type the requested plan-digest characters exactly. Completed work stays intact;
waiting work keeps its order; possible network contact is never replayed; affected
scheduled occurrences remain available for review; and one replacement local
processing attempt is queued when safe. NCT restarts with Nmap, Arkime, device
contact, local processing, and storage maintenance paused separately. In Active
Scans, review **Unfinished work self-check** and resume only the named category
that is ready. Device contact cannot resume until uncertain attempts are closed.
Storage maintenance runs a fresh retained-evidence verification before it resumes.
Normal scope, Mission Environment, No-Strike and pre-contact checks still apply.
Preserve the backup, plan and receipts if the helper refuses recovery. NCT restarts only after Docker
successfully proves that the temporary recovery helper is gone. If that proof
fails, NCT remains stopped with automatic restart disabled and the terminal
prints the exact manual review boundary.

## Start a genuinely fresh NCT installation

Use this only when an administrator has decided to start NCT with no inherited
accounts, evidence, scopes, Saved Networks, profiles, schedules, notes, settings,
or unfinished work. This is separate from **repair unfinished work**, which preserves
all completed application data.

Create the non-destructive preview plan first:

```sh
sh scripts/nct-fresh-install.sh --container nct
```

The preview stops the exact container, disables automatic restart, proves no other
container shares its data, creates a complete cold backup in a separate directory,
extracts it, and compares file bytes, paths, types, permissions, ownership, symbolic
links, and hard-link relationships. A successful preview intentionally holds NCT stopped
so those exact reviewed bytes cannot change before Apply. The screen and private plan
name the old container, pinned image, old data, proposed empty
data location, retained TLS files, web bind address and port, Docker network, backup,
and everything that will not carry into the fresh installation. Previous connector
credentials and automatic collection settings are deliberately omitted for later
review.

If the administrator decides not to continue, cancel the preview and restore the old
restart policy and running state:

```sh
sh scripts/nct-fresh-install.sh --cancel \
  --plan /var/lib/nct/deployment/fresh-installs/EXACT_RUN/fresh-install-plan.json
```

After reviewing the plan, apply that exact file:

```sh
sh scripts/nct-fresh-install.sh --apply \
  --plan /var/lib/nct/deployment/fresh-installs/EXACT_RUN/fresh-install-plan.json \
  --admin-user NEW_ADMIN
```

Type the plan-specific `FRESH-...` confirmation and enter the new Administrator
password twice. There is no general `--yes` bypass. NCT rechecks the container, image,
data mount, backup checksum and complete stopped-data inventory before switching. The
old container is renamed, stopped, and retained with its old data and exact image. The
new container uses a different empty bind folder or named volume, reuses the reviewed
TLS and network presentation, initializes one new Administrator, removes bootstrap
access, and proves health, empty operator data, and the first Administrator sign-in.
It cannot begin automatic collection because old schedules, Mission Environment
decisions, connector credentials and collection settings are not copied.

If initialization or acceptance fails, the helper attempts to restore and verify the
exact old container name, data mount, restart policy and earlier running state. It
retains the failed candidate data for review. If any restoration check cannot be
proved, the helper attempts to disable restart and stop both installations. It says
they are stopped only after Docker verifies that state. If Docker itself cannot provide
that proof, the command tells the operator to disconnect NCT network access and inspect
Docker manually. Every temporary helper is named, time-bounded and proven absent before NCT
can resume. HTTPS acceptance pins the reviewed certificate and never sends the new
Administrator password with certificate verification disabled. For an intentional
later rollback, stop the fresh container and use the exact
retained container, old data source, pinned image and receipt printed by this command;
never attach the old data to a different image or delete either data source until the
fresh installation has been accepted and the backup has been transferred according to
local retention policy.

## Before you begin

You need:

- the file `NCT-Air-Gapped-Range-Deployment-0.16.0-20261025-phase5-r1.zip` uploaded to
  the Range server;
- the matching adjacent file
  `NCT-Air-Gapped-Range-Deployment-0.16.0-20261025-phase5-r1.zip.sha256` uploaded to
  the same folder;
- access to a terminal on the Range server with root or `sudo` privileges;
- the Range server's IP address; and
- an approved analyst network address for the firewall rule, if a new rule is
  required.

In the examples below, the ZIP is in `/root`. If your browser placed it in a
different folder, use that folder in the first command.

## 1. Open the package

Open the Range server's terminal and run these commands one line at a time:

```sh
cd /root
package_zip=/root/NCT-Air-Gapped-Range-Deployment-0.16.0-20261025-phase5-r1.zip
checksum_file="$package_zip.sha256"
[ -f "$checksum_file" ] || {
    echo "HALT: the matching package checksum file is missing: $checksum_file" >&2
    exit 1
}
actual_package_sha256=$(sha256sum "$package_zip" | awk '{print $1}')
export NCT_PACKAGE_SHA256="$actual_package_sha256"
echo "Package SHA-256: $actual_package_sha256"
(cd /root && sha256sum -c "$(basename "$checksum_file")") || exit 1
if [ -e /root/NCT-Air-Gapped-Range-Deployment ]; then
    staging_dir="/root/nct-package-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -m 0700 "$staging_dir"
    unzip "$package_zip" -d "$staging_dir"
    export NCT_WORKDIR="$staging_dir/NCT-Air-Gapped-Range-Deployment"
else
    unzip "$package_zip" -d /root
    export NCT_WORKDIR=/root/NCT-Air-Gapped-Range-Deployment
fi
cd "$NCT_WORKDIR"
sha256sum -c PACKAGE-MANIFEST.sha256 || exit 1
```

What success looks like: the companion checksum comparison prints `OK`. A missing
or mismatched companion checksum file stops installation before extraction. Do not
extract or run a package whose checksum cannot be verified. After extraction, the
final command verifies every delivered file and must print `OK` for each one before
returning to the prompt. Run the following command to confirm the package contents
are visible:

If an internal package or image checksum reports a missing or mismatched file,
stop, preserve the package and the displayed output, and obtain a corrected
release. Never edit or regenerate checksum files on the Range.

```sh
ls
```

You should see `compose.range.yaml`, `offline-images`, and `scripts`.

If an earlier package folder already exists, these commands leave it unchanged
and extract the new release into a separate root-only staging folder. Keep this
terminal open for the remaining steps because `NCT_WORKDIR` tells every helper
which clean package to use. If you must open a new terminal, set `NCT_WORKDIR`
again to the full path printed by `pwd` before running a helper.

## 2. Find which start method this server supports

Run:

```sh
docker version --format 'Server {{.Server.Version}} / API {{.Server.APIVersion}}'
docker compose version
```

The first command should print a Docker server version and API number. The
second command may either print a Compose version or an error. Use this simple
table to choose a start method later:

| What you see | Start method |
| --- | --- |
| API **1.41 or newer**, and the Compose command works | `compose` |
| API **1.41 or newer**, but the Compose command fails | `docker` |
| API **1.39 or 1.40** | `legacy` |
| API older than **1.39**, or the first command fails | Stop and contact the Range administrator |

The older recurring Range VM has previously reported API 1.39, so `legacy` is
the expected choice there. You do not need to install Compose.

## 3. Decide whether this is a new installation or an upgrade

Run:

```sh
docker inspect nct --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
```

Choose only one of these paths:

- If the output includes `/var/lib/nct/data -> /data`, this is an **upgrade**.
  Go to step 6.
- If Docker says that no container named `nct` exists, this is a **new
  installation**. Go to step 4.
- If the output includes `nct-data` or a Docker volume path pointing to
  `/data`, this is an **older installation that must be migrated**. Continue
  with step 3A below.
- If the output is different or unclear, stop. Do not remove anything; ask the
  Range administrator to review it.

### 3A. Move an older Docker volume into the permanent host folder

First confirm that the old volume exists:

```sh
docker volume inspect nct-data
```

Then run:

```sh
sh "$NCT_WORKDIR/scripts/nct-migrate-data.sh"
```

The migration will refuse to start if NCT is busy. It stops and retains the old
container, copies the data, and compares every copied file. It does not delete
the old `nct-data` volume.

What success looks like: the script prints a successful migration receipt and
a rollback-container name. Write down both names. After a successful
migration, continue to the port check in step 4, then use the **new
installation** start in step 5. Existing accounts and data will still be
preserved.

## 4. Confirm that the web port is available

NCT uses HTTPS port 8445 by default. Before starting NCT, run:

```sh
ss -ltn | grep ':8445 ' || echo PORT_8445_FREE
```

`PORT_8445_FREE` means the port is available. If the command shows another
program already using 8445, stop and ask the Range administrator to select an
approved unused port. In step 5, put `NCT_HTTPS_PORT=APPROVED_PORT` before the
selected start command, replacing `APPROVED_PORT` with that port number.

## 5. Start a new or newly migrated installation

Skip this step when upgrading an installation that already uses
`/var/lib/nct/data`.

Replace `RANGE_IP` with the server's real IP address. Use the one command that
matches the method selected in step 2:

For `legacy`:

```sh
sh "$NCT_WORKDIR/scripts/nct-start-legacy.sh" RANGE_IP
```

For `docker`:

```sh
sh "$NCT_WORKDIR/scripts/nct-start-docker.sh" RANGE_IP
```

For `compose`:

```sh
sh "$NCT_WORKDIR/scripts/nct-start-compose.sh" RANGE_IP
```

If step 4 selected a different approved port, prefix the selected command. For
example:

```sh
NCT_HTTPS_PORT=APPROVED_PORT sh "$NCT_WORKDIR/scripts/nct-start-legacy.sh" RANGE_IP
```

On a completely new installation, the script asks you to enter an
Administrator username and password. The password is hidden while you type.
On a migrated installation, the existing accounts are kept and no password is
reset.

What success looks like: the script reports that NCT is healthy and returns to
the prompt without an error. Continue with step 7.

## 6. Upgrade an existing host-folder installation

Use this step only when step 3 showed `/var/lib/nct/data -> /data`.
If the installed NCT container is stopped, unhealthy, or repeatedly restarting,
do not use upgrade as a startup repair. Run the read-only diagnostic and the
exact-installed recovery path first. That path preserves the current image,
ports, data, accounts, evidence, settings, and restart policy. Upgrade is only
for changing to the reviewed image after the installed copy is stable, or after
the exact recovery path explicitly identifies the historical package-specific
compatibility case described in step 6A.

Replace `RANGE_IP` with the server's real IP address:

```sh
sh "$NCT_WORKDIR/scripts/nct-upgrade.sh" RANGE_IP
```

The helper automatically chooses Compose when it is available. If step 2 told
you to use `legacy`, add that word to the end:

```sh
sh "$NCT_WORKDIR/scripts/nct-upgrade.sh" RANGE_IP legacy
```

For current Docker without Compose, add `docker` instead.

The upgrade will refuse to start if a scan or collection is running. It checks
the packaged image and stops the current NCT writer. The retained original image
first completes SQLite's normal stopped-database checkpoint so the audit cannot
miss recently committed records. The replacement image then audits the saved
database through a read-only mount without changing it. The audit verifies database
integrity, the complete saved migration history, and the exact recorded structure
and build identity. This Phase 5 package accepts only the exact schema-version-6
Range source `0.16.0-range-test-20261019-phase4-r5` at commit
`b908834cb60327a640e9987fddff036c4df9fb75`. A version-5 installation must first
use the exact Phase 4 bridge package; do not point this package directly at it.
Any other version, build, incomplete history, or altered structure stops the upgrade
and restores the original container. After the audit passes, the helper backs up the permanent
data, retains the old container, preserves the installation's current web port,
starts NCT 0.16.0, and confirms that stored file and record counts did not go
down.

What success looks like: the script prints a successful upgrade receipt, a
read-only schema-audit receipt, a backup location, and a rollback-container
name. Write down all four and keep them until testing is complete.

If the helper reports an unsupported saved database and confirms that the original
container was restored, leave that restored NCT and `/var/lib/nct/data` unchanged.
Do not edit the database, manifests, or checksums, and do not replace only one script.
Obtain the corrected full ZIP and matching adjacent checksum, repeat step 1 into a
new staging folder, confirm the new release identity and checksums, and then repeat
step 6. If the original container was not confirmed restored, stop and involve the
administrator instead of retrying.

### 6A. Historical package-specific migration after exact recovery stops

Use this path only when the exact-installed recovery has already preserved the
container and verified backup, has identified the reviewed historical
saved-schema fingerprint case, and the ordinary upgrade did not create a new
schema-audit record. It is not the first response to a stopped, unhealthy, or
restarting container. Do not delete or rename the old container or
`/var/lib/nct/data`.

Keep the same terminal used in step 1 so `NCT_WORKDIR` and
`NCT_PACKAGE_SHA256` are still set. For the older Range Docker engine, run:

```sh
sh "$NCT_WORKDIR/scripts/nct-recover-unhealthy-upgrade.sh" RANGE_IP legacy
```

Replace `RANGE_IP` with the server's real address. This helper rechecks every
package file and the image archive before loading anything. It stops the failed
restart loop, confirms no other running container has the data folder mounted,
checkpoints the stopped database, checks for unresolved work, and audits the
saved schema through a read-only mount. It then creates a cold backup, extracts
that backup separately, and compares the complete extracted inventory before it
can retain the old container and start the replacement.

If replacement validation fails after the new application may have written,
the helper preserves the failed container and data, restores and verifies the
cold backup, and leaves the incompatible old image stopped. It never starts the
old image against replacement-written data.

Rollback must restore the matching pre-upgrade data backup before the older image
is started. The older image cannot safely open data after the schema-version-7
transition.

What success looks like: the helper verifies retained files, registered
artifacts, database record counts, accounts, image identity, mount, port, build,
health, and one restart. It prints a recovery receipt, backup, read-only schema
audit, and stopped source-container name. Keep all four until Range acceptance
is complete.

## 7. Allow approved analysts through the Range firewall

Skip this step if the existing Range firewall rule already allows the approved
analyst network to reach HTTPS port 8445.

Replace `APPROVED_ANALYST_CIDR` and `RANGE_IP` with the approved values:

```sh
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=APPROVED_ANALYST_CIDR destination address=RANGE_IP port port=8445 protocol=tcp accept'
firewall-cmd --reload
```

If the new-installation port check selected a different approved port, or the
upgrade reported that it preserved a different port, replace 8445 in the
firewall rule.

## 8. Open and sign in to NCT

In a browser, open:

```text
https://RANGE_IP:8445
```

Replace `RANGE_IP` with the server's address. The Range uses its own HTTPS
certificate, so the browser may display the Range's expected certificate
warning. Follow the site's approved procedure for reaching the login page.
For an upgrade, use the exact address and port printed by the successful
upgrade. For a new installation, if step 4 used a different approved web port,
replace 8445 with that same port.

For a new installation, sign in with the Administrator account created in
step 5. For an upgrade, use an existing Administrator account. The username is
not necessarily `admin`.

## 9. Verify the installation before accepting it

Run these checks in the Range terminal:

```sh
docker ps --filter name=nct
docker logs nct
docker inspect nct --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
curl --connect-timeout 2 --max-time 5 -k https://RANGE_IP:8445/health
```

Replace `RANGE_IP` in the last command. For an upgrade, use the port printed by
the successful upgrade. For a new installation, if step 4 used a different
approved web port, replace 8445 with that same port. Confirm all of the
following:

- the `nct` container is running;
- the health response shows version `0.16.0`;
- the build ID is `0.16.0-range-test-20261025-phase5-r1`;
- the `/data` mount points to `/var/lib/nct/data`; and
- the logs do not show repeated startup errors.

Both the ZIP name and build ID end in `phase5-r1`. Open
`$NCT_WORKDIR/RELEASE-RECEIPT.txt` and confirm that it lists this same package
revision, image name, build ID, and source commit before continuing.

This `phase5-r1` package includes the automatic Arkime connector. Follow
[`ARKIME_CONNECTOR_RANGE_SETUP.md`](ARKIME_CONNECTOR_RANGE_SETUP.md); do not copy
individual connector files from another release. That procedure creates a separate
read-only Arkime account, installs the trusted CA and password as root-only files,
and applies the verified Compose override. Do not place the Arkime password in a
guide, Compose file or shell command line.

Then verify the saved information in the browser:

1. Open **Nmap Scans** and confirm the existing scan history is present.
2. Open **Network Devices** and expand an existing collection.
3. Download `manifest.json` and `stdout.txt`, and confirm both files save.
4. If the Range administrator has provided an approved live-collection test
   procedure, follow that procedure exactly. It must identify the approved
   device, approved credentials, capture interface, authorization, and any
   required No-Strike exclusion. Confirm the read-only Cisco collection
   completes, displays non-blank output, and allows its saved configuration to
   download. If those approved details are not available, do not guess and do
   not contact a device. Record live collection as **not yet validated**. You
   may upload and inspect an approved retained configuration to verify the
   non-contact analysis path, but that does not prove live collection works.

### Verify container CPU and memory on this Range host

1. Open **Settings → System Health**, then find **Live performance and
   reliability**.
2. CPU may initially say **Warming up**. Leave the panel visible through at
   least the second five-second sample.
3. Confirm that the **NCT process** and **Container** rows stay aligned under
   the CPU and Memory headings.
4. In the Container CPU row, confirm **Current**, **Average**, and **Maximum**
   contain percentages and that a visible Basis explains whether the percentage
   uses one CPU or a container CPU allowance.
5. In the Container Memory row, confirm **Current**, **Average**, and
   **Maximum** contain plausible memory amounts and the panel shows no raw
   error text. **Time near max** may correctly be `0 sec`; that is not a
   failure.

**Unavailable** is an honest unknown value and never means zero. However,
Unavailable container CPU or memory does not pass this release's Range
acceptance check. Record what the panel shows, stop acceptance, and have the
Range administrator review the Docker/Linux resource-counter access. Do not
change container permissions or mount host files as a workaround.

### Verify this release's Network Scope handoff correction

First verify the affected saved scan without contacting the network:

1. In **Nmap Scans**, open **Scan History** and find the completed scan that
   shows **Saved scope handoff needs correction**.
2. Confirm that the row names the Network Scope already saved with that scan.
   Sign in as an Administrator, choose **Repair saved scope handoff**, enter a
   clear reason, and confirm the action.
3. Confirm that NCT reports **Scoped evidence ready · corrected handoff** after
   local processing completes. The original failed handoff must remain in the
   saved history. No new item should appear in Active Scans, because this repair
   reads the retained file and does not run Nmap or contact the network.
4. Open **Hunt → Network Evidence**. Confirm that the corrected scan is no
   longer labeled as needing Network Scope context and that its retained
   candidate-processing result is visible. A scan with no offline candidate
   matches may correctly show zero candidates; that alone is not a failure.

Stop the acceptance check if the saved scope shown for the scan is wrong, the
retained file fails verification, the repair reports an error, or any network
scan starts. Preserve the evidence and do not try to work around the error.

The forward handoff can only be tested with a newly authorized scan. Do not run
this check unless the Range administrator has explicitly approved the Saved
Network, Network Scope, scan profile, timing, and any required No-Strike
exclusions. When those details are approved:

1. Run that exact saved scan and wait for it to complete.
2. In **Scan History**, confirm that the completed row reaches **Scoped evidence
   ready** without showing **Saved scope handoff needs correction** or **Network
   Scope required**.
3. Open **Hunt → Network Evidence** and confirm that candidate processing for
   the new retained scan completed. Zero matching candidates is a valid result
   when the observed products and versions have no match in the offline data.

If the administrator has not approved this network-contact test, do not scan.
Record the new-scan forward handoff as **not yet validated** and continue with
the non-contact checks above.

Do not accept the upgrade until all checks pass. Keep `/var/lib/nct` in the
normal Range or Proxmox backup scope. The live data folder must stay on the
VM's local disk, not NFS, SMB, OneDrive, or another synchronized folder.

## 10. Roll back if the new release fails testing

Only use this section after a failed acceptance check. First determine whether
step 3A migrated an old Docker volume or step 6 upgraded an existing host-folder
installation. The two rollback paths are different.

### Roll back after step 3A migrated an old Docker volume

The old container still points to the unchanged original Docker volume. Use the
exact rollback-container name printed during migration in place of
`ROLLBACK_CONTAINER_NAME`. Run these commands one at a time and stop if any
command reports an error:

```sh
rollback_time=$(date -u +%Y%m%dT%H%M%SZ)
docker stop nct
docker rename nct "nct-failed-$rollback_time"
docker rename ROLLBACK_CONTAINER_NAME nct
docker start nct
```

This returns the earlier container to its unchanged original Docker volume.
The failed host-folder copy and failed container remain preserved for
investigation.

### Roll back after step 6 upgraded a host-folder installation

Do not start the earlier application against data opened by NCT 0.16.0. Use the
exact upgrade receipt path printed by step 6 in place of `UPGRADE_RECEIPT`, then
run:

```sh
sh "$NCT_WORKDIR/scripts/nct-rollback-upgrade.sh" RANGE_IP UPGRADE_RECEIPT
```

The helper refuses active or unresolved work, preserves the failed container
and post-upgrade data, verifies the cold-backup checksum, restores it, compares
the complete restored file and database inventory with the pre-upgrade
inventory, verifies the exact retained container, image, and data-folder mount,
and starts the earlier container only after those checks pass. It reads the
original web port from the upgrade receipt, including when an approved port
other than 8445 was used.
If any check fails, it leaves the older application stopped and tells the
administrator which recovery sources to preserve. A successful restore returns
the application and data to the moment of the pre-upgrade backup, so information
entered later will not appear. Keep the failed container and post-upgrade data
for investigation.

## Administrator password help

To list Administrator accounts and interactively set an account and password:

```sh
sh "$NCT_WORKDIR/scripts/nct-set-admin.sh"
```

For emergency recovery, make sure a verified backup exists, then run:

```sh
sh "$NCT_WORKDIR/scripts/nct-admin-recover.sh" --admin-user ADMIN_USERNAME
```

Replace `ADMIN_USERNAME` with the actual account name. The recovery helper
backs up the data, resets only the selected Administrator, revokes that
account's earlier sessions, and returns NCT to its prior running state.

## Add offline SearchSploit data later

Upload the unextracted official Exploit-DB archive from **Settings -> System
Health -> Offline Exploit-DB references**. Hunt also provides a **Manage offline
exploit references** shortcut beside **Refresh network view**. NCT validates and
stages the archive before activation, keeps earlier versions for rollback, and
does not require Internet access for this import.
