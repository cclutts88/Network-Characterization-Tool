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

## Before you begin

You need:

- the file `NCT-Air-Gapped-Range-Deployment-0.16.0-20261013-phase2-r2.zip` uploaded to
  the Range server;
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
unzip NCT-Air-Gapped-Range-Deployment-0.16.0-20261013-phase2-r2.zip
cd /root/NCT-Air-Gapped-Range-Deployment
```

What success looks like: the last command returns to the prompt without an
error. Run the following command to confirm the package contents are visible:

```sh
ls
```

You should see `compose.range.yaml`, `offline-images`, and `scripts`.

If the package must remain somewhere other than
`/root/NCT-Air-Gapped-Range-Deployment`, stop here and ask the Range
administrator to set `NCT_WORKDIR` to its full location.

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
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-migrate-data.sh
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
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-start-legacy.sh RANGE_IP
```

For `docker`:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-start-docker.sh RANGE_IP
```

For `compose`:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-start-compose.sh RANGE_IP
```

If step 4 selected a different approved port, prefix the selected command. For
example:

```sh
NCT_HTTPS_PORT=APPROVED_PORT sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-start-legacy.sh RANGE_IP
```

On a completely new installation, the script asks you to enter an
Administrator username and password. The password is hidden while you type.
On a migrated installation, the existing accounts are kept and no password is
reset.

What success looks like: the script reports that NCT is healthy and returns to
the prompt without an error. Continue with step 7.

## 6. Upgrade an existing host-folder installation

Use this step only when step 3 showed `/var/lib/nct/data -> /data`.

Replace `RANGE_IP` with the server's real IP address:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-upgrade.sh RANGE_IP
```

The helper automatically chooses Compose when it is available. If step 2 told
you to use `legacy`, add that word to the end:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-upgrade.sh RANGE_IP legacy
```

For current Docker without Compose, add `docker` instead.

The upgrade will refuse to start if a scan or collection is running. It checks
the packaged image, backs up the permanent data, retains the old container,
preserves the installation's current web port, starts NCT 0.16.0, and confirms
that stored file and record counts did not go down.

What success looks like: the script prints a successful upgrade receipt, a
backup location, and a rollback-container name. Write down all three and keep
them until testing is complete.

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
- the build ID is `0.16.0-range-test-20261013-phase2-r2`;
- the `/data` mount points to `/var/lib/nct/data`; and
- the logs do not show repeated startup errors.

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
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-rollback-upgrade.sh RANGE_IP UPGRADE_RECEIPT
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
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-set-admin.sh
```

For emergency recovery, make sure a verified backup exists, then run:

```sh
sh /root/NCT-Air-Gapped-Range-Deployment/scripts/nct-admin-recover.sh --admin-user ADMIN_USERNAME
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
