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

- the file `NCT-Air-Gapped-Range-Deployment-0.15.9-20260924.zip` uploaded to
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
unzip NCT-Air-Gapped-Range-Deployment-0.15.9-20260924.zip
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
migration, use the **new installation** start in step 5; existing accounts and
data will still be preserved.

## 4. Confirm that the web port is available

NCT uses HTTPS port 8445 by default. Before starting NCT, run:

```sh
ss -ltn | grep ':8445 ' || echo PORT_8445_FREE
```

`PORT_8445_FREE` means the port is available. If the command shows another
program already using 8445, stop and ask the Range administrator to select an
approved unused port and update the `HOST_PORT=8445` line in the selected start
script.

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
starts NCT 0.15.9, and confirms that stored file and record counts did not go
down.

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

If a different web port was approved, replace 8445 in the firewall rule.

## 8. Open and sign in to NCT

In a browser, open:

```text
https://RANGE_IP:8445
```

Replace `RANGE_IP` with the server's address. The Range uses its own HTTPS
certificate, so the browser may display the Range's expected certificate
warning. Follow the site's approved procedure for reaching the login page.

For a new installation, sign in with the Administrator account created in
step 5. For an upgrade, use an existing Administrator account. The username is
not necessarily `admin`.

## 9. Verify the installation before accepting it

Run these checks in the Range terminal:

```sh
docker ps --filter name=nct
docker logs nct
docker inspect nct --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
curl -k https://RANGE_IP:8445/health
```

Replace `RANGE_IP` in the last command. Confirm all of the following:

- the `nct` container is running;
- the health response shows version `0.15.9`;
- the build ID is `0.15.9-range-20260924`;
- the `/data` mount points to `/var/lib/nct/data`; and
- the logs do not show repeated startup errors.

Then verify the saved information in the browser:

1. Open **Nmap Scans** and confirm the existing scan history is present.
2. Open **Network Devices** and expand an existing collection.
3. Download `manifest.json` and `stdout.txt`, and confirm both files save.
4. Run the established read-only Cisco test collection. Confirm it completes,
   displays non-blank output, and allows its saved configuration to download.

Do not accept the upgrade until all checks pass. Keep `/var/lib/nct` in the
normal Range or Proxmox backup scope. The live data folder must stay on the
VM's local disk, not NFS, SMB, OneDrive, or another synchronized folder.

## 10. Roll back if the new release fails testing

Only use this procedure after a failed acceptance check. Use the exact
rollback-container name printed during migration or upgrade in place of
`ROLLBACK_CONTAINER_NAME`:

```sh
docker stop nct
docker rm nct
docker rename ROLLBACK_CONTAINER_NAME nct
docker start nct
```

This restores the earlier container. It does not erase the copied host-folder
data, old Docker volume, or upgrade backup. Record the failure and preserve
those items for investigation.

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

Upload the unextracted official Exploit-DB archive from **Hunt -> SearchSploit
enrichment -> Manage offline database**. NCT does not require Internet access
for this import.
