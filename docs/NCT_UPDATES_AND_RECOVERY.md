# NCT Updates and Recovery

This feature uses an independent, temporary recovery page. The NCT application
cannot control Docker. A trusted helper installed on the host performs a fixed
set of update and recovery operations. The console normally remains stopped.

## Normal operator workflow

1. Sign in to NCT and open **Account and settings → Updates & Recovery**.
2. Select **Open update and recovery workspace**. NCT starts the independent
   console, proves its HTTPS endpoint is ready, and sends a two-minute, one-use
   handoff. The handoff is removed from browser history immediately on arrival.
3. Choose the single `nct-update-….tar.gz` file. The image checksum is inside it;
   no second upload is needed. Existing terminal-installer ZIP files remain
   terminal packages and are deliberately rejected by the GUI.
4. Select **Upload and validate package**. NCT continues running. Validation checks
   the bounded two-file package, image checksum and immutable image identity,
   exact tested source build, saved-data compatibility on a disposable database
   copy, and available space. The image is loaded without changing installed tags.
   A checksum verifies bytes, so obtain the package from your trusted release source.
5. Review the build and choose **Apply validated update**. Finish or resolve scans,
   scheduled work, device pulls and other unfinished work first. Apply stops NCT,
   disables automatic restart, checks the writer lock and saved work, checks data
   compatibility again, and creates a cold backup. A separate extraction must match
   the saved inventory before the replacement can write to the evidence folder.
6. The console shows saved progress during the NCT outage. Closing the browser
   does not cancel the operation. Reopen the console through NCT or the host launcher.
7. After exact build, readiness and evidence checks pass, enter an existing NCT
   username and password. The helper tests sign-in against the actual replacement.
   The password is used only for that request and is never saved in receipts.
   New collection, local processing and storage maintenance stay paused until
   this verification completes. The temporary update pause never clears a
   separate unfinished-work recovery gate.
8. Successful verification records the result, returns the browser to NCT and
   stops the console. The original container and cold backup remain available.
   Before recording completion the helper performs a journaled final restart of
   the same verified image, releases only its own temporary pause and proves
   readiness again. This activates the ordinary background services skipped while
   verification was paused. Other recovery gates remain intact. If the helper
   restarts during this step, it reconciles the exact runtime without discarding
   work already completed after release. A failed final restart requires a proved
   stop before a new temporary pause is recorded.

The console inherits the active NCT theme during the handoff. Its tables expand
with the page; only horizontal overflow stays inside the table. Its Operator
Guide uses normal body text.

## If something fails

**Restore saved backup** verifies the original container and image identity,
stops the replacement, verifies and independently restores the cold backup, and
then starts the previous image against that restored data. It never opens the
replacement's changed database with an older image. The table shows the backup
time before restoring.
Fresh account verification is required against the restored version too. A
successful check from the replacement never substitutes for that restored check.

Evidence collected after the backup is preserved in a sibling folder named
`nct-preserved-…`; the exact location appears in the result. It is not merged
automatically into the restored installation. Keep that folder and the stopped
preserved container for investigation or a deliberate evidence import. The original
backup path and receipts also appear in the result. Recovery does not delete them.

After a host-service interruption, the saved operation changes to **Needs recovery
review**. Choose Restore to reconcile the actual saved container identities and
verified backup. An unverified backup, changed target, additional writer, missing
original image, or failed data check leaves the previous image stopped. Preserve
the result and use the existing terminal diagnostic/recovery procedures.

**Investigate NCT** reads the exact configured container, state, image, capacity
and current recovery result. **Verify saved backup** extracts a fresh copy and
checks its inventory. Start, stop and restart address only that configured NCT
container. Diagnostic export contains a summary rather than passwords, raw
container environment, raw evidence or raw logs. Review paths and identifiers
before sharing it.

**Check unfinished work for repair** stops NCT, makes a verified cold backup and
previews the installed release's existing recovery plan on a disposable copy.
Review the work categories, changes and valid waiting scans that will be preserved.
NCT stays stopped until you choose Apply reviewed work repair or Resume NCT without
repair. Apply binds the exact plan and backup, preserves completed evidence and valid
waiting work, then keeps collection paused for review. Verify an existing account
before returning to NCT, where the existing recovery gates control later resumption.
Resuming without repair can restart the original queues and automation; its
confirmation says so explicitly. A changed plan or failed repair leaves NCT stopped
with its backup available. These controls never silently empty the scan queue.

When NCT cannot provide a signed-in handoff, use the exact emergency command
printed during installation. It pins the selected Python interpreter and actual
paths. For a separate Python 3.9 and the default installation paths, for example:

```sh
sudo /usr/bin/python3.9 /opt/nct-recovery/nct_update_host.py \
  --config /opt/nct-recovery/config.json --access-code
```

Open the printed recovery URL and enter the one-use code within two minutes.
An unhealthy or restarting NCT can start the console automatically, but it still
requires this independent access code. Application failure never bypasses sign-in.

## One-time host installation

Terminal application upgrades preserve the exact installed container settings by
default, including its security options, mounts, environment, startup command and
complete restart policy. Only the image and release identity change. The standalone
runtime helper supports host Python 3.6 or newer and does not install the recovery
service. It verifies a freshly extracted cold backup before starting the replacement.
New upgrade receipts retain the original restart policy, including retry counts;
verified rollback restores it after checking the restored data. Older receipts use
the retained container's current policy and warn that a missing policy is not guessed.
Unsupported network layouts or mismatched Docker connections stop the upgrade before
NCT is stopped. Fresh-install launchers retain their normal defaults. Recovery-console
installation remains a separate Python 3.9-or-newer prerequisite.

The first release containing this feature needs the normal full-package deployment
so its application image includes the new workspace. Then install the host helper
from that reviewed source release. Do not install host code from a GUI upload.
The full package's `nct-install-range.sh` launcher already performs this host setup;
do not run the manual example again after successful bootstrap. The example below
is only for an administrator completing a separately reviewed manual installation.
The host needs Python 3.9 or newer, a Docker CLI supporting `--pull=never`, systemd,
and working local POSIX file locks. Helpers use only locally retained images.
The system's default Python may stay at an older version. Bootstrap searches for
versioned Python 3.13 through 3.9, then `python3`, and validates the required host
modules. To select a separately installed runtime explicitly, set an absolute path,
for example `export NCT_RECOVERY_PYTHON=/usr/bin/python3.9`. An invalid explicit
choice stops setup rather than falling back. The resolved executable is pinned in
the host service and emergency access instructions. Keep it installed at that path;
interpreters under home directories are refused because the protected service cannot
access them. Missing Python must be supplied from approved offline vendor media;
the NCT package does not replace system Python or download an operating-system update.
Use a dedicated, locally attached evidence bind mount with proven SQLite WAL,
atomic rename and filesystem synchronization behavior. Named volumes and shared
application workloads require a separately qualified deployment adapter.

An example with installation-specific addresses and paths:

```sh
sudo python3 scripts/install_nct_recovery.py \
  --container nct \
  --console-image 'sha256:THE_REVIEWED_LOCAL_CONSOLE_IMAGE_ID' \
  --application-url https://NCT_HOST:8445 \
  --console-url https://NCT_HOST:8446 \
  --bind-address NCT_HOST_IP \
  --cert-file /var/lib/nct/tls-material/tls/nct-server.crt \
  --key-file /var/lib/nct/tls-material/tls/nct-server.key \
  --ca-file /var/lib/nct/tls-material/certs/nct-lab-root.crt \
  --enable-container
```

The certificate must be valid for both URLs. The helper verifies it using the
provided certificate authority; it does not ignore TLS errors. The installer
recreates the exact current application image once to add only its launch socket,
preserves the prior container stopped, and creates the separate console stopped.
Initial enablement also creates a verified cold backup and leaves collection
paused until an existing account is verified through the console. The console
must prove that both its GUI and host connection are ready before this restart.
It starts for this initial verification and stops after the verified return to NCT.
The console receives only its control socket, private upload spool and HTTPS
certificate/key. It receives neither Docker control nor the evidence mount.

The initial live unfinished-work check uses a fixed trusted script and SQL
`mode=ro`. Its helper's evidence mount permits SQLite's WAL/SHM housekeeping because
an otherwise read-only query may need to create or open those sidecars; it does
not write evidence records or run schema initialization. All stopped immutable
checks mount evidence read-only. Repair previews instead query a verified
disposable copy. These distinctions avoid treating a read-only mount failure as
proof that no unfinished work exists.

The installed host code is under `/opt/nct-recovery`; its private configuration
is `config.json`. Durable console state is separate from evidence, under
`/var/lib/nct/deployment/recovery-console` by default. The host service is
`nct-recovery-host.service`. Its two private Unix sockets separate application
launch access from authenticated management operations. The application receives
only the launch socket. The console image is pinned independently from application
updates so it remains usable when a replacement fails.

All signed-in operators are allowed by the default self-contained policy. An
administrator can replace `allowed_operators: "all"` in the private host
configuration with an explicit username list and restart the helper. The revised
policy also applies to already-issued console sessions. Host-issued
recovery remains an administrator operation. Receipts retain the operator and exact
package/plan/container/image bindings. Never share the private host-state directory:
it also retains the original container configuration needed for recovery.

The GUI and updated terminal maintenance scripts share
`/var/lib/nct/deployment/maintenance.lock`. For a custom persistent root, set
`NCT_PERSIST_ROOT` consistently when using terminal scripts. Concurrent actions
are refused. Direct Docker commands outside those workflows remain an administrator
responsibility.

The console stops when the verified workflow returns to NCT, or after 15 minutes
without authenticated activity when no recovery is unresolved. Browser polling
keeps an actively viewed workspace available. The host helper may start it for a
failed or restarting NCT; independent authentication remains mandatory.

Private staging allows at most four uploaded packages and 24 GiB of compressed
uploads, with additional free-space checks for upload spooling, expanded image
layers, the Docker image store, cold backup and restoration. Failed uploads
also count. Backups and preserved evidence are never silently removed. An
administrator can archive completed package directories after preserving receipts
and required rollback material; do not remove the current operation or its backup.
Disposable verification copies are removed after a successful check; original
backups and preserved post-backup evidence are retained. The GUI works with the
most recent operation; older private receipts and backups remain available for
administrator-led recovery rather than being silently overwritten or deleted.

## Building an air-gapped update file

Build and test the release image first. Name every exact source build whose update
path was tested; a source-build declaration is not a substitute for testing.

```sh
python3 scripts/build_nct_update.py \
  --image THE_LOCAL_RELEASE_IMAGE \
  --source-build EXACT_SOURCE_BUILD_ID@EXACT_SOURCE_COMMIT \
  --output nct-update-RELEASE.tar.gz
```

Repeat `--source-build` for each tested source. The builder produces one gzip file
containing `release.json` and a tagless, single-image Docker archive. The manifest
binds the image checksum, immutable image ID, release build and tested source builds.
The GUI never executes uploaded shell scripts, Python scripts or Compose files.
The archive binds the image configuration digest and every expanded layer identity;
the saved operation separately binds the exact loaded runtime image ID. This
supports both classic Docker image IDs and the newer OCI image-store representation.

## Development acceptance boundary

### Interrupted first installation

Do not rerun the one-time installer over an existing recovery service. Keep its
configuration, operation history and console. First reconcile the interrupted
operation using the installed helper, then verify the existing NCT account in the
recovery workspace. Collection stays paused until that check completes.

For an administrator-reviewed interruption before the launch socket was connected,
`scripts/finish_nct_recovery.py` continues the existing installation. It requires
the exact application/console image identities, build ID and full commit, and the
reviewed console certificate/key file paths. It checks the installed service and
runtime again under the maintenance lock, preserves the previous reconciliation
receipt, creates a new operation and independently verifies a new cold backup.
It then uses the same replacement, evidence check, account check and rollback
transaction as first installation. It does not reinstall the host service, change
accounts or treat an incomplete operation as success. This is an administrator
recovery path, not an extra step in the normal operator update workflow.

Trusted, isolated deployments should prioritize a short operator workflow.
Reducing repeated access and sign-in prompts is planned; the current release's
checks still apply until a simpler flow is implemented and tested.

The dedicated console is built with `Dockerfile.recovery` and its pinned
`requirements-recovery.txt`. It contains only the recovery web interface and socket
transport, not the main application or network collection tools. The pinned official
Python Alpine base uses a different C runtime to avoid the observed thread-creation
failure under the older host's security filter. Do not assume compatibility from the
base name alone: qualify the exact immutable image under read-only root, dropped
capabilities and no-new-privileges on the target. Do not inherit an application's
unrestricted compatibility setting into this console. Local syscall-failure
reproduction and HTTPS acceptance do not substitute for target-engine acceptance.
The existing sealed release and its console tag are unchanged; a new console must
be packaged and transferred with its own exact identity and qualification results.

Automated Docker exercises cover real NCT intake, HTTP upload, replacement, fresh
account checks, backup restore, failed-release recovery and unfinished-work repair.
A separate fixture executes the real host installer, real HTTPS console and copied
host service as a separate process, including its restart and one-use recovery code.
Only the fixture's systemctl call is substituted. A real systemd boot, the exact
Range storage/network setup and retained-data acceptance on that deployment remain
separate gates. Disposable acceptance storage is a persistent named test volume;
the earlier interrupted volatile fixture is not counted as a passing exercise.

## Kubernetes adapter boundary

The first executable adapter is single-container Docker/Compose. The GUI explicitly
reports Kubernetes installation unavailable. The equivalent controller contract
must preserve the same `nct-update-v1` package, plan digest, operator, phases and
receipts. A controller operates on one configured namespace, Deployment and PVC;
it cannot enumerate the cluster or read Secrets. Its service account may read and
patch only that named Deployment and create/watch bounded maintenance Jobs in that
namespace. Job admission must enforce approved images, service account, mounts,
resources, deadlines and an operation label.

Before any maintenance Job mounts evidence for writing, the controller must suspend
dispatch, scale the named workload to zero, prove every previous pod terminated,
fence automatic replacement, acquire the shared recovery lock and prove storage
qualification and the application writer lock. ReadWriteOnce and a replica count
of one do not prove exclusivity. The backup, independent restore, exact build,
readiness, authenticated sign-in and evidence checks match Docker's contract.
Failure uses a verified pre-update restore before an older image can start.
Interrupted Jobs remain fenced until their exact receipts and actual pod state are
reconciled. This is the required design contract; it is not a claim that the
Kubernetes controller is implemented or accepted on a cluster.
