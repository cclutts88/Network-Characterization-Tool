# Start here — install NCT on a clean Range controller

This is a **fresh-install-only** release. Use steps 1–4 below on a Linux Docker
host where the NCT container, NCT storage and NCT recovery service/state are absent.
It does not upgrade an older NCT installation or carry older NCT accounts, settings
or evidence forward. It refuses an occupied target instead of deleting, adopting or
changing it.

You do not need to open or choose files from the `scripts` folder yourself. Use only
the commands shown in this guide. The same sealed package may be installed separately
on a second clean Range controller; each installation creates its own account,
storage, evidence and recovery state.

This is the standalone Docker route; it does not set up Kubernetes or claim a
separately tested Docker Compose deployment.

## 1. Put the package on the controller

Range releases larger than 48 MiB are supplied with smaller transfer pieces.
Create one new empty controller folder for that release, then upload **every file
from its `-Transfer-Parts` folder** into that same controller folder. There is no
need to choose among them: the pieces, joiner, readme and transfer identity record
all belong together, and they do not need separate folders. Run
`sh JOIN-NCT.sh` there and wait for all four numbered stages plus **PASS**. The
joiner verifies the exact generated identity record and readme, refuses missing,
corrupt, linked, extra or mixed-release pieces, then rebuilds the original verified
ZIP without installing NCT. Do not extract individual pieces or try to upload the
large ZIP again when the transfer tool rejects it.

Once the complete ZIP is on the controller, extract it into a new folder. Keep
the ZIP. Open a root
terminal inside its `NCT-Air-Gapped-Range-Deployment` folder. All image files,
checksums and setup scripts are included; installation downloads nothing.

The host must already have Docker running, systemd, Python **3.9 or newer**,
OpenSSL, curl, ss, flock, tar and standard shell tools. The package does not
install or replace the operating system or its Python. If necessary select an
existing compatible interpreter, for example:

```sh
export NCT_RECOVERY_PYTHON=/usr/bin/python3.9
```

Use its actual installed path. Omit that line when automatic discovery already
finds a supported interpreter. Do not put the interpreter under a home folder.

## 2. Check before installing

Replace `NCT_HOST_IP` below with the controller's actual IPv4 address, reachable
from the analyst workstation. Do not type the words `NCT_HOST_IP` literally.

```sh
sha256sum -c PACKAGE-MANIFEST.sha256
sh scripts/nct-install-range.sh NCT_HOST_IP check-fresh
```

Every checksum should say **OK**. The second command checks prerequisites, loads
the exact packaged images when they are not already present, and tests both
application runtimes under the host's normal container security. It does not
create NCT storage, a container, an account, a certificate or a service. A later
install reuses those exact verified images instead of loading the large archive
again. Fresh setup refuses an existing
NCT container, nonempty NCT storage or an existing recovery service/state. It
does not delete or adopt them. Stop and review a refusal; do not wipe host files.
The default dedicated storage location is `/var/lib/nct`.

## 3. Install and choose your administrator password

```sh
sh scripts/nct-install-range.sh NCT_HOST_IP fresh
```

The default NCT account name is **admin**. Enter a new password when prompted,
then enter it again. It must be 12–256 characters; spaces and symbols are allowed.
Nothing is displayed while typing the password. This is a new NCT account,
separate from the controller login. The temporary startup password file is
removed after the selected password is saved.

The terminal loads the included images, creates HTTPS material, starts NCT and
sets up the independent recovery helper and console. Wait for the final address
and completion instructions. Initial loading and database setup can take time.
If setup stops, preserve its output and NCT files for recovery; do not rerun it
after deleting arbitrary state. If it stops while confirming the Administrator
password and reports that the protected bootstrap state was preserved, continue
that exact empty installation with:

```sh
sh scripts/nct-install-range.sh NCT_HOST_IP resume-fresh
```

The continuation verifies the exact release image, dedicated data path,
temporary bootstrap mount, one expected Administrator identity and zero
operator evidence. If the password had already been saved before the
interruption, NCT keeps it and continues without asking for it again. Otherwise,
it asks for the password again. It refuses unknown, nonempty, changed or older
installations; it is not an upgrade or reset path.

Before creating NCT storage or services, setup tests both loaded images under
normal container security, including thread creation and required collection
tools. A failed runtime check stops installation with an explanation. It does
not disable the host's security protections to force the application to start.

## 4. Finish setup in the browser

Before opening the browser, have the administrator allow only approved analyst
addresses to reach HTTPS ports 8445 and 8446 using the Range's firewall policy.
This package does not make a broad firewall change. Have that administrator
install the generated root CA on the workstation according to local policy; its
controller path is `/var/lib/nct/tls-material/certs/nct-lab-root.crt`. Check the
host address and certificate rather than silently bypassing a browser warning.

1. Open `https://NCT_HOST_IP:8445` on the analyst workstation.
2. Sign in as **admin** with the password you just chose. For an exact new empty
   installation, this one normal sign-in verifies the Administrator and completes
   the protected recovery handoff automatically. Keep the sign-in page open while
   it reports that setup is finishing. NCT may restart once; the page reconnects
   automatically. If it takes longer than expected, reload the page once. Sign in
   again only if the restart cleared the browser session.
3. Open **hamburger → Updates & Recovery**, then select **Open update and recovery
   workspace**. Confirm the workspace reports **Update complete**. The independent
   console is normally on
   `https://NCT_HOST_IP:8446` and starts on demand through NCT.
4. If the fresh proof expired, changed, or the installation was no longer empty,
   the sign-in page explains that automatic setup could not finish and offers
   **Open Updates & Recovery**. Select **Open update and recovery workspace**, then
   complete **Verify sign-in and finish** there. No evidence or safety check is
   bypassed.
5. Confirm the build matches `release.json` in this package.
6. Begin in **Mission Environment**: establish Scope and No-Strike controls before
   network collection. Then create Saved Networks and use the normal collection
   workflow. **Evidence Library** starts empty and fills as evidence is retained.

The administrator must allow only the approved analyst addresses to reach HTTPS
ports 8445 and 8446 using the Range's existing firewall policy. This package does
not make a broad firewall change. Data persists under `/var/lib/nct/data`; the
host recovery helper lives under `/opt/nct-recovery` and its service is
`nct-recovery-host.service`. The web containers do not receive Docker control.

## Qualification limits

`release.json` identifies this package with `fresh_only: true`, an empty
`supported_sources` list and the `fresh-only-empty-host` gate. Do not use it as an
upgrade, reset or evidence-preservation route. If an NCT installation is present,
stop and preserve it for a separately qualified procedure; do not remove it merely
to make the fresh check pass.

After sealing, the package includes `VALIDATION.json`, which records the exact local
fresh-install rehearsal used to qualify that sealed package. It is intentionally absent
from an unsealed staging folder. A real host's service boot, browser trust and
authorized network collection still need acceptance on each Range. The package
includes a separate recovery-console image so recovery remains available when the
application is unavailable. No credentials, analyst evidence or local preview data are
bundled.

## Protected evidence retirement

This package includes the completed cross-evidence retirement workflow and Map
stored-file filtering. `release.json` has no deferred retirement work and sets
`retirement_complete` to `true`. Retirement is still deliberately guarded: the
independent host authority must be healthy, and a signed-in analyst or administrator
must review the exact impact, record a reason and type the displayed confirmation.
Retirement removes one retained encounter from ordinary use; it does not erase the
original source bytes or provide an audit shortcut back to its download or analysis.
