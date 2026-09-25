# NCT — Network Characterization Tool

A local, Dockerized application for authorized network characterization. NCT
collects Nmap and network-device evidence, analyzes and correlates it, presents
network-wide Hunt datasets, enriches observed products with an offline
SearchSploit database, and visualizes retained topology evidence.

## Current capabilities

- One **Nmap Scans** page with a scan builder at the top and actions to **Save as profile**, **Run now**, or **Generate package**.
- Human-readable `Name_Date_Time` scan names. Scheduled execution manifests use `Name_(S)_Date_Time`.
- Creator, scheduler, executor, execution method, target, protocol, port scope, interface, profile, and profile-version metadata in scan history.
- A shared first-in/first-out analyzer queue with active ownership, waiting
  positions, automatic next-run dispatch, owner cancellation, Administrator
  reassignment, live status, and per-run audit history.
- Owner-scoped autosaved scan-builder drafts for signed-in analysts, including
  scope, profile, interface, timeout, and scan settings.
- Reusable scan profiles with protected built-ins, clone, save, reuse, and immutable save-as-new-version behavior.
- Saved Networks with normalized IPv4 CIDRs, operator ownership, tags,
  categories, archive behavior, and immutable scan-time snapshots. Scans can
  combine multiple Saved Networks with manual targets.
- First-class TCP, UDP, and TCP + UDP scans with independent common, full, custom, and ICS/OT port scopes.
- Optional FPING pre-discovery and Nmap traceroute evidence for faster discovery and path mapping.
- Mandatory `-n` in every generated Nmap command.
- Active one-time, hourly, daily, weekly, monthly, and custom-hour schedules
  pinned to a specific immutable profile version, with sequential conflict
  handling, operator change history, and restart-safe chunk recovery.
- Historical scans reopen through the same complete analysis renderer used for new XML uploads.
- MAC address and vendor parsing from Nmap XML.
- ARP/neighbor-table collection and parsing that excludes incomplete entries.
- MAC correlation across Nmap and router/firewall ARP tables, with evidence
  source, interface/segment, timestamps, confidence, and conflict warnings.
  Scanner-side PCAPs are not used for endpoint MAC inference across routed boundaries.
- Offline vendor enrichment from Nmap's locally installed OUI prefix database;
  no external lookup service or internet access is required.
- Separate host-summary and normalized port-level CSV exports.
- Interactive VyOS, Cisco, Juniper, pfSense, and UniFi OS Gateway collection with no stored password, visible cleanup behavior, optional operator commands, reusable device presets, optional device names, and Nmap-discovered device selection.
- Review-only subnet suggestions parsed from saved device configurations. An
  operator must explicitly add a suggestion to Saved Networks before it can be
  selected as scan scope; saved suggestions leave the pending list.
- A dedicated network-wide Hunt view with service-aware datasets, combined
  host/network/evidence filters, CVE categorization, collapsible result panels,
  and scan-to-scan change analysis.
- Read-only Reach analysis that correlates retained routes, applied policy,
  sequential vendor NAT, and Nmap services. A Not Exposed result requires exact
  per-host Nmap protocol/port coverage rather than merely assuming an unlisted
  port is closed. An analyst can explicitly mark a source IP or CIDR as external
  while preserving that exact address for retained WAN-policy matching. A
  read-only proposed-policy check compares an exact permit or deny with the
  retained outcome and exports the evidence without changing a device. A
  companion proposed-route check adds a route on a retained interface or
  removes an exact retained route in memory, exposes broader fallback routes,
  changes an explicit metric/preference, and exports the comparison without
  contacting a device. Equal-prefix path selection is projected only where all
  competing retained routes have comparable numeric priority evidence. Both
  policy and route checks show current/projected paths, retained alternatives,
  and bounded collateral scope without extrapolating beyond the one evaluated
  representative flow. Complete report JSON uses short filenames, and either
  proposal can open as a temporary current-to-projected Map focus without
  changing a saved layout.
  On-demand exposure reports group every unique observed service by Internet and
  Saved Network source, retain route/policy/NAT objects, associate local
  SearchSploit candidates, and export the complete evidence as JSON. Individual
  checks and report paths can open as temporary Map focus overlays without
  changing an analyst's saved layout.
- Audited analyst OS corrections from the Nmap host inventory. Scanner evidence
  remains visible and unchanged; the confirmed value is used for Hunt and Map
  presentation, and later scanner disagreement is flagged.
- Offline SearchSploit enrichment using a managed Exploit-DB database with
  connected updates, air-gapped uploads, source/version details, archive safety
  validation, atomic activation, and prior-version rollback. Hunt correlates
  each potential match with retained external and per-Saved-Network Reach
  evidence without presenting a product/version match as proven exploitability.
- A network map with consolidated router/firewall identities, Saved Network and
  subnet grouping, collapsible endpoint groups, compact topology nodes, a sticky
  evidence panel, cursor-centered zoom, drag-to-pan, draggable nodes, and Fit.
  Endpoint subnets can remain collapsed, fan out into individual connection
  lines, or organize hosts inside a larger box with IP, hostname, or OS
  breakdowns. An expanded workspace uses the available browser area while map
  presentation choices remain local to each analyst browser.

## Run

For a controlled Linux Docker Test or Range deployment, start with the guided
installer. It asks for the deployment type, address, ports, firewall scope,
TLS choice, image, acceptance receipt, and initial Administrator, then runs a
non-destructive preflight before asking for final installation approval:

```bash
sudo sh scripts/install-nct.sh
```

Use `--plan-only` to review the questions and resulting plan without generating
certificates, loading images, changing the firewall, or starting containers.
After a successful installation, non-sensitive answers are retained under
`nct-deployment` for the next reset; passwords are never stored in that preset.
On later resets, accept the reuse prompt or add `--reuse-preset` to skip the
individual setup questions. The review, safe preflight, and final installation
approval always remain in place.

For advanced or unattended operation, use the rapid launcher directly in
check-only mode. Every profile requires an explicit versioned image
with embedded application/build identity; mutable `:latest` references are
rejected. The launcher validates the Docker runtime, existing NCT
instance and data volume, active operations, access address, ports, firewall
plan, image availability, disk space, and rollback prerequisites without
changing containers:

```bash
sh scripts/nct-deploy.sh --profile test --access local \
  --image network-characterization-tool:VERSION --check-only
```

See [Rapid deployment](docs/RAPID_DEPLOYMENT.md) before using LAN, offline,
upgrade, TLS, or Range options. The Mission profile remains intentionally
blocked until the formal mission-readiness gate is complete. Range deployments
require authentication; a fresh account store is initialized with an
operator-selected Administrator and no fixed default credentials.

Use the [Range compatibility matrix](docs/RANGE_COMPATIBILITY_MATRIX.md) to run
the repeatable non-destructive deployment scenarios and optionally include a
real `--check-only` preflight for one immutable local image.

To generate private-lab TLS material without starting any containers:

```bash
sh scripts/setup-lab-https.sh SERVER_IP nct-deployment/tls-material
```

Transfer the generated public `nct-lab-root.crt` to each operator workstation
through the approved process and install it in **Trusted Root Certification
Authorities**. Never transfer the CA or server private key. The guided installer
automates this generation option and prints the verified final address. See
[Private-lab HTTPS setup](docs/HTTPS_LAB_SETUP.md) for the complete trust steps.

The automated **Run now** path requires the container capabilities and bundled Nmap/FPING/tcpdump tools. It starts tcpdump on the selected analyzer interface and retains the PCAP with the scan evidence. **Generate package** creates a portable certified package without starting a scan on the analyzer.

## Air-gapped run

If an offline image is supplied with a release package, start the guided
installer and choose **Air-gapped / offline installation**. It will request the
versioned image name and archive, calculate or confirm the SHA-256, run the safe
preflight, and deploy without building or pulling:

```bash
sudo sh scripts/install-nct.sh
```

Rebuild and export a new image whenever source changes are incorporated into an offline release.

### Air-gapped SearchSploit updates

On an internet-connected transfer system, download the official Exploit-DB
archive from the [Exploit-DB GitLab repository](https://gitlab.com/exploit-database/exploitdb/-/archive/main/exploitdb-main.tar.gz).
Move the unchanged archive to the NCT system using the approved transfer
process. In **Hunt**, expand **SearchSploit enrichment** and **Manage offline
database**, choose the archive, and select **Upload offline update**.

NCT accepts ZIP, TAR, TAR.GZ, and TGZ packages. It validates the archive before
atomically activating it and retains the previous version for rollback. The
official archive validated during Release 8 was approximately 47 MB compressed
and approximately 309 MB after installation. Retaining another database version
requires roughly the same additional installed space.

## Range operator scripts

For repeat Range deployments, use the small operator-focused scripts under
`scripts/` rather than the older all-in-one launcher:

- `nct-start-compose.sh` — start with Docker Compose when `docker compose` is available.
- `nct-start-docker.sh` — start with the modern Docker CLI when Compose is unavailable.
- `nct-start-legacy.sh` — compatibility start path for older Range Docker engines.
- `nct-set-admin.sh` — inspect, create, replace, rename, or reset the NCT Administrator interactively.

The older `nct-range-direct-deploy.sh` is retained for compatibility with prior
deployment bundles, but it is not the preferred reset workflow. It now requires
an explicit Administrator username and does not assume a personal account name.

See [scripts/README.md](scripts/README.md) for the short decision tree and
operator commands.

## Persistent and sensitive data

Runtime data is stored in `./data`; logs and optional device keys use `./logs`
and `./keys`. Deployment receipts, presets, generated TLS material, and backups
use `./nct-deployment`. These paths, databases, PCAPs, key material, offline
images, and generated packages are excluded from Git by `.gitignore`.

Never commit operational scan evidence, credentials, private certificate keys, or device configuration captures.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q app
```

## GitHub Pages

The static project page lives in `docs/`. The Pages workflow publishes it from the `main` branch. In repository settings, configure **Pages → Source** as **GitHub Actions**.

GitHub Pages presents documentation only; it cannot run FastAPI, Docker, Nmap, tcpdump, or SSH collection. See [ROADMAP.md](ROADMAP.md) for later phases.
