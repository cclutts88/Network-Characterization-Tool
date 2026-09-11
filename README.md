# Nmap Terrain Analyzer

A local, Dockerized FastAPI application for building authorized Nmap scans, running scans with accountability capture, generating portable scan packages, collecting network-device configurations, and analyzing current or historical Nmap XML.

## Phase 1 and 2 capabilities

- One **Nmap Scans** page with a scan builder at the top and actions to **Save as profile**, **Run now**, or **Generate package**.
- Human-readable `Name_Date_Time` scan names. Scheduled execution manifests use `Name_(S)_Date_Time`.
- Creator, scheduler, executor, execution method, target, protocol, port scope, interface, profile, and profile-version metadata in scan history.
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
- Interactive network-device collection with no stored password, visible cleanup behavior, optional operator commands, reusable device presets, optional device names, and Nmap-discovered device selection.
- Review-only subnet suggestions parsed from saved device configurations. An
  operator must explicitly add a suggestion to Saved Networks before it can be
  selected as scan scope; saved suggestions leave the pending list.

## Run

For a first-time private-lab HTTPS installation:

```bash
sh scripts/setup-lab-https.sh SERVER_IP
```

Install `http://SERVER-IP/nct-lab-root.crt` once in each operator computer's **Trusted Root Certification Authorities** store. Then open `https://SERVER-IP`.

The HTTPS proxy exposes ports 80 and 443. Analyzer port 8080 is bound only to the server's loopback interface. See [Private-lab HTTPS setup](docs/HTTPS_LAB_SETUP.md) for the complete setup and certificate-trust steps.

The automated **Run now** path requires the container capabilities and bundled Nmap/FPING/tcpdump tools. It starts tcpdump on the selected analyzer interface and retains the PCAP with the scan evidence. **Generate package** creates a portable certified package without starting a scan on the analyzer.

## Air-gapped run

If an offline image is supplied with a release package, load it and start the containers without building:

```bash
docker load -i offline-images/IMAGE_NAME.tar.gz
docker compose up -d --no-build
```

Rebuild and export a new image whenever source changes are incorporated into an offline release.

## Persistent and sensitive data

Runtime data is stored in `./data`; logs and optional device keys use `./logs` and `./keys`. Certificates and Caddy runtime state use `./certs`, `./tls`, `./caddy-data`, and `./caddy-config`. These paths, databases, PCAPs, key material, offline images, and generated packages are excluded from Git by `.gitignore`.

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
