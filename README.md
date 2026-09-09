# Nmap Terrain Analyzer

A local, Dockerized FastAPI application for building authorized Nmap scans,
running scans with accountability capture, generating portable scan packages,
and analyzing current or historical Nmap XML.

## Phase 1 and 2 capabilities

- One **Nmap Scans** page with a scan builder at the top and actions to **Save
  as profile**, **Run now**, or **Generate package**.
- Human-readable `Name_Date_Time` scan names. Scheduled execution manifests use
  `Name_(S)_Date_Time`.
- Creator, scheduler, executor, execution method, target, protocol, port scope,
  interface, profile, and profile-version metadata in scan history.
- Reusable scan profiles with protected built-ins, clone, save, reuse, and
  immutable save-as-new-version behavior.
- First-class TCP, UDP, and TCP + UDP scans with independent common, full,
  custom, and ICS/OT port scopes.
- Mandatory `-n` in every generated Nmap command.
- Schedule-definition storage pinned to a specific immutable profile version.
  Recurring schedule execution remains a later-phase feature.
- Historical scans reopen through the same complete analysis renderer used for
  new XML uploads.
- MAC address and vendor parsing from Nmap XML.
- Separate host-summary and normalized port-level CSV exports. Port-level output
  contains one row per IP/protocol/port.
- Raw XML remains available as a secondary historical action.

## Run

Connected build:

```bash
docker compose up -d --build
```

Open `http://SERVER-IP`. Port `8080` is also mapped for diagnostics.

The automated **Run now** path requires the container capabilities and bundled
Nmap/tcpdump tools. It starts tcpdump on the selected analyzer interface and
retains the PCAP with the scan evidence. The **Generate package** path creates a
portable certified package without starting a scan on the analyzer.

## Air-gapped run

If an offline image is supplied with a release package:

```bash
docker load -i offline-images/IMAGE_NAME.tar.gz
docker compose up -d --no-build
```

The previously bundled image predates these source changes. Rebuild and export a
new image before treating an offline bundle as the updated release.

## Persistent and sensitive data

Runtime data is stored in `./data`; logs and optional device keys use `./logs`
and `./keys`. These paths, databases, PCAPs, key material, offline images, and
generated packages are excluded from Git by `.gitignore`.

Never commit operational scan evidence or credentials.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q app
```

## GitHub Pages

The static project page lives in `docs/`. The Pages workflow publishes it from
the `main` branch. In repository settings, configure **Pages → Source** as
**GitHub Actions**.

GitHub Pages presents documentation only; it cannot run FastAPI, Docker, Nmap,
or tcpdump.

See [ROADMAP.md](ROADMAP.md) for later phases.
