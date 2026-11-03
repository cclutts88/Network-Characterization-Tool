# Recovery-r4 existing-helper upgrade on classic Docker

This is a narrowly qualified administrator procedure for the unchanged full
`NCT-Full-Range-20261102-Recovery-r4.zip`. It does not change that package or apply
the NCT application update. Do not use it for any other release or installation.

The sealed upgrader recognizes the local development engine's R2 console runtime
ID. Classic Docker identifies the exact same console using its exported image
configuration digest. Both configurations and layers were independently verified.
The bridge accepts only that exact classic identity, exact R2 build/source and
exact sealed R4 manifest and helper sources. All normal upgrade checks remain.

Keep the existing service, accounts, evidence, receipts, old console and package.
Transfer `scripts/nct-r4-classic-console-bridge.py` separately to a root-owned,
non-writable-by-other-users location outside the extracted package. Its qualified
SHA256 is `5b7834a2e99c6c2f545002d54559ac1680f1cfdbf551f5186e1526393b0bfe3d`.
Use the protected Python selected by the existing service, version 3.9 or newer.

1. Follow the sealed START-HERE existing-helper route through package checksum
   verification and offline image loading. Extract into a new root-owned directory.
2. From the extracted `NCT-Air-Gapped-Range-Deployment` directory, preview:
   `/usr/bin/python3.9 -B /root/nct-r4-classic-console-bridge.py --package "$PWD"`.
3. If and only if the complete preview passes, repeat with `--apply` during the
   authorized maintenance window. Preserve its printed identity receipt and the
   installed `helper-upgrade.json` journal and backup directory.
4. If interrupted, inspect the saved journal. The same bridge with `--rollback`
   invokes the unchanged interrupted-helper recovery checks. It refuses completed
   transactions and mismatched original consoles. Do not reinstall over saved state.
5. After success, open signed-in NCT's Updates & Recovery. On the browser workstation,
   extract the full ZIP into a new folder and select the enclosed compressed
   `nct-update-0.16.0-range-test-20261102-recovery-r4.tar.gz`. Complete the separate
   browser upload, review, apply and existing-account verification.
6. Verify the actual installed build, normal sign-in and a saved older scan's XML.

Use `-B` throughout to avoid adding Python cache files inside the sealed package.
If an earlier preview created a cache, preserve it outside the package or extract
a fresh copy. Do not weaken the package manifest to admit extra files.

Qualification: 38 Linux tests, including the actual final sealed manifest/files,
wrong-content/config/release rejection and interruption after new-console creation
followed by rollback. Representative lifecycle engines and Docker Desktop bind
permission substitutions do not replace target checks. Actual Range preview,
systemd helper restart, CA-verified console readiness and helper apply passed.
Application GUI/account/evidence acceptance remains a separate recorded step.
