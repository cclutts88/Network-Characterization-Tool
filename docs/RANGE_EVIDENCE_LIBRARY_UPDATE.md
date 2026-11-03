# Evidence Library — offline Range update

This ZIP updates an existing **Recovery-r4** installation
(`0.16.0-range-test-20261102-recovery-r4`, source
`937954bc03e4b21c3e93d7430321a918d8bc59a0`). Keep the existing recovery helper,
console, accounts and evidence. This package does not replace those recovery
components, install Kubernetes, or provide a newly qualified first-time install.
Older releases need their separately reviewed upgrade path.

## Prepare the file

1. Transfer this one ZIP to the Range. Extract it into a **new folder** and keep
   the previous package. Checksums are included; no separate download is needed.
2. Have an administrator check the extracted contents by running
   `sha256sum -c PACKAGE-MANIFEST.sha256` inside the deployment folder. Stop if
   any entry fails. These checks detect damaged files; use a trusted package source.
3. Copy the included `nct-update-…tar.gz` to the workstation running the browser.
   Keep that file compressed. Upload that file inside NCT, not the full ZIP.
   If transferring from the controller, use SCP with its actual account, address
   and extracted file path; save it in the workstation's Downloads folder.

## Apply through the existing recovery console

1. Finish active scans and device pulls. Review pending work and schedules before
   the maintenance window. Keep your existing NCT username and password.
2. Sign in to NCT. Open the hamburger's **Updates & Recovery** entry, then open
   the update and recovery workspace. Use the existing console handoff.
3. **Upload and validate** the `nct-update-…tar.gz`. Validation checks the installed
   release and package while NCT continues running. Review the reported versions.
4. Choose **Apply**. NCT stops temporarily while the console saves and verifies a
   backup, installs the application and checks retained evidence. Keep the console
   open and wait for the next stage. Do not reinstall or delete its saved state.
5. At **Verify sign-in and finish**, enter your existing NCT account and click
   **Verify sign-in**. Verification and a final restart can take time. A cleared
   password field alone is not a completion message; wait for the console result
   and return to NCT. Sign in normally if asked.
6. Confirm the new build shown in NCT. Open **Evidence Library** from the
   hamburger. Filter for an older scan and device collection, open **Files and
   context**, and save an original XML or configuration to check real access.

If an update fails, stay in the independent console and follow its reported
recovery/restore stage. Preserve backups and receipts. Do not rerun the first-time
installer or the older R3 helper-upgrade procedure on this R4 installation.

## What's included and what is qualified

The ZIP includes the application update, offline application/recovery/HTTPS
images, source-bound administrator tools, internal checksums and local validation
receipt. The qualified route for this kit is the existing-R4 GUI application
update and restore using its unchanged recovery helper and console. Bundled older
terminal instructions are reference material, not permission to choose an
unqualified alternate installation path. Loading replacement recovery images or
changing the host service is unnecessary for this update.

The Evidence Library joins retained scans, import encounters and device evidence.
It supplies filters and original-file/context links without launching collection.
Saved status is descriptive, not proof of integrity or present network truth.
Device index coverage is shown explicitly when incomplete. Administrator changes
made directly to retained files can require an administrator to restart NCT to
rebuild its temporary catalog. A previously identified setup interruption can
leave database protections incomplete and prevent startup; that separate repair
remains open. This release does not bypass that startup check or claim to fix it.

Local qualification is separate from installation acceptance on your Range.
`VALIDATION.json` records the exact locally tested package and limitations.
