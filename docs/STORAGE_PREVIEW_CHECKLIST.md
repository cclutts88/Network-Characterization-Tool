# Storage preview: hands-on check

Open http://127.0.0.1:18087/settings/system-health on this computer.
This is foundation-only, with disposable sample data. Production data and main
are unchanged. Keep anything you want to retain outside this preview.

1. Run **Run storage dry run**. Expect a completed report, two verified evidence
   references, no issues, and deletion disabled.
2. Check **Storage breakdown**. It lists the database and evidence folders.
   Figures describe file sizes; filesystem overhead is excluded.
3. Select **Backfill existing evidence**. The prepared samples are already
   registered: expect zero newly registered, two already registered or unchanged,
   and zero issues. Repeating it must not add observations or remove originals.
4. Refresh or leave and return. The latest report should remain available.
5. Try a disposable Nmap XML or device-config upload in the normal workspace
   pages, then rerun the dry run. Confirm you can still open/download that evidence.

The two prepared files have identical contents. Unique evidence is 57 KiB;
duplicate and potentially reclaimable copies are 114 KiB after backfill because
the canonical copy and both retained originals remain. Reclaimable is an estimate,
not an available deletion action. Used space can change as the database/report grow.

Report any confusing labels, stalled buttons, missing history, unexpected changes
in counts, or evidence that will not reopen. User acceptance is still pending;
passing development checks does not establish Range or mission readiness.

The preview container is named `nct-foundation-storage-preview`. It has no production
data mount and listens only on this computer. Stopping it removes its disposable
data. Restarting it preserves its data and reloads the application.
