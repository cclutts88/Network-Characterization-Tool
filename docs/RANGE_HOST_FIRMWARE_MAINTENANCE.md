# Range Host Firmware Maintenance Gate

Use this checklist before resuming the Security Onion build. It applies to the
physical Proxmox host only. It does not authorize changes to the NCT application,
production evidence or the inaccessible `chrisJr` storage pool.

## Current status — deferred without flashing

On 2026-10-20, physical firmware access and the prepared update media were verified,
but the operator deferred the update after the motherboard interface presented an
unreliable mixed-language display. M-FLASH was not started and no firmware setting was
changed. After the host returned, it still reported BIOS `1.A0`, dated 2024-03-28, and
CPU microcode `0x123`.

All guests remain stopped with automatic start disabled. The `chrisJr` storage entry
remains disabled and excluded from LVM autoactivation; the verified `pve` boot volume
group remains the only permitted automatic-activation volume group. This is a safe
deferral, not completion of the maintenance gate. Security Onion acceptance, sensor
setup and heavy host workloads remain halted. Bounded NCT development may continue on
the separate development workstation using copies of retained exports or isolated
fixtures, subject to an independent design gate.

## Why the gate exists

The host currently reports:

- Intel Core i9-14900KF
- MSI PRO B760-P WIFI DDR4 (MS-7D98)
- BIOS `1.A0`, dated 2024-03-28
- CPU microcode `0x123`

During one manager build, the guest kernel crashed. After changing to the alternate
kernel already included on the verified Security Onion ISO, Elasticsearch's bundled
Java runtime later crashed with `SIGSEGV`. Neither event proves that host firmware is
the cause. Current Intel guidance nevertheless recommends Intel Default Settings and
the latest BIOS containing microcode `0x12F` or later for this processor family. The
host must be serviced and then tested before Security Onion acceptance resumes.

## Before the maintenance window

1. Plan for a complete range outage. The host currently runs routing, firewall,
   test-network, Arkime and other guests. Remote access can disappear when network
   infrastructure guests stop. Before changing any guest, connect a monitor and
   keyboard to the physical host, confirm that the local Proxmox console is visible and
   accepts input, and have MSI's exact firmware-entry and recovery steps available.
2. Keep the replacement Security Onion manager and both sensors stopped. Confirm
   automatic start is disabled for all three.
3. Record the current Proxmox guest and container list, each `onboot` and `startup`
   value, all HA-managed resources, bridge configuration, boot order and the BIOS
   settings needed for virtualization, IOMMU, storage and system boot. Save this
   baseline on healthy storage and verify it is readable.
4. Back up the Proxmox configuration to verified healthy storage. Do not activate,
   repair, mount, remove or write to the unhealthy `chrisJr` pool as part of this work.
5. Temporarily set `onboot=0` for every VM and container. If HA resources exist, place
   them in a recorded stopped state that HA will not restart. Re-read every guest,
   container and HA setting to prove that nothing can start automatically. Keep the
   baseline needed to restore the exact prior values after validation.
6. Disable the Proxmox storage entry `chrisJr` in `/etc/pve/storage.cfg`. On this host,
   merge a host-local LVM autoactivation allowlist into `/etc/lvm/lvmlocal.conf` while
   preserving its original contents. The effective allowlist must include only the
   verified healthy boot volume group `pve` and exclude `chrisJr`. Validate the
   effective LVM configuration, check that no explicit boot or Proxmox script activates
   `chrisJr`, rebuild the initramfs, identify the initramfs the next boot will actually
   use, and verify that it contains the host-local rule. A storage-status check must no
   longer try to activate `chrisJr`. These steps change host configuration only; do not
   use an LVM command that writes the unhealthy volume group's metadata. If the healthy
   volume inventory differs from the expected `pve` layout, if an explicit activation
   path remains, or if this prevention cannot be proved, halt before shutdown.
7. From MSI's support page for **PRO B760-P WIFI DDR4 (MS-7D98)**, download the latest
   stable BIOS that contains microcode `0x12F` or later. Do not use a beta release.
   Verify the downloaded file against MSI's published SHA-256 value.
8. Put the extracted MSI update on a FAT32 USB drive. Keep a copy of the prior BIOS and
   MSI's recovery instructions available on a second device.
9. Use stable power. Do not begin if power may be interrupted.

## Controlled shutdown and update

1. Reconfirm that automatic start and HA restart are suppressed for every guest.
2. Shut down ordinary application and test guests first.
3. Shut down passive monitoring guests next.
4. Shut down the router and firewall guests last, from the demonstrated physical
   console.
5. Confirm no guest or container is running, then shut down the Proxmox host normally.
6. Enter the motherboard firmware and use MSI M-FLASH with the verified file. Do not
   flash from an unverified utility and do not interrupt the update.
7. Apply Intel Default Settings. Restore only the recorded settings required for
   virtualization, IOMMU, storage, boot order and network operation.

## Verification before Security Onion resumes

1. Boot Proxmox and record the new BIOS version, date and CPU microcode. Microcode must
   report `0x12F` or later.
2. Before starting any guest, verify that the automatic-start suppression remains in
   effect, expected healthy storage is active, and `chrisJr` remains disabled,
   untouched and excluded from LVM autoactivation. Repeat the guest-start and storage
   checks after every reboot, including any reboot used for offline memory testing.
3. Check host logs for hardware, machine-check, memory, storage and kernel errors.
4. Run a complete offline memory test and a sustained CPU/memory load test. A BIOS
   update alone does not prove that the processor or memory is stable.
5. Start the router and firewall guests manually first and verify the range networks.
6. Start the other previously running guests one at a time and verify their services.
7. Start only the Security Onion manager. Keep both sensors stopped.
8. With no sensors enrolled, inspect the installed Security Onion
   `/usr/sbin/so-elastic-fleet-reset` procedure, retain the current partial-state
   evidence, and then use that supported reset to clear and rebuild the incomplete
   Fleet state. Do not resume from the interrupted optional-package process and do not
   use a hand-edited reset sequence. Halt if the installed reset would affect anything
   beyond the incomplete, sensor-free lab setup.
9. Require clean Security Onion status, successful Fleet completion, web login,
   repeated service checks, sustained search load and at least two clean restarts.
10. Restore each guest's exact prior `onboot`, `startup` and HA values only after host
    and network validation is complete. Keep `chrisJr` disabled and excluded from LVM
    autoactivation while restoring those values.
11. Only after those checks pass may sensor installation resume, one sensor at a time.

If the host shows another kernel, Java, machine-check or unexplained application crash,
stop acceptance again and investigate the CPU, memory and guest software independently.
