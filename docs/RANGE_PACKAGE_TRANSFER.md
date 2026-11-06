# Move an NCT package to an air-gapped Range

This is the standard transfer process for a sealed full NCT Range package. It
solves only the file-size problem between the build workstation and the Range
controller. It does not install, update, reset, or delete NCT.

## What the release build produces

When the sealed ZIP is larger than 48 MiB, the release builder automatically
creates one adjacent `-Transfer-Parts` folder. That folder is bound to one ZIP
checksum and contains:

- numbered `.part` files, each no larger than 48 MiB;
- `JOIN-NCT.sh`, which contains every part checksum and the complete ZIP checksum;
- `READ-ME-FIRST.txt`, with the exact filenames and controller commands; and
- `TRANSFER-CHECKSUMS.json`, the visible identity record for that exact set.

The release builder rereads every generated piece and proves that the persisted
pieces reconstruct the exact sealed ZIP before it reports the transfer set as
ready. Do not manually split or rename the package.

## Controller transfer

1. Create one new empty controller folder for this release. All pieces go
   together in that folder; individual pieces do not get separate folders.
2. Upload **every file in that transfer folder**. There is no file-selection
   decision: the numbered pieces, `JOIN-NCT.sh`, `READ-ME-FIRST.txt`, and
   `TRANSFER-CHECKSUMS.json` all go together. No separate `.sha256` upload is
   needed.
3. Open a controller terminal in that folder and run:

   ```sh
   sh JOIN-NCT.sh
   ```

4. Wait for the four numbered stages and the final `PASS`. The joiner refuses a
   missing, corrupt, linked, extra, or mixed-release piece, and verifies the
   exact generated transfer identity record and operator readme. It also preserves
   a different ZIP already using the destination name. Repeating it after a
   successful join verifies the existing ZIP without replacing it.
5. Keep the pieces and rebuilt ZIP until Range acceptance is complete. Extract
   the ZIP into a new folder and follow its `START-HERE.md` from the beginning.

`HALT` means the package is not ready to install. Correct only the named
transfer problem; do not combine pieces by hand or install a partial ZIP.

## Development command

Packaging normally calls the splitter automatically. To prepare an already
sealed ZIP manually during development, keep its adjacent `.zip.sha256` file and
run:

```sh
python scripts/split_nct_range_package.py SEALED_PACKAGE.zip
```

The command refuses an existing transfer folder so an older set cannot be
silently overwritten. This development command does not qualify the application
or make it Range-ready; all package and acceptance gates still apply.
