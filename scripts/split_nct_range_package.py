#!/usr/bin/env python3
"""Transfer a sealed Range ZIP in bounded pieces without changing its contents."""
import argparse
import hashlib
import json
from pathlib import Path

PART_BYTES = 48 * 1024**2


def digest(path):
    result=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024**2),b''):result.update(block)
    return result.hexdigest()


def split_package(source, output=None, *, part_bytes=PART_BYTES):
    source=Path(source)
    if source.is_symlink() or not source.is_file() or source.suffix.lower()!='.zip' or source.stat().st_size==0:
        raise ValueError('Choose a nonempty sealed ZIP')
    source=source.resolve()
    if not 0<part_bytes<=PART_BYTES:raise ValueError('Transfer pieces must be at most 48 MiB')
    # Generated shell filenames are deliberately limited; no shell interpolation
    # of arbitrary filenames, paths, user data or credentials is accepted.
    import re
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*\.zip',source.name):raise ValueError('ZIP filename must use simple letters, numbers, dots, dashes or underscores')
    expected=digest(source)
    sidecar=source.with_suffix(source.suffix+'.sha256')
    if not sidecar.is_file() or sidecar.read_text().split()[0]!=expected:
        raise ValueError('The sealed ZIP checksum must be present and match before splitting')
    output=Path(output) if output else source.with_name(source.stem+'-Transfer-Parts')
    output.mkdir(parents=True,exist_ok=False)
    parts=[]
    with source.open('rb') as stream:
        while block:=stream.read(part_bytes):
            name=source.name+f'.part{len(parts)+1:02d}'
            with (output/name).open('xb') as part:part.write(block)
            parts.append({'file':name,'bytes':len(block),'sha256':hashlib.sha256(block).hexdigest()})
    # Refuse a source that changed during the split; retain partials for review.
    if digest(source)!=expected or sum(x['bytes'] for x in parts)!=source.stat().st_size:
        raise ValueError('The source ZIP changed during splitting; transfer set is not qualified')
    checks='\n'.join(x['sha256']+'  '+x['file'] for x in parts)
    inputs=' '.join('"$PARTS/'+x['file']+'"' for x in parts)
    script=f'''#!/bin/sh
set -eu
umask 077
PARTS=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
OUT=${{1:-$PARTS}}
OUT=$(CDPATH= cd -- "$OUT" && pwd -P)
FINAL="$OUT/{source.name}"
EXPECTED={expected}
if [ -e "$FINAL" ] || [ -L "$FINAL" ]; then
  if [ ! -L "$FINAL" ] && [ -f "$FINAL" ] && [ "$(sha256sum "$FINAL" | cut -d " " -f 1)" = "$EXPECTED" ]; then printf '%s\\n' "Complete ZIP already exists and its checksum is correct: $FINAL"; exit 0; fi
  printf '%s\\n' "A different file or link already exists at $FINAL. It has been preserved." >&2; exit 1
fi
printf '%s\\n' 'Checking all {len(parts)} transfer pieces...'
(cd "$PARTS" && sha256sum -c - <<'NCT_PART_CHECKSUMS'
{checks}
NCT_PART_CHECKSUMS
)
TEMP=$(mktemp "$OUT/.nct-transfer-join.XXXXXX")
trap 'rm -f -- "$TEMP"' EXIT HUP INT TERM
printf '%s\\n' 'Rebuilding the original ZIP...'
cat {inputs} > "$TEMP"
[ "$(sha256sum "$TEMP" | cut -d " " -f 1)" = "$EXPECTED" ] || {{ printf '%s\\n' 'Combined ZIP checksum failed. Keep the pieces and retry.' >&2; exit 1; }}
ln -- "$TEMP" "$FINAL" || {{ printf '%s\\n' 'The output name became occupied; existing file preserved.' >&2; exit 1; }}
printf '%s\\n' 'PASS: Complete ZIP rebuilt and checksum verified.' "$FINAL" 'This only joins the package; NCT has not been installed or updated.'
'''
    (output/'JOIN-NCT.sh').write_text(script,encoding='utf-8',newline='\n')
    instructions=f'''NCT Range transfer pieces

Upload all {len(parts)} .part files AND JOIN-NCT.sh to the same controller folder.
Do not extract or install individual pieces. No separate checksum upload is needed;
the join script contains every expected part and complete-ZIP checksum.

In that controller folder, run:
  sh JOIN-NCT.sh

It verifies every piece, rebuilds {source.name}, and checks the complete ZIP.
It preserves any different existing output file and does not install NCT.
After PASS, extract the rebuilt ZIP into a new folder and follow START-HERE.md.
Keep the original pieces until installation is verified.

Complete ZIP SHA-256: {expected}
Complete ZIP bytes: {source.stat().st_size}
'''
    (output/'READ-ME-FIRST.txt').write_text(instructions,encoding='utf-8',newline='\n')
    result={'contract':'nct-transfer-parts-v1','zip':source.name,'zip_bytes':source.stat().st_size,'zip_sha256':expected,
        'max_piece_bytes':part_bytes,'parts':parts,'join_script':'JOIN-NCT.sh','join_script_sha256':digest(output/'JOIN-NCT.sh')}
    (output/'TRANSFER-CHECKSUMS.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    return {'directory':str(output.resolve()),**result}


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('zip',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    print(json.dumps(split_package(args.zip,args.output),indent=2))
