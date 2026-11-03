#!/usr/bin/env python3
"""Content-verified adapter for the sealed Recovery-r4 helper upgrade only."""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path

CLASSIC = 'sha256:cf8d3141abfcb66450b435cd351e4a7824f70b3d0a67b8ca62fecc465d139548'
SEALED = 'eeda609ec4909e631ab04157556365e59df23440b1ba0b85171a00d8da5498dd'
COMMIT = '937954bc03e4b21c3e93d7430321a918d8bc59a0'
BUILD = '0.16.0-range-test-20261102-recovery-r4'
OLD_BUILD = '0.16.0-range-test-20261029-recovery-r2'
OLD_COMMIT = '54aa0df9cbc7dd30cb68adbaf21a055761776b5c'
CONSOLE_DIGEST = 'sha256:0606260094f4a81e4227c9809fa8e5c633ad99b88bfe2b3a18c7f3e9febfff7c'
MANIFEST = '289f788dee3324600bf43324d1487d51426ab11f066caab4aad7a6741af825b6'


def protected(path):
    for item in (path, *path.parents):
        s = item.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('Bridge and package paths must be protected and root-owned')


def check_release(package):
    manifest = package / 'PACKAGE-MANIFEST.sha256'
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != MANIFEST:
        raise ValueError('Full package manifest differs from the qualified release')
    for line in manifest.read_text().splitlines():
        digest, relative = line.split('  ', 1)
        p = Path(relative)
        if p.is_absolute() or '..' in p.parts:
            raise ValueError('Invalid package member')
        member = package / p
        protected(member)
        h = hashlib.sha256()
        with member.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
        if h.hexdigest() != digest:
            raise ValueError('Packaged file checksum differs: ' + relative)
    source = package / 'scripts/nct-upgrade-recovery.py'
    if hashlib.sha256(source.read_bytes()).hexdigest() != SEALED:
        raise ValueError('This bridge requires the unchanged sealed Recovery-r4 upgrader')
    release = json.loads((package / 'release.json').read_text())
    image = 'nct-recovery-console:' + BUILD
    if (release.get('commit'), release.get('build_id'), release.get('console_image')) != (COMMIT, BUILD, image):
        raise ValueError('Unexpected full package release')
    if release['images'][image]['archive_config_digest'] != CONSOLE_DIGEST:
        raise ValueError('Unexpected replacement console content')
    return source, image


def qualify(upgrade, rollback=False):
    # Exported config binds every layer as well as environment and entrypoint.
    image = json.loads(upgrade.engine.command('image', 'inspect', CLASSIC))[0]
    env = dict(v.split('=', 1) for v in image['Config'].get('Env', []) if '=' in v)
    if (env.get('NCT_BUILD_ID'), env.get('NCT_BUILD_COMMIT')) != (OLD_BUILD, OLD_COMMIT):
        raise ValueError('Original console release identity differs')
    if image['Id'] != CLASSIC or upgrade.image_config_digest(CLASSIC) != CLASSIC:
        raise ValueError('Original console content differs')
    if not rollback:
        console = upgrade.engine.inspect(upgrade.config['console_container'])
        if upgrade.config.get('console_image_id') != CLASSIC or console['Image'] != CLASSIC:
            raise ValueError('Configured and actual original console must match exactly')
    else:
        # The unchanged rollback checks the journal, retained container and backups.
        upgrade_module = sys.modules[upgrade.__class__.__module__]
        upgrade_module.protected(upgrade.journal_path)
        journal = json.loads(upgrade.journal_path.read_text())
        if journal.get('old_console', {}).get('Image') != CLASSIC:
            raise ValueError('Rollback journal is not for this original console')
    return {'contract': 'nct-r4-classic-console-bridge-v1', 'original_console_runtime': CLASSIC,
            'original_console_content': CLASSIC, 'original_build': OLD_BUILD,
            'original_commit': OLD_COMMIT, 'sealed_upgrader_sha256': SEALED}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--config', type=Path, default=Path('/opt/nct-recovery/config.json'))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run on the NCT host as administrator')
    os.umask(0o077)
    protected(Path(__file__).absolute())
    protected(args.package.absolute())
    source, image = check_release(args.package)
    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location('sealed_r4_upgrade', source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.protected(Path(__file__))
    module.protected(Path(__file__).parent, True)
    module.protected(args.package, True)
    module.protected(source.parent, True)
    module.protected(source)
    module.verify_manifest(args.package)
    upgrade = module.Upgrade(args.config, source.parent, image)
    receipt = qualify(upgrade, args.rollback)
    receipt['bridge_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps(receipt, sort_keys=True), flush=True)
    module.OLD_CONSOLE = CLASSIC
    if args.rollback:
        upgrade.rollback()
    elif args.apply:
        upgrade.apply()
    else:
        upgrade.preflight()
        print('Checks passed. NCT is unchanged. Repeat with --apply to upgrade recovery.', flush=True)


if __name__ == '__main__':
    main()
