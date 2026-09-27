"""Opt-in Linux benchmark using only disposable synthetic evidence.

Run from the repository root with the normal NCT dependencies installed.
Prints JSON; never reads an existing NCT data directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collections', type=int, default=1000)
    parser.add_argument('--unique', type=int, default=10)
    parser.add_argument('--file-bytes', type=int, default=65536)
    args = parser.parse_args()
    if not (1 <= args.unique <= args.collections <= 10000 and 64 <= args.file_bytes <= 1048576):
        parser.error('Use 1..10000 collections, 1..collections unique contents, and 64..1048576 bytes per file.')
    if sys.platform != 'linux':
        parser.error('Run inside the NCT Linux test container for comparable memory units.')
    import resource
    with tempfile.TemporaryDirectory(prefix='nct-storage-benchmark-') as directory:
        root = Path(directory)
        os.environ['ANALYZER_DATA_DIR'] = str(root)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from app.storage_health import analyze_storage, backfill_storage
        from app.artifacts import artifact_storage_summary

        source_hashes = {}
        for index in range(args.collections):
            run = root / 'device-configs' / f'benchmark-{index:05d}'
            run.mkdir(parents=True)
            marker = f'synthetic-evidence-{index % args.unique:05d}\n'.encode()
            payload = (marker * (args.file_bytes // len(marker) + 1))[:args.file_bytes]
            (run / 'stdout.txt').write_bytes(payload)
            (run / 'manifest.json').write_text(json.dumps({
                'run_id': run.name, 'status': 'completed', 'operator': 'synthetic benchmark',
                'created_at': '2026-09-27T00:00:00+00:00', 'local_output_name': 'stdout.txt'}))
            for file in run.iterdir():
                source_hashes[file] = hashlib.sha256(file.read_bytes()).hexdigest()
        db_path = root / 'analyzer.db'
        # Warm module imports outside the timed operations; no storage inspection yet.
        from app import poc, device_configs  # noqa: F401

        measurements = []
        def measure(name, operation):
            before = resource.getrusage(resource.RUSAGE_SELF)
            start = time.perf_counter()
            result = operation()
            after = resource.getrusage(resource.RUSAGE_SELF)
            measurements.append({'operation': name, 'wall_seconds': round(time.perf_counter()-start, 4),
                'cpu_seconds': round(after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime, 4),
                'process_peak_rss_kib': after.ru_maxrss})
            return result
        initial = measure('dry_run', lambda: analyze_storage(db_path))
        assert initial['issue_count'] == 0 and initial['verified_references'] == args.collections
        assert initial['duplicate_bytes'] == (args.collections-args.unique)*args.file_bytes
        def backfill_and_report():
            return backfill_storage(db_path), analyze_storage(db_path)
        first, report = measure('backfill_and_report', backfill_and_report)
        repeated, repeated_report = measure('repeat_backfill_and_report', backfill_and_report)
        assert first['completed'] == args.collections and first['issue_count'] == 0
        assert repeated['completed'] == 0 and repeated['resumed_unchanged'] == args.collections
        assert repeated['issue_count'] == repeated_report['issue_count'] == 0
        summary = artifact_storage_summary(db_path)
        assert summary['observation_count'] == args.collections
        assert summary['unique_artifact_count'] == args.unique
        assert report['reclaimable_bytes'] == args.collections*args.file_bytes
        assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path,digest in source_hashes.items())
        print(json.dumps({'platform': platform.platform(), 'python': platform.python_version(),
            'dataset': vars(args), 'measurements': measurements,
            'initial_used_bytes': initial['used_bytes'], 'after_backfill_used_bytes': report['used_bytes'],
            'reclaimable_bytes': report['reclaimable_bytes'], 'observations': summary['observation_count'],
            'originals_unchanged': True, 'checks': 'passed',
            'limitations': 'Synthetic warm-import local Docker run. Peak RSS is process lifetime, including imports and data creation. No cold-cache, concurrent workloads, production or Range acceptance.'}, indent=2))


if __name__ == '__main__':
    main()
