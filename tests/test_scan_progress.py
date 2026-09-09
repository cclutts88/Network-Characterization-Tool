from __future__ import annotations

from app.scan_progress import (
    latest_nmap_stats,
    new_scan_progress,
    update_scan_progress,
)


def test_latest_nmap_stats_uses_the_newest_complete_status_line():
    output = """
Stats: 0:00:02 elapsed; 4 hosts completed (1 up), 12 undergoing SYN Stealth Scan
unrelated diagnostic text
Stats: 0:00:04 elapsed; 9 hosts completed (3 up), 7 undergoing Service Scan
"""

    assert latest_nmap_stats(output) == (9, 3)
    assert latest_nmap_stats("Nmap is starting") is None


def test_progress_clamps_nmap_counters_and_tracks_whole_scheduled_batch():
    progress = new_scan_progress(
        50,
        chunk_number=3,
        chunk_count=6,
        batch_hosts_total=256,
        batch_hosts_completed_before=100,
    )

    changed = update_scan_progress(
        progress,
        phase="nmap",
        hosts_completed=20,
        hosts_up=4,
        updated_at="2026-09-09T12:00:00+00:00",
    )

    assert changed is True
    assert progress["percent"] == 40.0
    assert progress["batch_hosts_completed"] == 120
    assert progress["batch_hosts_total"] == 256
    assert progress["batch_percent"] == 46.9

    update_scan_progress(progress, hosts_completed=999, hosts_up=999)
    assert progress["hosts_completed"] == 50
    assert progress["hosts_up"] == 50

