from __future__ import annotations

from fastapi.responses import Response


def scan_references_script() -> Response:
    """Return shared, presentation-only formatting for retained scan references."""
    return Response(
        r'''(() => {
  const GENERATED_SUFFIX = /(?:_|\s)+(?:\(S\)(?:_|\s)+)?\d{4}-\d{2}-\d{2}(?:_|\s)+\d{4}$/i;
  const CHUNK_SUFFIX = /(?:_|\s)+Chunk(?:_|\s)+\d+(?:_|\s)+of(?:_|\s)+\d+/i;

  function text(value) {
    return String(value ?? '').trim();
  }

  function humanize(value) {
    return text(value).replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
  }

  function primary(item = {}) {
    const explicit = text(item.name || item.campaign || item.logical_name);
    if (explicit) return humanize(explicit);
    let value = text(item.display_name || item.comparison_name || item.filename || 'Scan');
    value = value.replace(CHUNK_SUFFIX, '').replace(GENERATED_SUFFIX, '').replace(/(?:_|\s)+\(S\)$/i, '');
    return humanize(value) || 'Scan';
  }

  function formatTime(value) {
    const raw = text(value);
    if (!raw) return 'Time unavailable';
    const date = new Date(raw);
    if (Number.isNaN(date.getTime())) return raw;
    return date.toLocaleString([], {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: 'numeric', minute: '2-digit',
    });
  }

  function savedNetworks(item = {}) {
    const values = item.saved_networks || item.target_selection?.saved_networks || [];
    if (!Array.isArray(values)) return [];
    const seen = new Set();
    return values.filter(value => value && typeof value === 'object').filter(value => {
      const key = text(value.saved_network_id || value.name || value.cidr).toLowerCase();
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function scope(item = {}) {
    const networks = savedNetworks(item);
    const manual = item.manual_targets || item.target_selection?.manual_targets || [];
    const manualCount = Array.isArray(manual) ? manual.length : 0;
    if (networks.length) {
      const networkLabel = networks.length === 1
        ? humanize(networks[0].name || networks[0].cidr || 'Saved Network')
        : `${networks.length} Saved Networks`;
      return manualCount
        ? `${networkLabel} + ${manualCount} manual target${manualCount === 1 ? '' : 's'}`
        : networkLabel;
    }
    const values = item.scope?.targets || item.coverage?.targets || item.targets || [];
    if (Array.isArray(manual) && manual.length === 1) return text(manual[0]);
    if (Array.isArray(manual) && manual.length > 1 && manual.length <= 3) return `${manual.length} manual targets`;
    if (!Array.isArray(values) || !values.length) return 'Scope unavailable';
    if (values.length === 1) return text(values[0]);
    return `${values.length} target ranges`;
  }

  function mode(item = {}) {
    return item.scheduled || item.schedule_id || item.execution_method === 'scheduled'
      ? 'Scheduled'
      : 'Manual';
  }

  function profile(item = {}) {
    const name = text(item.profile || item.profile_name || item.coverage?.profile_name);
    const version = text(item.profile_version || item.coverage?.profile_version);
    return name ? `${name}${version ? ` v${version}` : ''}` : '';
  }

  function targets(item = {}) {
    const values = item.scope?.targets || item.coverage?.targets || item.targets || [];
    return Array.isArray(values) ? values.map(text).filter(Boolean) : [];
  }

  function reference(item = {}) {
    const completed = text(item.completed_at || item.created_at);
    const title = primary(item);
    const scopeLabel = scope(item);
    const timeLabel = formatTime(completed);
    const modeLabel = mode(item);
    const profileLabel = profile(item);
    const hostCount = item.host_count == null ? '' : `${Number(item.host_count).toLocaleString()} hosts`;
    const excluded = Number(item.scope?.excluded_address_count ?? item.coverage?.excluded_address_count ?? 0);
    const metadata = [profileLabel, hostCount, excluded ? `${excluded.toLocaleString()} excluded` : ''].filter(Boolean).join(' · ');
    const runId = text(item.selection_run_id || item.run_id || item.group_id);
    const artifact = text(item.display_name || item.filename);
    const fullTargets = targets(item);
    const detail = [
      artifact && artifact !== title ? `Artifact: ${artifact}` : '',
      completed ? `Recorded: ${completed}` : '',
      fullTargets.length ? `Full scope: ${fullTargets.join(', ')}` : '',
      runId ? `ID: ${runId.slice(0, 12)}` : '',
    ].filter(Boolean).join(' · ');
    return {
      primary: title,
      scope: scopeLabel,
      time: timeLabel,
      mode: modeLabel,
      profile: profileLabel,
      metadata,
      secondary: [scopeLabel, timeLabel, modeLabel].filter(Boolean).join(' · '),
      selection: [title, scopeLabel, timeLabel].filter(Boolean).join(' — '),
      detail,
    };
  }

  window.NCTScanReference = { formatTime, humanize, primary, reference, scope };
})();''',
        media_type="application/javascript",
    )
