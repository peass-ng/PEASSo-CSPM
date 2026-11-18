import { useEffect, useState } from 'react';
import { request } from './api';
import { findingGroupPath } from './GroupedFindingEvidence';
import type { Finding } from './types';
import { foundSecretValues } from './foundSecretValue';

export function PrivateSecretEvidence({ finding, scanId }: { finding: Finding; scanId: string }) {
  const [data, setData] = useState(finding.secret_evidence);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  useEffect(() => { setData(finding.secret_evidence); }, [finding.secret_evidence]);
  if (!data) return null;
  async function more() {
    if (!data || data.next_offset == null) return;
    setLoading(true); setError(false);
    try {
      const path = finding.grouped ? findingGroupPath(scanId, finding) : `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(finding.id)}`;
      const next = await request<Finding>(`${path}${path.includes('?') ? '&' : '?'}secret_offset=${data.next_offset}`);
      const page = next.secret_evidence;
      if (!page || page.status !== 'available') { setError(true); return; }
      const matches = data.matches.map(match => ({ ...match, locations: [...match.locations] }));
      for (const match of page.matches) {
        const prior = matches.find(row => row.fingerprint === match.fingerprint);
        if (prior) prior.locations.push(...match.locations);
        else matches.push(match);
      }
      setData({ ...page, matches });
    } catch { setError(true); }
    finally { setLoading(false); }
  }
  return <section className="finding-detail-section" aria-label="Matched secret values">
    <h3>Matched secret values</h3>
    {data.message && <p>{data.message}</p>}
    {data.matches.map(match => <div key={match.fingerprint}>
      {match.locations.some(location => location.location_kind === 'detector_composite') && <p>Complete match reported by the detector. This representation was not found verbatim in the inspected bytes; observed components are listed separately.</p>}
      {match.locations.some(location => location.location_kind === 'detector_decoded') && <p>Decoded match reported by the detector. The value was not found verbatim in the inspected bytes.</p>}
      <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{match.value}</pre>
      {match.locations.map((location, index) => <dl className="finding-detail-metadata" key={index}>
        <dt>Resource</dt><dd>{location.resource_id || 'Not retained'}</dd>
        {location.scope && <><dt>Scope</dt><dd>{location.scope}</dd></>}
        {['detector_composite', 'detector_decoded'].includes(location.location_kind || '')
          ? <><dt>Scanned input</dt><dd style={{ overflowWrap: 'anywhere' }}>{location.detector_input_path || 'Not retained'}</dd><dt>Observed file or path</dt><dd>{location.location_kind === 'detector_composite' ? 'Not asserted for this detector-composed representation' : 'Not asserted for this decoded-only value'}</dd></>
          : <><dt>File or path</dt><dd style={{ overflowWrap: 'anywhere' }}>{location.path || 'Not retained'}</dd></>}
        {location.field && <><dt>Native field</dt><dd>{location.field}</dd></>}
        <dt>Line</dt><dd>{location.line ?? 'Unknown — no original file line was reported'}</dd>
        {location.image_digest && <><dt>Image digest</dt><dd>{location.image_digest}</dd></>}
        {location.layer && <><dt>Layer</dt><dd>{location.layer}</dd></>}
        {location.source && <><dt>Source</dt><dd>{location.source}</dd></>}
      </dl>)}
    </div>)}
    {data.complete === false && <p>Private evidence capture was incomplete; some locations or values may be unavailable.</p>}
    {data.next_offset != null && <button disabled={loading} onClick={more}>{loading ? 'Loading…' : 'Show more matched values and locations'}</button>}
    {error && <p role="alert">Private matched values could not be loaded. Try again.</p>}
  </section>;
}

/** Found values carried on the finding itself, shown in clear text so they can be rotated. */
export function FoundSecretValues({ evidence }: { evidence: unknown }) {
  const values = foundSecretValues(evidence);
  if (!values.length) return null;
  return <section className="finding-detail-section" aria-label="Found secret values">
    <h3>Found secret values</h3>
    <p>Rotate these credentials; they were found in scanned content and were not validated.</p>
    {values.map(found => <div key={found.fingerprint}>
      <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{found.value}</pre>
      {found.value_truncated && <p>Only the first {found.value.length} characters were retained.</p>}
      {found.context && <><p>Matched in:</p><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{found.context}</pre></>}
    </div>)}
  </section>;
}
