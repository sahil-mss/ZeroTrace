import React, { useState } from 'react';
import { useApp } from '../context/useApp';
import { Server, Globe, Cpu } from 'lucide-react';

export const AssetsPage: React.FC = () => {
  const { assets, currentAssessmentId, globalSearch } = useApp();
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [localSearch, setLocalSearch] = useState<string>('');

  const currentAssets = assets.filter((a) => a.assessment_id === currentAssessmentId);

  const filteredAssets = currentAssets.filter((asset) => {
    // Type filter
    if (typeFilter !== 'all' && asset.asset_type !== typeFilter) return false;

    // Search query
    const query = (localSearch || globalSearch).toLowerCase().trim();
    if (!query) return true;

    return (
      asset.hostname_or_address.toLowerCase().includes(query) ||
      asset.source.toLowerCase().includes(query) ||
      asset.discovered_services.some(
        (s) =>
          s.port.toString().includes(query) ||
          (s.service_name && s.service_name.toLowerCase().includes(query)) ||
          (s.banner && s.banner.toLowerCase().includes(query))
      )
    );
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="h1">Discovered Assets & Services</h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--color-text-muted)', marginTop: '0.2rem' }}>
            Empirical reconnaissance findings, host footprints, and discovered network listeners.
          </p>
        </div>

        {/* Filter Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <select
            className="input-select"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            aria-label="Filter by asset type"
          >
            <option value="all">All Asset Types</option>
            <option value="web_app">Web Application</option>
            <option value="api_endpoint">API Endpoint</option>
            <option value="service">Network Service</option>
          </select>

          <input
            type="text"
            className="input-text"
            placeholder="Filter assets..."
            value={localSearch}
            onChange={(e) => setLocalSearch(e.target.value)}
            style={{ width: '200px' }}
          />
        </div>
      </div>

      {/* Asset Inventory Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Asset ID</th>
              <th>Hostname / Address</th>
              <th>Asset Classification</th>
              <th>Discovered Services & Ports</th>
              <th>Recon Provenance</th>
              <th>Observed At</th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--color-text-dim)' }}>
                  No in-scope assets match the active criteria.
                </td>
              </tr>
            ) : (
              filteredAssets.map((asset) => (
                <tr key={asset.id}>
                  <td className="font-mono" style={{ fontSize: '0.78rem', width: '110px' }}>
                    {asset.id}
                  </td>
                  <td>
                    <div className="font-mono" style={{ fontWeight: 600, color: 'var(--color-text-main)' }}>
                      {asset.hostname_or_address}
                    </div>
                  </td>
                  <td style={{ width: '160px' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.35rem',
                        fontSize: '0.75rem',
                        textTransform: 'uppercase',
                        fontWeight: 600,
                        color: 'var(--color-text-muted)',
                        backgroundColor: 'var(--color-surface-subtle)',
                        padding: '0.2rem 0.5rem',
                        borderRadius: '3px',
                        border: '1px solid var(--color-border)',
                      }}
                    >
                      {asset.asset_type === 'web_app' ? (
                        <Globe size={12} />
                      ) : asset.asset_type === 'api_endpoint' ? (
                        <Cpu size={12} />
                      ) : (
                        <Server size={12} />
                      )}
                      <span>{asset.asset_type.replace('_', ' ')}</span>
                    </span>
                  </td>
                  <td>
                    {asset.discovered_services.length === 0 ? (
                      <span style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
                        No open ports detected
                      </span>
                    ) : (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                        {asset.discovered_services.map((srv, idx) => (
                          <span
                            key={idx}
                            className="font-mono"
                            style={{
                              fontSize: '0.72rem',
                              backgroundColor: 'var(--color-surface-hover)',
                              border: '1px solid var(--color-border)',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '3px',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.3rem',
                            }}
                          >
                            <span style={{ fontWeight: 700, color: 'var(--color-accent)' }}>
                              {srv.port}/{srv.protocol}
                            </span>
                            {srv.service_name && (
                              <span style={{ color: 'var(--color-text-muted)' }}>({srv.service_name})</span>
                            )}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)' }}>
                    {asset.source}
                  </td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--color-text-dim)' }}>
                    {new Date(asset.observed_at).toLocaleTimeString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
