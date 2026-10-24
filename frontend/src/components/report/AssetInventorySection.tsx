import React from 'react';
import { Server } from 'lucide-react';
import type { AssessmentReportData } from '../../services/reportExport';

interface AssetInventorySectionProps {
  inventory: AssessmentReportData['asset_inventory'];
}

export const AssetInventorySection: React.FC<AssetInventorySectionProps> = ({ inventory }) => {
  const hasAssets = inventory.total > 0;

  return (
    <div className="report-section" data-testid="report-section-assets">
      <h3 className="section-title text-sm row" style={{ fontWeight: 700, gap: '0.5rem', marginBottom: '0.75rem' }}>
        <Server size={16} style={{ color: 'var(--color-accent)' }} />
        <span>3. Asset Inventory Summary ({inventory.total})</span>
      </h3>

      {!hasAssets ? (
        <div style={{ padding: '1.5rem', textAlign: 'center', backgroundColor: 'var(--color-surface-subtle)', borderRadius: '4px', border: '1px dashed var(--color-border)', fontSize: '0.8125rem', color: 'var(--color-text-muted)' }}>
          Zero assets discovered or assigned to this assessment record.
        </div>
      ) : (
        <div className="table-container table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Asset ID</th>
                <th>Hostname / Address</th>
                <th>Type</th>
                <th>Discovery Source</th>
                <th>Services Observed</th>
              </tr>
            </thead>
            <tbody>
              {inventory.items.map((ast) => (
                <tr key={ast.id}>
                  <td className="font-mono" style={{ fontWeight: 600 }}>{ast.id}</td>
                  <td className="font-mono" style={{ color: 'var(--color-accent)' }}>{ast.hostname_or_address}</td>
                  <td>
                    <span className="subtle-box text-xs" style={{ textTransform: 'uppercase', fontWeight: 600, padding: '0.1rem 0.4rem' }}>
                      {ast.asset_type}
                    </span>
                  </td>
                  <td className="text-sm">{ast.source}</td>
                  <td className="text-sm">
                    {ast.services.length === 0 ? (
                      <span className="dim">None</span>
                    ) : (
                      ast.services.map((s, idx) => (
                        <div key={idx} className="font-mono text-xs">
                          {s.port}/{s.protocol} {s.banner ? `(${s.banner})` : ''}
                        </div>
                      ))
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
