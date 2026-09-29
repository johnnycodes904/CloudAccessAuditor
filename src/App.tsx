/**
 * CloudAccessAuditor CIEM
 * Copyright (c) 2026. All Rights Reserved.
 * PROPRIETARY AND CONFIDENTIAL.
 * Unauthorized reproduction, copying, distribution, or commercial exploitation is strictly prohibited.
 */

import React, { useState, useMemo } from 'react';
import { CloudIdentity, FilterState } from './types';
import { INITIAL_IDENTITIES } from './data/mockIdentities';
import { calculateRiskLevel } from './utils/riskEngine';
import { HeaderStats } from './components/HeaderStats';
import { ControlsBar } from './components/ControlsBar';
import { IdentityTable } from './components/IdentityTable';
import { RemediationDrawer } from './components/RemediationDrawer';
import { JsonDropzoneModal } from './components/JsonDropzoneModal';
import { exportIdentitiesToCsv, exportIdentitiesToJson } from './utils/exportUtils';
import { ShieldCheck, CheckCircle2, X } from 'lucide-react';

export default function App() {
  const [identities, setIdentities] = useState<CloudIdentity[]>(INITIAL_IDENTITIES);
  const [selectedIdentity, setSelectedIdentity] = useState<CloudIdentity | null>(null);
  const [isDropzoneOpen, setIsDropzoneOpen] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const [filters, setFilters] = useState<FilterState>({
    provider: 'All',
    identityType: 'All',
    riskLevel: 'All',
    complianceFramework: 'All',
    searchQuery: '',
    status: 'All'
  });

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 4000);
  };

  // Provider counts for tab badges
  const providerCounts = useMemo(() => {
    return {
      all: identities.length,
      aws: identities.filter((i) => i.provider === 'AWS').length,
      azure: identities.filter((i) => i.provider === 'Azure').length,
      gcp: identities.filter((i) => i.provider === 'GCP').length
    };
  }, [identities]);

  // Filter logic
  const filteredIdentities = useMemo(() => {
    return identities.filter((item) => {
      // Provider filter
      if (filters.provider !== 'All' && item.provider !== filters.provider) {
        return false;
      }

      // Identity Type filter
      if (filters.identityType !== 'All' && item.identityType !== filters.identityType) {
        return false;
      }

      // Risk Level filter
      const effectiveLevel = item.remediated ? 'Low' : item.riskLevel;
      if (filters.riskLevel !== 'All' && effectiveLevel !== filters.riskLevel) {
        return false;
      }

      // Status filter
      if (filters.status === 'Active' && (item.violations.length === 0 || item.remediated)) {
        return false;
      }
      if (filters.status === 'Remediated' && !item.remediated) {
        return false;
      }

      // Compliance filter
      if (filters.complianceFramework !== 'All') {
        const hasTag = item.violations.some((v) =>
          v.complianceTags.some((t) => {
            if (filters.complianceFramework === 'SOC 2') {
              return t.framework === 'SOC 2';
            }
            if (filters.complianceFramework === 'CIS Benchmarks') {
              return t.framework.startsWith('CIS');
            }
            return false;
          })
        );
        if (!hasTag) return false;
      }

      // Search Query
      if (filters.searchQuery.trim() !== '') {
        const q = filters.searchQuery.toLowerCase();
        const matchesName = item.name.toLowerCase().includes(q);
        const matchesScope = item.scope.toLowerCase().includes(q);
        const matchesRole = item.rolesOrPolicies.some((r) => r.toLowerCase().includes(q));
        const matchesViolation = item.violations.some((v) => v.title.toLowerCase().includes(q) || v.code.toLowerCase().includes(q));
        if (!matchesName && !matchesScope && !matchesRole && !matchesViolation) {
          return false;
        }
      }

      return true;
    });
  }, [identities, filters]);

  // Interactive Remediation
  const handleApplyRemediation = (identityId: string) => {
    setIdentities((prev) =>
      prev.map((item) => {
        if (item.id === identityId) {
          return {
            ...item,
            originalRiskScore: item.originalRiskScore ?? item.riskScore,
            originalRiskLevel: item.originalRiskLevel ?? item.riskLevel,
            remediated: true,
            riskScore: 12,
            riskLevel: 'Low'
          };
        }
        return item;
      })
    );

    if (selectedIdentity && selectedIdentity.id === identityId) {
      setSelectedIdentity((prev) =>
        prev
          ? {
              ...prev,
              originalRiskScore: prev.originalRiskScore ?? prev.riskScore,
              originalRiskLevel: prev.originalRiskLevel ?? prev.riskLevel,
              remediated: true,
              riskScore: 12,
              riskLevel: 'Low'
            }
          : null
      );
    }

    showToast(`Successfully remediated "${selectedIdentity?.name || 'Identity'}". Risk score reduced to 12 (Low).`);
  };

  const handleRevertRemediation = (identityId: string) => {
    setIdentities((prev) =>
      prev.map((item) => {
        if (item.id === identityId) {
          const original = INITIAL_IDENTITIES.find((orig) => orig.id === identityId);
          const restoredScore = original ? original.riskScore : (item.originalRiskScore ?? 80);
          const restoredLevel = original ? original.riskLevel : (item.originalRiskLevel ?? calculateRiskLevel(restoredScore));
          return {
            ...item,
            remediated: false,
            riskScore: restoredScore,
            riskLevel: restoredLevel
          };
        }
        return item;
      })
    );

    if (selectedIdentity && selectedIdentity.id === identityId) {
      const original = INITIAL_IDENTITIES.find((orig) => orig.id === identityId);
      const restoredScore = original ? original.riskScore : (selectedIdentity.originalRiskScore ?? 80);
      const restoredLevel = original ? original.riskLevel : (selectedIdentity.originalRiskLevel ?? calculateRiskLevel(restoredScore));
      setSelectedIdentity((prev) =>
        prev
          ? {
              ...prev,
              remediated: false,
              riskScore: restoredScore,
              riskLevel: restoredLevel
            }
          : null
      );
    }

    showToast(`Reverted remediation for "${selectedIdentity?.name || 'Identity'}".`);
  };

  // Ingested identities from JSON Dropzone
  const handleIngestSuccess = (newIdentities: CloudIdentity[]) => {
    setIdentities((prev) => [...newIdentities, ...prev]);
    showToast(`Ingested ${newIdentities.length} new cloud identity into governance inventory.`);
    // Auto-open first ingested identity
    if (newIdentities.length > 0) {
      setSelectedIdentity(newIdentities[0]);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Banner Stats Header */}
      <HeaderStats identities={identities} />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Controls Bar */}
        <ControlsBar
          filters={filters}
          onFilterChange={setFilters}
          onOpenDropzone={() => setIsDropzoneOpen(true)}
          onExportCsv={() => exportIdentitiesToCsv(filteredIdentities)}
          onExportJson={() => exportIdentitiesToJson(filteredIdentities)}
          totalFilteredCount={filteredIdentities.length}
          totalCount={identities.length}
          providerCounts={providerCounts}
        />

        {/* Identity Table */}
        <IdentityTable
          identities={filteredIdentities}
          onSelectIdentity={(idObj) => setSelectedIdentity(idObj)}
          selectedIdentityId={selectedIdentity?.id}
        />
      </main>

      {/* Slide-over Remediation Drawer / Modal */}
      <RemediationDrawer
        identity={selectedIdentity}
        onClose={() => setSelectedIdentity(null)}
        onApplyRemediation={handleApplyRemediation}
        onRevertRemediation={handleRevertRemediation}
      />

      {/* JSON Dropzone Modal */}
      <JsonDropzoneModal
        isOpen={isDropzoneOpen}
        onClose={() => setIsDropzoneOpen(false)}
        onIngestSuccess={handleIngestSuccess}
      />

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 animate-in slide-in-from-bottom-3 duration-200">
          <div className="flex items-center gap-2.5 px-4 py-3 rounded-xl bg-slate-900 border border-emerald-500/40 text-xs font-medium text-white shadow-xl shadow-slate-950/80">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 flex-shrink-0" />
            <span>{toastMessage}</span>
            <button
              type="button"
              onClick={() => setToastMessage(null)}
              className="ml-2 text-slate-500 hover:text-slate-300"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Subtle Footer */}
      <footer className="border-t border-slate-900 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span className="flex items-center gap-1.5">
            <ShieldCheck className="h-4 w-4 text-cyan-500" />
            <span>CloudAccessAuditor CIEM v2.4</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-400">Proprietary & Confidential</span>
            <span className="text-slate-600">|</span>
            <span>All Rights Reserved</span>
          </span>
          <span className="text-[11px] text-slate-500">
            Compliant with SOC 2 CC6.1–3 • CIS AWS 3.0 • CIS Azure 2.1 • CIS GCP 3.0
          </span>
        </div>
      </footer>
    </div>
  );
}
