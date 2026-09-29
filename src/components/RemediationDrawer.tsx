import React, { useState, useEffect } from 'react';
import { CloudIdentity } from '../types';
import { PolicyDiffViewer } from './PolicyDiffViewer';
import { CloudProviderBadge } from './CloudProviderBadge';
import {
  X,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Terminal,
  FileCheck,
  Check,
  Copy,
  Cpu,
  User,
  RotateCcw,
  Sparkles,
  Layers,
  Code
} from 'lucide-react';

interface RemediationDrawerProps {
  identity: CloudIdentity | null;
  onClose: () => void;
  onApplyRemediation: (identityId: string) => void;
  onRevertRemediation: (identityId: string) => void;
}

type TabType = 'diff' | 'blastRadius' | 'script' | 'compliance';

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  identity,
  onClose,
  onApplyRemediation,
  onRevertRemediation
}) => {
  const [activeTab, setActiveTab] = useState<TabType>('diff');
  const [copiedCli, setCopiedCli] = useState(false);
  const [copiedTf, setCopiedTf] = useState(false);

  // Close on Escape key
  useEffect(() => {
    if (!identity) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [identity, onClose]);

  if (!identity) return null;

  const copyCli = () => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard
        .writeText(identity.remediationCommand)
        .then(() => {
          setCopiedCli(true);
          setTimeout(() => setCopiedCli(false), 2000);
        })
        .catch((err) => {
          console.warn('Clipboard write failed:', err);
        });
    }
  };

  const copyTf = () => {
    if (identity.remediationTerraform && navigator?.clipboard?.writeText) {
      navigator.clipboard
        .writeText(identity.remediationTerraform)
        .then(() => {
          setCopiedTf(true);
          setTimeout(() => setCopiedTf(false), 2000);
        })
        .catch((err) => {
          console.warn('Clipboard write failed:', err);
        });
    }
  };

  const effectiveScore = identity.remediated ? 12 : identity.riskScore;
  const effectiveLevel = identity.remediated ? 'Low' : identity.riskLevel;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-identity-title"
      className="fixed inset-0 z-50 flex items-center justify-end bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200"
    >
      <div className="w-full max-w-4xl h-full bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col overflow-hidden">
        {/* Modal/Drawer Top Bar */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/90 flex items-start justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center flex-wrap gap-2">
              <CloudProviderBadge provider={identity.provider} size="sm" showFullName={true} />

              <span className="flex items-center gap-1 text-xs text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700 font-mono">
                {identity.identityType === 'Machine' ? (
                  <Cpu className="h-3 w-3 text-purple-400" />
                ) : (
                  <User className="h-3 w-3 text-cyan-400" />
                )}
                <span>{identity.identityType} Identity</span>
              </span>

              <span className="text-xs text-slate-400 font-mono bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                Scope: {identity.scope}
              </span>
            </div>

            <div className="flex items-center gap-3">
              <h2 id="drawer-identity-title" className="text-lg font-bold text-white tracking-tight font-mono">{identity.name}</h2>
              {identity.remediated ? (
                <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-semibold flex items-center gap-1">
                  <ShieldCheck className="h-3.5 w-3.5" /> Remediated
                </span>
              ) : (
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase flex items-center gap-1 ${
                    effectiveLevel === 'Critical'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse'
                      : effectiveLevel === 'High'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      : effectiveLevel === 'Medium'
                      ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  }`}
                >
                  <AlertTriangle className="h-3 w-3" /> Risk Score: {effectiveScore} ({effectiveLevel})
                </span>
              )}
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-5 pt-3 border-b border-slate-800 bg-slate-950/40 text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('diff')}
            className={`px-3.5 py-2.5 font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'diff'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="h-3.5 w-3.5" />
            <span>Policy Diff & Remediation</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('blastRadius')}
            className={`px-3.5 py-2.5 font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'blastRadius'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Flame className="h-3.5 w-3.5 text-rose-400" />
            <span>Blast Radius & What Breaks</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('script')}
            className={`px-3.5 py-2.5 font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'script'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="h-3.5 w-3.5 text-amber-400" />
            <span>CLI & IaC Script</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('compliance')}
            className={`px-3.5 py-2.5 font-semibold border-b-2 transition-all flex items-center gap-2 ${
              activeTab === 'compliance'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCheck className="h-3.5 w-3.5 text-emerald-400" />
            <span>Compliance Mapping ({identity.violations.flatMap((v) => v.complianceTags).length})</span>
          </button>
        </div>

        {/* Tab Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {/* TAB 1: Policy Diff & Remediation */}
          {activeTab === 'diff' && (
            <div className="space-y-5">
              {/* Remediation Action Banner */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 to-slate-800/90 border border-slate-700/70 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    {identity.remediated ? (
                      <>
                        <ShieldCheck className="h-4 w-4 text-emerald-400" />
                        <span>Least-Privilege Policy Applied & Enforced</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-4 w-4 text-amber-400" />
                        <span>Over-Privileged Identity Requires Scoping</span>
                      </>
                    )}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    {identity.remediated
                      ? 'This identity has been remediated. Risk score has dropped to Low and unnecessary wildcards have been revoked.'
                      : 'Review the side-by-side policy diff below to inspect the replacement least-privilege policy.'}
                  </p>
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                  {identity.remediated ? (
                    <button
                      type="button"
                      onClick={() => onRevertRemediation(identity.id)}
                      className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                      <span>Revert Remediation</span>
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={() => onApplyRemediation(identity.id)}
                      className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20 text-xs font-semibold flex items-center gap-1.5 transition-all"
                    >
                      <ShieldCheck className="h-4 w-4" />
                      <span>Apply Least-Privilege Remediation</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Detected Violations Highlights */}
              {identity.violations.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Active Entitlement Violations ({identity.violations.length})
                  </h4>
                  <div className="grid grid-cols-1 gap-2.5">
                    {identity.violations.map((viol) => (
                      <div
                        key={viol.id}
                        className="p-3 rounded-lg bg-slate-950 border border-rose-900/40 text-xs space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-rose-300 flex items-center gap-1.5">
                            <span className="h-2 w-2 rounded-full bg-rose-500"></span>
                            [{viol.code}] {viol.title}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-rose-950/60 text-rose-400 text-[10px] font-mono border border-rose-800/40">
                            {viol.severity}
                          </span>
                        </div>
                        <p className="text-slate-300 text-[11px] leading-relaxed">{viol.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Side-by-Side Policy Diff Viewer */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Side-by-Side Entitlement Diff (Provider Native Format)
                </h4>
                <PolicyDiffViewer
                  currentPolicy={identity.currentPolicy}
                  recommendedPolicy={identity.recommendedPolicy}
                  provider={identity.provider}
                  identityName={identity.name}
                />
              </div>
            </div>
          )}

          {/* TAB 2: Blast Radius & What Breaks */}
          {activeTab === 'blastRadius' && (
            <div className="space-y-6">
              {/* Critical What Breaks Callout Box */}
              <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 text-xs space-y-2">
                <div className="flex items-center gap-2 text-amber-300 font-bold text-sm">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  <span>"What Breaks" Blast Radius Impact Assessment</span>
                </div>
                <p className="text-slate-200 leading-relaxed font-medium">
                  {identity.blastRadiusDetails.whatBreaksAnalysis}
                </p>
                <div className="mt-2 pt-2 border-t border-amber-500/20 flex items-center gap-1.5 text-amber-400 text-[11px]">
                  <span className="font-semibold">Safety Mitigation Note:</span>
                  <span>{identity.blastRadiusDetails.remediationSafetyNote}</span>
                </div>
              </div>

              {/* Services Exposed Grid */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Layers className="h-3.5 w-3.5 text-cyan-400" />
                  <span>Exposed Cloud Infrastructure Services</span>
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {identity.blastRadiusDetails.servicesExposed.map((srv, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 flex items-center gap-2"
                    >
                      <span className="h-1.5 w-1.5 rounded-full bg-rose-400"></span>
                      <span>{srv}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Privilege Escalation Vectors */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Flame className="h-3.5 w-3.5 text-rose-400" />
                  <span>Potential Privilege Escalation Pathways</span>
                </h4>
                <div className="space-y-2">
                  {identity.blastRadiusDetails.privilegeEscalationVectors.map((vec, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950 border border-rose-950/60 text-xs font-mono text-rose-300 flex items-center gap-2"
                    >
                      <span className="text-rose-500">➔</span>
                      <span>{vec}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Impacted Resource Scope */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                <span className="text-slate-400 text-[11px] font-medium">Impacted Target Resource URI:</span>
                <p className="font-mono text-cyan-400">{identity.blastRadiusDetails.impactedResources}</p>
              </div>
            </div>
          )}

          {/* TAB 3: Remediation Script (CLI & IaC) */}
          {activeTab === 'script' && (
            <div className="space-y-5">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                    <Terminal className="h-3.5 w-3.5 text-amber-400" />
                    <span>Native Provider CLI Execution Command</span>
                  </h4>
                  <button
                    type="button"
                    onClick={copyCli}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
                  >
                    {copiedCli ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copiedCli ? 'Copied Command' : 'Copy CLI'}</span>
                  </button>
                </div>
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-amber-300 overflow-x-auto leading-relaxed">
                  <pre className="whitespace-pre-wrap">{identity.remediationCommand}</pre>
                </div>
              </div>

              {identity.remediationTerraform && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Code className="h-3.5 w-3.5 text-purple-400" />
                      <span>Terraform / Infrastructure-as-Code (IaC) Scoping</span>
                    </h4>
                    <button
                      type="button"
                      onClick={copyTf}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
                    >
                      {copiedTf ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      <span>{copiedTf ? 'Copied IaC' : 'Copy IaC'}</span>
                    </button>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-purple-300 overflow-x-auto leading-relaxed">
                    <pre className="whitespace-pre-wrap">{identity.remediationTerraform}</pre>
                  </div>
                </div>
              )}

              <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-slate-400">
                <p>
                  Run this command in your CI/CD deployment pipeline or authorized administrator terminal to replace
                  the over-privileged policy in your cloud account.
                </p>
              </div>
            </div>
          )}

          {/* TAB 4: Compliance Evidence Mapping */}
          {activeTab === 'compliance' && (
            <div className="space-y-4">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-300">
                This entitlement audit evidence maps findings directly to SOC 2 Trust Services Criteria and CIS
                Foundation Benchmarks for automated GRC auditor verification.
              </div>

              <div className="space-y-3">
                {identity.violations.flatMap((v) => v.complianceTags).map((tag, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 font-mono text-[11px] border border-cyan-800/50">
                          {tag.framework} {tag.control}
                        </span>
                        <span>{tag.title}</span>
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">Benchmark Reference</span>
                    </div>
                    <p className="text-slate-300 leading-relaxed text-[11px]">{tag.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Drawer Bottom Bar with Quick Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/90 flex items-center justify-between">
          <div className="text-xs text-slate-400">
            Current Status:{' '}
            <span className={identity.remediated ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
              {identity.remediated ? 'Remediated & Enforced' : 'Over-Privileged (Action Required)'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {identity.remediated ? (
              <button
                type="button"
                onClick={() => onRevertRemediation(identity.id)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              >
                Revert
              </button>
            ) : (
              <button
                type="button"
                onClick={() => onApplyRemediation(identity.id)}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-md transition-all"
              >
                <ShieldCheck className="h-4 w-4" />
                <span>Apply Remediation</span>
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
