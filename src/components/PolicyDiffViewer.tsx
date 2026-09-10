import React, { useState } from 'react';
import { Copy, Check, Split, Columns2, AlertTriangle, ShieldCheck } from 'lucide-react';
import { CloudProviderBadge } from './CloudProviderBadge';

interface PolicyDiffViewerProps {
  currentPolicy: string;
  recommendedPolicy: string;
  provider: 'AWS' | 'Azure' | 'GCP';
  identityName: string;
}

export const PolicyDiffViewer: React.FC<PolicyDiffViewerProps> = ({
  currentPolicy,
  recommendedPolicy,
  provider,
  identityName
}) => {
  const [viewMode, setViewMode] = useState<'sideBySide' | 'unified'>('sideBySide');
  const [copiedCurrent, setCopiedCurrent] = useState(false);
  const [copiedRecommended, setCopiedRecommended] = useState(false);

  const copyToClipboard = (text: string, isRecommended: boolean) => {
    navigator.clipboard.writeText(text);
    if (isRecommended) {
      setCopiedRecommended(true);
      setTimeout(() => setCopiedRecommended(false), 2000);
    } else {
      setCopiedCurrent(true);
      setTimeout(() => setCopiedCurrent(false), 2000);
    }
  };

  const currentLines = currentPolicy.split('\n');
  const recommendedLines = recommendedPolicy.split('\n');

  const isRiskyLine = (line: string): boolean => {
    const l = line.toLowerCase();
    return (
      l.includes('"*"') ||
      l.includes("'*'") ||
      l.includes('"action": "*"') ||
      l.includes('"resource": "*"') ||
      l.includes('"principal": "*"') ||
      l.includes('roles/owner') ||
      l.includes('roles/editor') ||
      l.includes('"owner"') ||
      l.includes('"contributor"') ||
      l.includes('s3:*') ||
      l.includes('kms:decrypt') ||
      l.includes('iampassrole') ||
      l.includes('createaccesskey')
    );
  };

  const isScopedLine = (line: string): boolean => {
    const l = line.toLowerCase();
    return (
      l.includes('condition') ||
      l.includes('multifactorauthpresent') ||
      l.includes('oidc-provider') ||
      l.includes('token.actions.githubusercontent.com') ||
      l.includes('resourcegroups') ||
      l.includes('container.developer') ||
      l.includes('bigquery.dataeditor') ||
      l.includes('key vault secrets user') ||
      l.includes('scoped') ||
      l.includes('fintech-k8s-backups')
    );
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden shadow-md">
      {/* Top Header Controls */}
      <div className="flex flex-wrap items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 text-xs">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-200">Policy Diff Engine</span>
          <CloudProviderBadge provider={provider} size="xs" />
          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-cyan-400 font-mono">
            Native Format
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center bg-slate-950 rounded-lg p-0.5 border border-slate-800">
            <button
              type="button"
              onClick={() => setViewMode('sideBySide')}
              className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1 transition-all ${
                viewMode === 'sideBySide'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Columns2 className="h-3 w-3" />
              <span>Side-by-Side</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode('unified')}
              className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1 transition-all ${
                viewMode === 'unified'
                  ? 'bg-slate-800 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Split className="h-3 w-3" />
              <span>Unified View</span>
            </button>
          </div>
        </div>
      </div>

      {/* Side-by-Side Diff Layout */}
      {viewMode === 'sideBySide' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-800 text-xs font-mono">
          {/* Left: Over-permissioned Current Policy */}
          <div className="flex flex-col">
            <div className="px-3 py-2 bg-rose-950/20 border-b border-slate-800/80 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-rose-400 font-medium">
                <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
                <span>Current Over-Permissioned Policy</span>
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(currentPolicy, false)}
                className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition-colors"
              >
                {copiedCurrent ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                <span>{copiedCurrent ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <div className="p-3 overflow-x-auto max-h-[380px] bg-slate-950/60 leading-relaxed">
              {currentLines.map((line, idx) => {
                const risky = isRiskyLine(line);
                return (
                  <div
                    key={`curr-${idx}`}
                    className={`flex items-start gap-2 py-0.5 px-1 rounded ${
                      risky ? 'bg-rose-950/40 text-rose-200 border-l-2 border-rose-500' : 'text-slate-300'
                    }`}
                  >
                    <span className="w-6 text-right select-none text-slate-600 flex-shrink-0 text-[10px]">
                      {idx + 1}
                    </span>
                    <pre className="whitespace-pre overflow-x-auto font-mono text-[11px]">
                      {line}
                    </pre>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Least-Privilege Scoped Policy */}
          <div className="flex flex-col">
            <div className="px-3 py-2 bg-emerald-950/20 border-b border-slate-800/80 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-emerald-400 font-medium">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                <span>Recommended Least-Privilege Policy</span>
              </div>
              <button
                type="button"
                onClick={() => copyToClipboard(recommendedPolicy, true)}
                className="flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-900/30 hover:bg-emerald-800/40 text-emerald-300 border border-emerald-500/30 text-[11px] transition-colors"
              >
                {copiedRecommended ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                <span>{copiedRecommended ? 'Copied' : 'Copy Scoped'}</span>
              </button>
            </div>

            <div className="p-3 overflow-x-auto max-h-[380px] bg-slate-950/60 leading-relaxed">
              {recommendedLines.map((line, idx) => {
                const scoped = isScopedLine(line);
                return (
                  <div
                    key={`rec-${idx}`}
                    className={`flex items-start gap-2 py-0.5 px-1 rounded ${
                      scoped ? 'bg-emerald-950/30 text-emerald-200 border-l-2 border-emerald-500' : 'text-slate-300'
                    }`}
                  >
                    <span className="w-6 text-right select-none text-slate-600 flex-shrink-0 text-[10px]">
                      {idx + 1}
                    </span>
                    <pre className="whitespace-pre overflow-x-auto font-mono text-[11px]">
                      {line}
                    </pre>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        /* Unified View Layout */
        <div className="p-3 text-xs font-mono max-h-[420px] overflow-y-auto bg-slate-950/90 leading-relaxed">
          <div className="mb-2 text-[11px] text-slate-400 border-b border-slate-800 pb-1">
            Unified Git-style diff representation for <span className="text-white">{identityName}</span>
          </div>

          <div className="text-slate-400 mb-2">@@ -1,{currentLines.length} +1,{recommendedLines.length} @@</div>

          {currentLines.map((line, idx) => (
            <div key={`u-curr-${idx}`} className="flex items-start gap-2 py-0.5 px-1 bg-rose-950/30 text-rose-300 font-mono text-[11px]">
              <span className="select-none text-rose-500 font-bold">-</span>
              <pre className="whitespace-pre overflow-x-auto font-mono">{line}</pre>
            </div>
          ))}

          <div className="my-1 border-t border-slate-800"></div>

          {recommendedLines.map((line, idx) => (
            <div key={`u-rec-${idx}`} className="flex items-start gap-2 py-0.5 px-1 bg-emerald-950/30 text-emerald-300 font-mono text-[11px]">
              <span className="select-none text-emerald-400 font-bold">+</span>
              <pre className="whitespace-pre overflow-x-auto font-mono">{line}</pre>
            </div>
          ))}
        </div>
      )}

      {/* Footer Diff Legend */}
      <div className="px-4 py-2 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-rose-500"></span>
            <span>Excess Entitlements / Wildcards (Over-Privileged)</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
            <span>Scoped Least-Privilege Granular Access</span>
          </span>
        </div>
        <span className="text-slate-500 hidden sm:inline">Zero-Trust CIEM Diff</span>
      </div>
    </div>
  );
};
