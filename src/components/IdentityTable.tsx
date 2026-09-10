import React, { useState } from 'react';
import { CloudIdentity } from '../types';
import {
  Cpu,
  User,
  ShieldCheck,
  AlertTriangle,
  ChevronRight,
  Copy,
  Check,
  ArrowUpDown,
  Key,
  ShieldAlert,
  Lock
} from 'lucide-react';

interface IdentityTableProps {
  identities: CloudIdentity[];
  onSelectIdentity: (identity: CloudIdentity) => void;
  selectedIdentityId?: string;
}

type SortField = 'riskScore' | 'name' | 'provider' | 'violations';

export const IdentityTable: React.FC<IdentityTableProps> = ({
  identities,
  onSelectIdentity,
  selectedIdentityId
}) => {
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [copiedScope, setCopiedScope] = useState<string | null>(null);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const sortedIdentities = [...identities].sort((a, b) => {
    let comparison = 0;
    if (sortField === 'riskScore') {
      const scoreA = a.remediated ? 10 : a.riskScore;
      const scoreB = b.remediated ? 10 : b.riskScore;
      comparison = scoreA - scoreB;
    } else if (sortField === 'name') {
      comparison = a.name.localeCompare(b.name);
    } else if (sortField === 'provider') {
      comparison = a.provider.localeCompare(b.provider);
    } else if (sortField === 'violations') {
      comparison = a.violations.length - b.violations.length;
    }
    return sortDirection === 'asc' ? comparison : -comparison;
  });

  const copyScope = (e: React.MouseEvent, scope: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(scope);
    setCopiedScope(scope);
    setTimeout(() => setCopiedScope(null), 1500);
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold tracking-wider uppercase text-[11px]">
              <th
                onClick={() => handleSort('provider')}
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
              >
                <div className="flex items-center gap-1.5">
                  <span>Cloud Provider</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th
                onClick={() => handleSort('name')}
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
              >
                <div className="flex items-center gap-1.5">
                  <span>Identity & Type</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th className="py-3 px-4">Account / Project Scope</th>

              <th
                onClick={() => handleSort('riskScore')}
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
              >
                <div className="flex items-center gap-1.5">
                  <span>Risk Score</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th
                onClick={() => handleSort('violations')}
                className="py-3 px-4 cursor-pointer hover:text-white transition-colors"
              >
                <div className="flex items-center gap-1.5">
                  <span>Violations & Hygiene</span>
                  <ArrowUpDown className="h-3 w-3" />
                </div>
              </th>

              <th className="py-3 px-4">Compliance Tags</th>

              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800/60">
            {sortedIdentities.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <ShieldCheck className="h-8 w-8 text-slate-600" />
                    <p className="text-sm text-slate-400 font-medium">No identities matching current filter criteria</p>
                    <p className="text-xs text-slate-600">Try adjusting your search keywords, provider, or risk level</p>
                  </div>
                </td>
              </tr>
            ) : (
              sortedIdentities.map((item) => {
                const isSelected = item.id === selectedIdentityId;
                const effectiveScore = item.remediated ? 12 : item.riskScore;
                const effectiveLevel = item.remediated ? 'Low' : item.riskLevel;

                return (
                  <tr
                    key={item.id}
                    onClick={() => onSelectIdentity(item)}
                    className={`cursor-pointer transition-all hover:bg-slate-800/50 ${
                      isSelected ? 'bg-cyan-950/20 border-l-2 border-cyan-500' : ''
                    } ${item.remediated ? 'opacity-85' : ''}`}
                  >
                    {/* Provider */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        {item.provider === 'AWS' && (
                          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-300 font-semibold text-[11px]">
                            <span className="h-2 w-2 rounded-full bg-amber-400"></span>
                            <span>AWS</span>
                          </div>
                        )}
                        {item.provider === 'Azure' && (
                          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-blue-500/10 border border-blue-500/20 text-blue-300 font-semibold text-[11px]">
                            <span className="h-2 w-2 rounded-full bg-blue-400"></span>
                            <span>Azure</span>
                          </div>
                        )}
                        {item.provider === 'GCP' && (
                          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 font-semibold text-[11px]">
                            <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
                            <span>GCP</span>
                          </div>
                        )}
                      </div>
                    </td>

                    {/* Identity Name & Type */}
                    <td className="py-3.5 px-4">
                      <div className="flex flex-col">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-200 hover:text-cyan-400 transition-colors">
                            {item.name}
                          </span>
                          {item.remediated && (
                            <span className="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-medium border border-emerald-500/30">
                              Remediated
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 text-[11px] text-slate-400 mt-0.5">
                          <span className="flex items-center gap-1">
                            {item.identityType === 'Machine' ? (
                              <Cpu className="h-3 w-3 text-purple-400" />
                            ) : (
                              <User className="h-3 w-3 text-cyan-400" />
                            )}
                            <span>{item.identityType}</span>
                          </span>
                          <span>•</span>
                          <span className="text-slate-500">Active {item.lastActive}</span>
                        </div>
                      </div>
                    </td>

                    {/* Account / Scope */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-300">
                        <span className="truncate max-w-[180px] bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                          {item.scope}
                        </span>
                        <button
                          type="button"
                          onClick={(e) => copyScope(e, item.scope)}
                          className="p-1 rounded hover:bg-slate-800 text-slate-500 hover:text-slate-300 transition-colors"
                          title="Copy Scope ID"
                        >
                          {copiedScope === item.scope ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* Risk Score & Pill */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2.5">
                        <div className="flex flex-col">
                          <div className="flex items-center gap-1.5">
                            <span
                              className={`text-sm font-bold tracking-tight ${
                                effectiveScore >= 80
                                  ? 'text-rose-400'
                                  : effectiveScore >= 60
                                  ? 'text-amber-400'
                                  : effectiveScore >= 30
                                  ? 'text-yellow-400'
                                  : 'text-emerald-400'
                              }`}
                            >
                              {effectiveScore}
                            </span>
                            <span
                              className={`px-1.5 py-0.2 rounded text-[10px] font-semibold uppercase ${
                                effectiveLevel === 'Critical'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                  : effectiveLevel === 'High'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                  : effectiveLevel === 'Medium'
                                  ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              }`}
                            >
                              {effectiveLevel}
                            </span>
                          </div>
                          {/* Mini visual meter */}
                          <div className="w-20 bg-slate-800 rounded-full h-1 mt-1 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                effectiveScore >= 80
                                  ? 'bg-rose-500'
                                  : effectiveScore >= 60
                                  ? 'bg-amber-500'
                                  : effectiveScore >= 30
                                  ? 'bg-yellow-500'
                                  : 'bg-emerald-500'
                              }`}
                              style={{ width: `${effectiveScore}%` }}
                            ></div>
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Violations & Hygiene Indicators */}
                    <td className="py-3.5 px-4">
                      {item.violations.length === 0 ? (
                        <span className="flex items-center gap-1 text-emerald-400 text-xs font-medium">
                          <ShieldCheck className="h-3.5 w-3.5" />
                          <span>Compliant</span>
                        </span>
                      ) : (
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-1.5">
                            <span className="px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 text-[10px] font-semibold flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3 text-rose-400" />
                              {item.violations.length} {item.violations.length === 1 ? 'Violation' : 'Violations'}
                            </span>
                            {item.keyAgeDays !== undefined && item.keyAgeDays > 90 && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 text-[10px] font-mono flex items-center gap-1">
                                <Key className="h-3 w-3" /> Key {item.keyAgeDays}d
                              </span>
                            )}
                            {item.secretExpiryDays !== undefined && item.secretExpiryDays > 180 && (
                              <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 text-[10px] font-mono flex items-center gap-1">
                                <Lock className="h-3 w-3" /> Secret {item.secretExpiryDays}d
                              </span>
                            )}
                            {item.mfaEnabled === false && item.identityType === 'Human' && (
                              <span className="px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 text-[10px] flex items-center gap-1">
                                <ShieldAlert className="h-3 w-3" /> No MFA
                              </span>
                            )}
                          </div>
                          <span className="text-[10px] text-slate-400 truncate max-w-[240px]">
                            {item.violations[0]?.title}
                          </span>
                        </div>
                      )}
                    </td>

                    {/* Compliance Mapping Tags */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center flex-wrap gap-1">
                        {item.violations.flatMap((v) => v.complianceTags).length === 0 ? (
                          <span className="text-slate-500 text-[11px]">—</span>
                        ) : (
                          Array.from(
                            new Set(
                              item.violations.flatMap((v) =>
                                v.complianceTags.map((t) => `${t.framework === 'SOC 2' ? 'SOC2' : t.framework.split(' ')[1]} ${t.control}`)
                              )
                            )
                          )
                            .slice(0, 3)
                            .map((tag, idx) => (
                              <span
                                key={idx}
                                className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] font-medium"
                              >
                                {tag}
                              </span>
                            ))
                        )}
                      </div>
                    </td>

                    {/* Action Button */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIdentity(item);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-600/20 text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/30 text-xs font-medium transition-all group"
                      >
                        <span>{item.remediated ? 'Review' : 'Inspect & Remediate'}</span>
                        <ChevronRight className="h-3.5 w-3.5 text-slate-500 group-hover:text-cyan-300 group-hover:translate-x-0.5 transition-transform" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
