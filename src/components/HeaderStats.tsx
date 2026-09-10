import React from 'react';
import { CloudIdentity } from '../types';
import { ShieldCheck, ShieldAlert, Cpu, User, AlertTriangle, Layers } from 'lucide-react';

interface HeaderStatsProps {
  identities: CloudIdentity[];
}

export const HeaderStats: React.FC<HeaderStatsProps> = ({ identities }) => {
  const total = identities.length;
  const machineCount = identities.filter((i) => i.identityType === 'Machine').length;
  const humanCount = total - machineCount;
  const machinePercent = total > 0 ? Math.round((machineCount / total) * 100) : 0;

  const overPrivilegedCount = identities.filter((i) => i.violations.length > 0 && !i.remediated).length;
  const criticalCount = identities.filter((i) => i.riskLevel === 'Critical' && !i.remediated).length;
  const remediatedCount = identities.filter((i) => i.remediated).length;

  // Posture Score (100 = perfect, lower risk = higher posture score)
  const avgRisk = total > 0 ? Math.round(identities.reduce((acc, curr) => acc + (curr.remediated ? 15 : curr.riskScore), 0) / total) : 0;
  const postureScore = Math.max(0, 100 - avgRisk);

  const awsCount = identities.filter((i) => i.provider === 'AWS').length;
  const azureCount = identities.filter((i) => i.provider === 'Azure').length;
  const gcpCount = identities.filter((i) => i.provider === 'GCP').length;

  return (
    <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        {/* Top bar with Brand and Cloud Badges */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
              <ShieldCheck className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                  CloudAccessAuditor
                </h1>
                <span className="text-[11px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  CIEM Platform
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Multi-Cloud Least-Privilege Entitlement Governance & Blast-Radius Engine
              </p>
            </div>
          </div>

          {/* Provider Scope Pills */}
          <div className="flex items-center gap-2 text-xs">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300">
              <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse"></span>
              <span className="font-semibold">AWS:</span> {awsCount} identities
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-300">
              <span className="h-2 w-2 rounded-full bg-blue-400"></span>
              <span className="font-semibold">Azure:</span> {azureCount} identities
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
              <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
              <span className="font-semibold">GCP:</span> {gcpCount} identities
            </div>
          </div>
        </div>

        {/* 4 Primary Metric Stat Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 pt-4">
          {/* Total Monitored Identities */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-medium uppercase tracking-wider">Total Identities</span>
              <Layers className="h-4 w-4 text-cyan-400" />
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="text-2xl sm:text-3xl font-bold text-white tracking-tight">{total}</span>
              <span className="text-xs font-medium text-slate-400">Across 3 Clouds</span>
            </div>
            <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between border-t border-slate-800/60 pt-2">
              <span>{awsCount} AWS</span>
              <span>•</span>
              <span>{azureCount} Azure</span>
              <span>•</span>
              <span>{gcpCount} GCP</span>
            </div>
          </div>

          {/* Machine Identities % */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-medium uppercase tracking-wider">Machine Identities</span>
              <Cpu className="h-4 w-4 text-purple-400" />
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <div className="flex items-baseline gap-1.5">
                <span className="text-2xl sm:text-3xl font-bold text-white tracking-tight">{machinePercent}%</span>
                <span className="text-xs text-slate-400">ratio</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span className="flex items-center gap-1 text-purple-300">
                  <Cpu className="h-3 w-3" /> {machineCount}
                </span>
                <span className="flex items-center gap-1 text-slate-400">
                  <User className="h-3 w-3" /> {humanCount}
                </span>
              </div>
            </div>
            {/* Progress bar */}
            <div className="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-purple-500 h-full rounded-full transition-all duration-500"
                style={{ width: `${machinePercent}%` }}
              ></div>
            </div>
          </div>

          {/* Over-Privileged Count */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-medium uppercase tracking-wider">Over-Privileged</span>
              <AlertTriangle className="h-4 w-4 text-rose-400" />
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <div className="flex items-baseline gap-2">
                <span className="text-2xl sm:text-3xl font-bold text-rose-400 tracking-tight">
                  {overPrivilegedCount}
                </span>
                <span className="text-xs text-slate-400">identities</span>
              </div>
              {criticalCount > 0 && (
                <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse">
                  {criticalCount} Critical
                </span>
              )}
            </div>
            <div className="mt-2 text-[11px] text-slate-400 flex items-center justify-between border-t border-slate-800/60 pt-2">
              <span className="text-rose-400 font-medium">Excess Entitlements</span>
              {remediatedCount > 0 && (
                <span className="text-emerald-400 font-medium">{remediatedCount} Remediated</span>
              )}
            </div>
          </div>

          {/* Average Posture Score */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between text-slate-400">
              <span className="text-xs font-medium uppercase tracking-wider">Posture Score</span>
              <ShieldAlert
                className={`h-4 w-4 ${
                  postureScore >= 75 ? 'text-emerald-400' : postureScore >= 50 ? 'text-amber-400' : 'text-rose-400'
                }`}
              />
            </div>
            <div className="mt-2 flex items-baseline justify-between">
              <div className="flex items-baseline gap-1.5">
                <span
                  className={`text-2xl sm:text-3xl font-bold tracking-tight ${
                    postureScore >= 75 ? 'text-emerald-400' : postureScore >= 50 ? 'text-amber-400' : 'text-rose-400'
                  }`}
                >
                  {postureScore}
                </span>
                <span className="text-xs text-slate-400">/100</span>
              </div>
              <span
                className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                  postureScore >= 75
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : postureScore >= 50
                    ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                    : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                }`}
              >
                {postureScore >= 75 ? 'Healthy' : postureScore >= 50 ? 'Moderate Risk' : 'High Risk'}
              </span>
            </div>
            <div className="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  postureScore >= 75 ? 'bg-emerald-500' : postureScore >= 50 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${postureScore}%` }}
              ></div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
