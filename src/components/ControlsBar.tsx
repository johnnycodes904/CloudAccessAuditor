import React from 'react';
import { FilterState, CloudProvider, IdentityType, RiskLevel } from '../types';
import { Search, Filter, Download, Upload, Shield, X } from 'lucide-react';

interface ControlsBarProps {
  filters: FilterState;
  onFilterChange: (newFilters: FilterState) => void;
  onOpenDropzone: () => void;
  onExportCsv: () => void;
  onExportJson: () => void;
  totalFilteredCount: number;
  totalCount: number;
  providerCounts: {
    all: number;
    aws: number;
    azure: number;
    gcp: number;
  };
}

export const ControlsBar: React.FC<ControlsBarProps> = ({
  filters,
  onFilterChange,
  onOpenDropzone,
  onExportCsv,
  onExportJson,
  totalFilteredCount,
  totalCount,
  providerCounts
}) => {
  const hasActiveFilters =
    filters.provider !== 'All' ||
    filters.identityType !== 'All' ||
    filters.riskLevel !== 'All' ||
    filters.complianceFramework !== 'All' ||
    filters.searchQuery !== '' ||
    filters.status !== 'All';

  const resetFilters = () => {
    onFilterChange({
      provider: 'All',
      identityType: 'All',
      riskLevel: 'All',
      complianceFramework: 'All',
      searchQuery: '',
      status: 'All'
    });
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm mb-6 space-y-4">
      {/* Top Row: Provider Tabs & Export Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        {/* Multi-Cloud Provider Tabs */}
        <div className="flex items-center flex-wrap gap-1.5 p-1 bg-slate-950/80 rounded-lg border border-slate-800/80 w-fit">
          <button
            type="button"
            onClick={() => onFilterChange({ ...filters, provider: 'All' })}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
              filters.provider === 'All'
                ? 'bg-slate-800 text-white shadow-sm ring-1 ring-slate-700'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            <span>All Clouds</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-700/60 text-[10px] text-slate-300">
              {providerCounts.all}
            </span>
          </button>

          <button
            type="button"
            onClick={() => onFilterChange({ ...filters, provider: 'AWS' })}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
              filters.provider === 'AWS'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm shadow-amber-950/40'
                : 'text-slate-400 hover:text-amber-300 hover:bg-slate-900'
            }`}
          >
            <img
              src="/assets/aws.svg"
              alt="AWS"
              className="h-3.5 w-3.5 object-contain"
              referrerPolicy="no-referrer"
            />
            <span>AWS</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-amber-300 font-mono">
              {providerCounts.aws}
            </span>
          </button>

          <button
            type="button"
            onClick={() => onFilterChange({ ...filters, provider: 'Azure' })}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
              filters.provider === 'Azure'
                ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40 shadow-sm shadow-blue-950/40'
                : 'text-slate-400 hover:text-blue-300 hover:bg-slate-900'
            }`}
          >
            <img
              src="/assets/azure.svg"
              alt="Azure"
              className="h-3.5 w-3.5 object-contain"
              referrerPolicy="no-referrer"
            />
            <span>Azure</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-blue-300 font-mono">
              {providerCounts.azure}
            </span>
          </button>

          <button
            type="button"
            onClick={() => onFilterChange({ ...filters, provider: 'GCP' })}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all flex items-center gap-1.5 ${
              filters.provider === 'GCP'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm shadow-emerald-950/40'
                : 'text-slate-400 hover:text-emerald-300 hover:bg-slate-900'
            }`}
          >
            <img
              src="/assets/gcp.svg"
              alt="GCP"
              className="h-3.5 w-3.5 object-contain"
              referrerPolicy="no-referrer"
            />
            <span>GCP</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-emerald-300 font-mono">
              {providerCounts.gcp}
            </span>
          </button>
        </div>

        {/* Ingest JSON and Export Controls */}
        <div className="flex items-center flex-wrap gap-2">
          <button
            type="button"
            onClick={onOpenDropzone}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/20 text-cyan-300 hover:bg-cyan-600/30 border border-cyan-500/30 text-xs font-medium transition-all shadow-sm"
          >
            <Upload className="h-3.5 w-3.5" />
            <span>Ingest JSON / Policy</span>
          </button>

          <button
            type="button"
            onClick={onExportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-all"
            title="Export full identity audit evidence to CSV"
          >
            <Download className="h-3.5 w-3.5 text-slate-400" />
            <span>Export Audit CSV</span>
          </button>

          <button
            type="button"
            onClick={onExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-all"
            title="Export structured JSON evidence for GRC"
          >
            <Shield className="h-3.5 w-3.5 text-slate-400" />
            <span>Evidence JSON</span>
          </button>
        </div>
      </div>

      {/* Bottom Row: Search & Specific Filter Dropdowns */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-3 pt-2 border-t border-slate-800/60 items-center">
        {/* Search Input */}
        <div className="lg:col-span-4 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={filters.searchQuery}
            onChange={(e) => onFilterChange({ ...filters, searchQuery: e.target.value })}
            placeholder="Search by identity name, scope, or role..."
            aria-label="Search identities by name, scope, or role"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500"
          />
          {filters.searchQuery && (
            <button
              onClick={() => onFilterChange({ ...filters, searchQuery: '' })}
              aria-label="Clear search query"
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Identity Type Filter */}
        <div className="lg:col-span-2">
          <select
            value={filters.identityType}
            onChange={(e) => onFilterChange({ ...filters, identityType: e.target.value as 'All' | IdentityType })}
            aria-label="Filter by identity type"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="All">Type: All (Human & Machine)</option>
            <option value="Machine">Machine (Service Acc / Role)</option>
            <option value="Human">Human Users</option>
          </select>
        </div>

        {/* Risk Level Filter */}
        <div className="lg:col-span-2">
          <select
            value={filters.riskLevel}
            onChange={(e) => onFilterChange({ ...filters, riskLevel: e.target.value as 'All' | RiskLevel })}
            aria-label="Filter by risk level"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="All">Risk: All Levels</option>
            <option value="Critical">Critical (≥ 80)</option>
            <option value="High">High (60 - 79)</option>
            <option value="Medium">Medium (30 - 59)</option>
            <option value="Low">Low (&lt; 30)</option>
          </select>
        </div>

        {/* Compliance Framework Filter */}
        <div className="lg:col-span-2">
          <select
            value={filters.complianceFramework}
            onChange={(e) => onFilterChange({ ...filters, complianceFramework: e.target.value as any })}
            aria-label="Filter by compliance framework"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="All">Framework: All Standards</option>
            <option value="SOC 2">SOC 2 (CC6.1 - CC6.3)</option>
            <option value="CIS Benchmarks">CIS Benchmarks (AWS/Az/GCP)</option>
          </select>
        </div>

        {/* Status Filter */}
        <div className="lg:col-span-2 flex items-center gap-2">
          <select
            value={filters.status}
            onChange={(e) => onFilterChange({ ...filters, status: e.target.value as any })}
            aria-label="Filter by status"
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="All">Status: All</option>
            <option value="Active">Active Violations</option>
            <option value="Remediated">Remediated</option>
          </select>

          {hasActiveFilters && (
            <button
              onClick={resetFilters}
              title="Reset all filters"
              aria-label="Reset all filters"
              className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 transition-colors flex-shrink-0"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Result feedback bar */}
      <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
        <div>
          Showing <span className="text-white font-semibold">{totalFilteredCount}</span> of{' '}
          <span className="text-slate-300">{totalCount}</span> identities
          {hasActiveFilters && <span className="ml-1 text-cyan-400 font-medium">(Filtered)</span>}
        </div>
        <div className="flex items-center gap-3 text-[11px] text-slate-400">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-rose-500"></span> Critical (≥80)
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-amber-500"></span> High (60-79)
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-yellow-500"></span> Medium (30-59)
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-emerald-500"></span> Low (&lt;30)
          </span>
        </div>
      </div>
    </div>
  );
};
