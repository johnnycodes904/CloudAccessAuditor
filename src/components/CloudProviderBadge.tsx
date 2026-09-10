import React from 'react';
import { CloudProvider } from '../types';

interface CloudProviderBadgeProps {
  provider: CloudProvider;
  size?: 'xs' | 'sm' | 'md' | 'lg';
  showFullName?: boolean;
  className?: string;
  count?: number;
}

export const CloudProviderBadge: React.FC<CloudProviderBadgeProps> = ({
  provider,
  size = 'sm',
  showFullName = false,
  className = '',
  count
}) => {
  const config = {
    AWS: {
      name: 'AWS',
      fullName: 'Amazon Web Services',
      logo: '/assets/aws.svg',
      containerClass:
        'bg-amber-500/10 text-amber-300 border-amber-500/30 hover:bg-amber-500/15 shadow-sm shadow-amber-950/20',
      logoBg: 'bg-slate-900/90 border border-amber-500/30',
      textClass: 'font-semibold tracking-wide text-amber-300',
      countClass: 'bg-amber-950/80 text-amber-200 border-amber-500/30'
    },
    Azure: {
      name: 'Azure',
      fullName: 'Microsoft Azure',
      logo: '/assets/azure.svg',
      containerClass:
        'bg-blue-500/10 text-blue-300 border-blue-500/30 hover:bg-blue-500/15 shadow-sm shadow-blue-950/20',
      logoBg: 'bg-slate-900/90 border border-blue-500/30',
      textClass: 'font-semibold tracking-wide text-blue-300',
      countClass: 'bg-blue-950/80 text-blue-200 border-blue-500/30'
    },
    GCP: {
      name: 'GCP',
      fullName: 'Google Cloud Platform',
      logo: '/assets/gcp.svg',
      containerClass:
        'bg-emerald-500/10 text-emerald-300 border-emerald-500/30 hover:bg-emerald-500/15 shadow-sm shadow-emerald-950/20',
      logoBg: 'bg-slate-900/90 border border-emerald-500/30',
      textClass: 'font-semibold tracking-wide text-emerald-300',
      countClass: 'bg-emerald-950/80 text-emerald-200 border-emerald-500/30'
    }
  }[provider];

  const sizeStyles = {
    xs: {
      badge: 'px-1.5 py-0.5 text-[10px] gap-1 rounded',
      iconContainer: 'h-3.5 w-3.5 p-0.5 rounded',
      icon: 'h-2.5 w-2.5'
    },
    sm: {
      badge: 'px-2 py-0.5 text-[11px] gap-1.5 rounded-md',
      iconContainer: 'h-4 w-4 p-0.5 rounded',
      icon: 'h-3 w-3'
    },
    md: {
      badge: 'px-2.5 py-1 text-xs gap-2 rounded-lg',
      iconContainer: 'h-5 w-5 p-0.5 rounded-md',
      icon: 'h-3.5 w-3.5'
    },
    lg: {
      badge: 'px-3 py-1.5 text-xs font-semibold gap-2.5 rounded-lg',
      iconContainer: 'h-6 w-6 p-1 rounded-md',
      icon: 'h-4 w-4'
    }
  }[size];

  return (
    <div
      className={`inline-flex items-center border transition-all select-none ${config.containerClass} ${sizeStyles.badge} ${className}`}
      title={`${config.fullName} (${config.name})`}
    >
      {/* Cloud Logo Container */}
      <span
        className={`flex items-center justify-center flex-shrink-0 ${config.logoBg} ${sizeStyles.iconContainer}`}
      >
        <img
          src={config.logo}
          alt={`${provider} logo`}
          className={`${sizeStyles.icon} object-contain`}
          referrerPolicy="no-referrer"
          loading="lazy"
        />
      </span>

      {/* Cloud Provider Name */}
      <span className={config.textClass}>
        {showFullName ? config.fullName : config.name}
      </span>

      {/* Optional Count Pill */}
      {count !== undefined && (
        <span
          className={`ml-0.5 px-1.5 py-0.2 rounded font-mono text-[10px] font-semibold border ${config.countClass}`}
        >
          {count}
        </span>
      )}
    </div>
  );
};
