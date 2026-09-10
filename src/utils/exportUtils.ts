import { CloudIdentity } from '../types';

export function exportIdentitiesToCsv(identities: CloudIdentity[], filename = 'cloud-access-auditor-evidence.csv') {
  const headers = [
    'Identity Name',
    'Provider',
    'Identity Type',
    'Scope / Account',
    'Risk Score',
    'Risk Level',
    'Status',
    'Violation Count',
    'Violations (Codes & Titles)',
    'SOC 2 Controls',
    'CIS Benchmarks',
    'MFA Enabled',
    'Credential Age (Days)',
    'Last Active',
    'Audit Timestamp'
  ];

  const nowIso = new Date().toISOString();

  const rows = identities.map((item) => {
    const violationCodes = item.violations.map((v) => `[${v.code}] ${v.title}`).join(' | ');

    const soc2Tags = Array.from(
      new Set(
        item.violations.flatMap((v) =>
          v.complianceTags.filter((t) => t.framework === 'SOC 2').map((t) => `${t.framework} ${t.control}`)
        )
      )
    ).join('; ');

    const cisTags = Array.from(
      new Set(
        item.violations.flatMap((v) =>
          v.complianceTags.filter((t) => t.framework.startsWith('CIS')).map((t) => `${t.framework} §${t.control}`)
        )
      )
    ).join('; ');

    const credAge = item.keyAgeDays ? `${item.keyAgeDays}d key` : item.secretExpiryDays ? `${item.secretExpiryDays}d secret` : 'N/A';

    return [
      `"${item.name.replace(/"/g, '""')}"`,
      `"${item.provider}"`,
      `"${item.identityType}"`,
      `"${item.scope.replace(/"/g, '""')}"`,
      item.riskScore,
      `"${item.riskLevel}"`,
      item.remediated ? '"Remediated"' : item.violations.length > 0 ? '"Over-Privileged"' : '"Compliant"',
      item.violations.length,
      `"${violationCodes.replace(/"/g, '""')}"`,
      `"${soc2Tags.replace(/"/g, '""')}"`,
      `"${cisTags.replace(/"/g, '""')}"`,
      item.mfaEnabled === undefined ? '"N/A"' : item.mfaEnabled ? '"Yes"' : '"No"',
      `"${credAge}"`,
      `"${item.lastActive}"`,
      `"${nowIso}"`
    ].join(',');
  });

  const csvContent = [headers.join(','), ...rows].join('\n');
  downloadBlob(csvContent, filename, 'text/csv;charset=utf-8;');
}

export function exportIdentitiesToJson(identities: CloudIdentity[], filename = 'cloud-access-auditor-report.json') {
  const payload = {
    auditReport: {
      generatedAt: new Date().toISOString(),
      tool: 'CloudAccessAuditor CIEM',
      totalIdentities: identities.length,
      overPrivilegedCount: identities.filter((i) => i.violations.length > 0 && !i.remediated).length,
      averageRiskScore: Math.round(identities.reduce((acc, curr) => acc + curr.riskScore, 0) / (identities.length || 1)),
      frameworkCoverage: ['SOC 2 Trust Services Criteria CC6.1, CC6.2, CC6.3', 'CIS AWS Benchmark v3.0', 'CIS Microsoft Azure Benchmark v2.1', 'CIS Google Cloud Platform Benchmark v3.0'],
      identities
    }
  };

  const jsonStr = JSON.stringify(payload, null, 2);
  downloadBlob(jsonStr, filename, 'application/json;charset=utf-8;');
}

function downloadBlob(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
