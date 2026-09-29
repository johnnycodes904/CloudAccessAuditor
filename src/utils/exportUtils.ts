import { CloudIdentity } from '../types';

/**
 * Sanitizes a string value for safe CSV output, preventing Formula Injection (CWE-1236).
 * If a value starts with formula characters (=, +, -, @, \t, \r), it prepends a single quote.
 * Quotes are escaped by doubling them according to RFC 4180.
 */
function sanitizeCsvValue(val: unknown): string {
  if (val === null || val === undefined) return '""';
  const str = String(val);
  const trimmed = str.trimStart();
  // Prevent Excel / Sheets formula execution on untrusted strings
  const isFormula = /^[=+\-@\t\r]/.test(trimmed);
  const safeStr = isFormula ? `'${str}` : str;
  return `"${safeStr.replace(/"/g, '""')}"`;
}

/**
 * Exports a list of CloudIdentities to an RFC 4180 compliant CSV file with formula sanitization.
 *
 * @param identities - List of cloud identities to export
 * @param filename - Target download file name
 */
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
      sanitizeCsvValue(item.name),
      sanitizeCsvValue(item.provider),
      sanitizeCsvValue(item.identityType),
      sanitizeCsvValue(item.scope),
      item.riskScore,
      sanitizeCsvValue(item.riskLevel),
      sanitizeCsvValue(item.remediated ? 'Remediated' : item.violations.length > 0 ? 'Over-Privileged' : 'Compliant'),
      item.violations.length,
      sanitizeCsvValue(violationCodes),
      sanitizeCsvValue(soc2Tags),
      sanitizeCsvValue(cisTags),
      sanitizeCsvValue(item.mfaEnabled === undefined ? 'N/A' : item.mfaEnabled ? 'Yes' : 'No'),
      sanitizeCsvValue(credAge),
      sanitizeCsvValue(item.lastActive),
      sanitizeCsvValue(nowIso)
    ].join(',');
  });

  const csvContent = [headers.join(','), ...rows].join('\n');
  downloadBlob(csvContent, filename, 'text/csv;charset=utf-8;');
}

/**
 * Exports a structured JSON audit evidence file for GRC reporting and compliance archives.
 *
 * @param identities - List of cloud identities to export
 * @param filename - Target download file name
 */
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

/**
 * Triggers a browser file download using Blob and temporarily attached anchor element.
 * Defers URL.revokeObjectURL to avoid race condition where download stream is aborted prematurely.
 */
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
  // Defer revocation to prevent early cancellation in WebKit / Chromium
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 200);
}
