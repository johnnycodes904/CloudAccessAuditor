export type CloudProvider = 'AWS' | 'Azure' | 'GCP';

export type IdentityType = 'Human' | 'Machine';

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export interface ComplianceTag {
  framework: 'SOC 2' | 'CIS AWS 3.0' | 'CIS Azure 2.1' | 'CIS GCP 3.0';
  control: string;
  title: string;
  description: string;
}

export interface Violation {
  id: string;
  code: string;
  title: string;
  ruleType: string;
  severity: RiskLevel;
  description: string;
  complianceTags: ComplianceTag[];
  blastRadiusImpact: string;
  whatBreaks: string;
}

export interface BlastRadiusDetails {
  servicesExposed: string[];
  privilegeEscalationVectors: string[];
  impactedResources: string;
  whatBreaksAnalysis: string;
  remediationSafetyNote: string;
}

export interface CloudIdentity {
  id: string;
  name: string;
  provider: CloudProvider;
  identityType: IdentityType;
  scope: string; // e.g., "110293847561 (us-east-1)" or "sub-0a81-core-infrastructure" or "prj-fintech-core-prod"
  accountOrSubscriptionId: string;
  rolesOrPolicies: string[];
  riskScore: number; // 1 - 100
  riskLevel: RiskLevel;
  violations: Violation[];
  lastActive: string;
  mfaEnabled?: boolean;
  keyAgeDays?: number;
  secretExpiryDays?: number;
  currentPolicy: string;
  recommendedPolicy: string;
  remediationCommand: string;
  remediationTerraform?: string;
  remediated: boolean;
  originalRiskScore?: number;
  originalRiskLevel?: RiskLevel;
  blastRadiusDetails: BlastRadiusDetails;
}

export interface FilterState {
  provider: 'All' | CloudProvider;
  identityType: 'All' | IdentityType;
  riskLevel: 'All' | RiskLevel;
  complianceFramework: 'All' | 'SOC 2' | 'CIS Benchmarks';
  searchQuery: string;
  status: 'All' | 'Active' | 'Remediated';
}
