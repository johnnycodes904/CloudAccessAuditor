import { CloudIdentity, CloudProvider, IdentityType, RiskLevel, Violation, ComplianceTag } from '../types';

export interface IngestResult {
  success: boolean;
  providerDetected: CloudProvider | 'Unified' | 'Unknown';
  identities: CloudIdentity[];
  message: string;
}

export function detectProviderSchema(rawJson: unknown): { provider: CloudProvider | 'Unified' | 'Unknown'; confidence: string } {
  if (!rawJson || typeof rawJson !== 'object') {
    return { provider: 'Unknown', confidence: 'Invalid JSON payload' };
  }

  // Check for Unified / Batch schema
  if (Array.isArray(rawJson)) {
    if (rawJson.length > 0 && ('provider' in rawJson[0] || 'riskScore' in rawJson[0])) {
      return { provider: 'Unified', confidence: 'Detected array of unified CloudAccessAuditor identities' };
    }
  }

  const obj = rawJson as Record<string, unknown>;

  if ('identities' in obj && Array.isArray(obj.identities)) {
    return { provider: 'Unified', confidence: 'Detected unified CIEM multi-cloud manifest' };
  }

  const jsonStr = JSON.stringify(obj);

  // AWS detection
  const hasAwsKeys = 'Statement' in obj || 'PolicyDocument' in obj || 'RoleName' in obj || 'AssumeRolePolicyDocument' in obj;
  const hasAwsTerms = jsonStr.includes('arn:aws:iam') || jsonStr.includes('sts:AssumeRole') || jsonStr.includes('aws:MultiFactorAuthPresent');
  if (hasAwsKeys || hasAwsTerms) {
    return { provider: 'AWS', confidence: 'Detected AWS IAM Policy / Role Document schema' };
  }

  // Azure detection
  const hasAzureKeys = 'roleAssignments' in obj || 'roleDefinitionName' in obj || 'subscriptionId' in obj || 'servicePrincipal' in obj;
  const hasAzureTerms = jsonStr.includes('/subscriptions/') || jsonStr.includes('Microsoft.Authorization') || jsonStr.includes('onmicrosoft.com');
  if (hasAzureKeys || hasAzureTerms) {
    return { provider: 'Azure', confidence: 'Detected Azure Entra ID / RBAC Role Assignment schema' };
  }

  // GCP detection
  const hasGcpKeys = 'bindings' in obj || 'serviceAccountEmail' in obj || 'projectId' in obj;
  const hasGcpTerms = jsonStr.includes('roles/') || jsonStr.includes('iam.gserviceaccount.com') || jsonStr.includes('projects/');
  if (hasGcpKeys || hasGcpTerms) {
    return { provider: 'GCP', confidence: 'Detected Google Cloud IAM Policy Binding schema' };
  }

  return { provider: 'Unknown', confidence: 'Could not automatically identify provider schema' };
}

export function parseAndScoreIngestedJson(rawJson: unknown): IngestResult {
  const { provider } = detectProviderSchema(rawJson);

  try {
    if (provider === 'Unified') {
      const list = Array.isArray(rawJson) ? rawJson : (rawJson as { identities: unknown[] }).identities;
      const parsed = list.map((item: any, idx: number) => normalizeIdentity(item, idx));
      return {
        success: true,
        providerDetected: 'Unified',
        identities: parsed,
        message: `Successfully ingested ${parsed.length} identities from unified audit schema.`
      };
    }

    if (provider === 'AWS') {
      const identity = parseAwsJson(rawJson);
      return {
        success: true,
        providerDetected: 'AWS',
        identities: [identity],
        message: `Parsed AWS IAM identity "${identity.name}" with risk score ${identity.riskScore} (${identity.riskLevel}).`
      };
    }

    if (provider === 'Azure') {
      const identity = parseAzureJson(rawJson);
      return {
        success: true,
        providerDetected: 'Azure',
        identities: [identity],
        message: `Parsed Azure Entra identity "${identity.name}" with risk score ${identity.riskScore} (${identity.riskLevel}).`
      };
    }

    if (provider === 'GCP') {
      const identity = parseGcpJson(rawJson);
      return {
        success: true,
        providerDetected: 'GCP',
        identities: [identity],
        message: `Parsed GCP Cloud IAM identity "${identity.name}" with risk score ${identity.riskScore} (${identity.riskLevel}).`
      };
    }

    return {
      success: false,
      providerDetected: 'Unknown',
      identities: [],
      message: 'Unrecognized cloud policy format. Please ensure the JSON contains valid AWS IAM, Azure RBAC, or GCP IAM structures.'
    };
  } catch (err: any) {
    return {
      success: false,
      providerDetected: 'Unknown',
      identities: [],
      message: `Failed to parse policy document: ${err?.message || 'Syntax error'}`
    };
  }
}

function normalizeIdentity(item: any, index: number): CloudIdentity {
  const riskScore = typeof item.riskScore === 'number' ? item.riskScore : 50;
  const riskLevel = calculateRiskLevel(riskScore);

  return {
    id: item.id || `custom-id-${Date.now()}-${index}`,
    name: item.name || 'imported-cloud-identity',
    provider: (item.provider as CloudProvider) || 'AWS',
    identityType: (item.identityType as IdentityType) || 'Machine',
    scope: item.scope || 'imported-scope',
    accountOrSubscriptionId: item.accountOrSubscriptionId || item.scope || 'scope-id',
    rolesOrPolicies: Array.isArray(item.rolesOrPolicies) ? item.rolesOrPolicies : ['CustomPolicy'],
    riskScore,
    riskLevel,
    violations: Array.isArray(item.violations) ? item.violations : [],
    lastActive: item.lastActive || 'Just now',
    mfaEnabled: item.mfaEnabled ?? false,
    keyAgeDays: item.keyAgeDays,
    secretExpiryDays: item.secretExpiryDays,
    currentPolicy: typeof item.currentPolicy === 'string' ? item.currentPolicy : JSON.stringify(item.currentPolicy || {}, null, 2),
    recommendedPolicy: typeof item.recommendedPolicy === 'string' ? item.recommendedPolicy : JSON.stringify(item.recommendedPolicy || {}, null, 2),
    remediationCommand: item.remediationCommand || '# Apply least-privilege scoping',
    remediationTerraform: item.remediationTerraform,
    remediated: Boolean(item.remediated),
    blastRadiusDetails: item.blastRadiusDetails || {
      servicesExposed: ['Imported Cloud Resources'],
      privilegeEscalationVectors: ['Review individual API permissions'],
      impactedResources: item.scope || 'Cloud Account',
      whatBreaksAnalysis: 'Ensure dependent microservices have access before revoking broad permissions.',
      remediationSafetyNote: 'Audit application logs prior to policy downgrade.'
    }
  };
}

export function calculateRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

function parseAwsJson(raw: any): CloudIdentity {
  const jsonStr = JSON.stringify(raw);
  const statements = raw.Statement || raw.PolicyDocument?.Statement || [];
  const violations: Violation[] = [];
  let baseScore = 15;

  const hasWildcardAction = statements.some((s: any) => {
    const act = s.Action;
    const res = s.Resource;
    return (act === '*' || (Array.isArray(act) && act.includes('*'))) && (res === '*' || (Array.isArray(res) && res.includes('*')));
  }) || jsonStr.includes('"Action":"*"') || jsonStr.includes('"Action": "*"');

  const hasUnrestrictedAssume = jsonStr.includes('sts:AssumeRole') && (jsonStr.includes('"Principal":"*"') || jsonStr.includes('"Principal": "*"') || jsonStr.includes('"Principal": "*"'));

  const roleName = raw.RoleName || raw.UserName || raw.IdentityName || 'imported-aws-iam-role';
  const isHuman = roleName.includes('user') || roleName.includes('@') || Boolean(raw.UserName);

  if (hasWildcardAction) {
    baseScore += 50;
    violations.push({
      id: `viol-${Date.now()}-1`,
      code: 'AWS-IAM-WILDCARD-FULL-ADMIN',
      title: 'Full Wildcard Administrator Privileges (*:*)',
      ruleType: 'Wildcard Policy',
      severity: 'Critical',
      description: 'IAM Policy grants Action: "*" on Resource: "*", allowing destructive operations and full account takeover.',
      complianceTags: [
        { framework: 'SOC 2', control: 'CC6.1', title: 'Logical Access Controls', description: 'Restricts logical access to authorized workloads.' },
        { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Enforces scoped privileges.' },
        { framework: 'CIS AWS 3.0', control: '1.16', title: 'Avoid Full Admin Policies', description: 'Ensure IAM policies do not grant unrestricted Action: *.' }
      ],
      blastRadiusImpact: 'Full access to all AWS resources and encryption keys in the target account.',
      whatBreaks: 'Restricting to specific services may break unforeseen deployment steps unless pre-scoped.'
    });
  }

  if (hasUnrestrictedAssume) {
    baseScore += 35;
    violations.push({
      id: `viol-${Date.now()}-2`,
      code: 'AWS-IAM-UNRESTRICTED-ASSUME',
      title: 'Unrestricted sts:AssumeRole Trust Policy',
      ruleType: 'Unrestricted AssumeRole',
      severity: 'Critical',
      description: 'Trust policy allows any external AWS principal to assume the role without external ID conditions.',
      complianceTags: [
        { framework: 'SOC 2', control: 'CC6.3', title: 'Delegation Safeguards', description: 'Guards against cross-account delegation risks.' },
        { framework: 'CIS AWS 3.0', control: '1.20', title: 'External Trust Boundaries', description: 'Prevent cross-account delegation without condition checks.' }
      ],
      blastRadiusImpact: 'Permits cross-account identity impersonation without authentication challenge.',
      whatBreaks: 'Third-party integrations relying on broad assume role without external IDs.'
    });
  }

  const riskScore = Math.min(100, Math.max(10, baseScore));
  const riskLevel = calculateRiskLevel(riskScore);

  const formattedCurrent = JSON.stringify(raw, null, 2);
  const recommended = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ScopedWorkloadPermissions",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "cloudwatch:PutMetricData"
      ],
      "Resource": [
        "arn:aws:s3:::company-scoped-storage/*"
      ]
    }
  ]
}`;

  return {
    id: `aws-custom-${Date.now()}`,
    name: roleName,
    provider: 'AWS',
    identityType: isHuman ? 'Human' : 'Machine',
    scope: raw.AccountId ? `${raw.AccountId} (us-east-1)` : '123456789012 (us-east-1)',
    accountOrSubscriptionId: raw.AccountId || '123456789012',
    rolesOrPolicies: [raw.PolicyName || 'ImportedIAMPolicy'],
    riskScore,
    riskLevel,
    violations,
    lastActive: 'Just now (Imported)',
    mfaEnabled: isHuman ? false : undefined,
    currentPolicy: formattedCurrent,
    recommendedPolicy: recommended,
    remediationCommand: `aws iam put-role-policy --role-name ${roleName} --policy-name ScopedLeastPrivilege --policy-document file://scoped.json`,
    remediated: false,
    blastRadiusDetails: {
      servicesExposed: hasWildcardAction ? ['All AWS Services', 'IAM', 'S3', 'RDS', 'KMS'] : ['Scoped AWS Services'],
      privilegeEscalationVectors: hasWildcardAction ? ['iam:PassRole', 'iam:CreateAccessKey'] : ['None identified'],
      impactedResources: `arn:aws:iam::123456789012:role/${roleName}`,
      whatBreaksAnalysis: 'Switching to granular S3 and CloudWatch access prevents account takeover while maintaining core functionality.',
      remediationSafetyNote: 'Review CloudTrail Access Advisor logs for the past 90 days before applying.'
    }
  };
}

function parseAzureJson(raw: any): CloudIdentity {
  const jsonStr = JSON.stringify(raw);
  const violations: Violation[] = [];
  let baseScore = 20;

  const roleName = raw.roleDefinitionName || raw.roleName || (jsonStr.includes('"Owner"') ? 'Owner' : 'Contributor');
  const isOwner = roleName.toLowerCase().includes('owner') || jsonStr.includes('"Owner"');
  const isContributor = roleName.toLowerCase().includes('contributor') || jsonStr.includes('"Contributor"');
  const isSubLevel = jsonStr.includes('/subscriptions/') && !jsonStr.includes('resourceGroups');

  const name = raw.displayName || raw.name || raw.appId || 'imported-azure-service-principal';
  const isHuman = name.includes('@') || name.includes('user');

  if ((isOwner || isContributor) && (isSubLevel || raw.scope?.startsWith('/subscriptions/'))) {
    baseScore += isOwner ? 55 : 40;
    violations.push({
      id: `viol-${Date.now()}-az-1`,
      code: isOwner ? 'AZURE-RBAC-SUBSCRIPTION-OWNER' : 'AZURE-RBAC-SUBSCRIPTION-CONTRIBUTOR',
      title: `${isOwner ? 'Owner' : 'Contributor'} Role Assigned at Subscription Scope`,
      ruleType: 'Subscription Owner/Contributor',
      severity: isOwner ? 'Critical' : 'High',
      description: `Service Principal has ${roleName} assigned at the root subscription level instead of scoped to a specific resource group.`,
      complianceTags: [
        { framework: 'SOC 2', control: 'CC6.1', title: 'Logical Access', description: 'Prevent broad ownership permissions on workloads.' },
        { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Scope service principal role assignments.' },
        { framework: 'CIS Azure 2.1', control: '1.23', title: 'Avoid Subscription Owners', description: 'Service principals must not have Owner role at Subscription scope.' }
      ],
      blastRadiusImpact: 'Attacker with leaked secret can destroy all resource groups, modify network firewalls, and tamper with logs.',
      whatBreaks: 'Resource group creation outside the target resource group will be denied.'
    });
  }

  const secretDays = typeof raw.secretAgeDays === 'number' ? raw.secretAgeDays : 210;
  if (secretDays > 180) {
    baseScore += 25;
    violations.push({
      id: `viol-${Date.now()}-az-2`,
      code: 'AZURE-ENTRA-LONG-LIVED-SECRET',
      title: `Client Secret Age (${secretDays} Days) Exceeds 180-Day Benchmark`,
      ruleType: 'Long-Lived Client Secret',
      severity: 'High',
      description: 'App registration client secret has not been rotated for over 180 days, presenting risk of persistent unauthorized access.',
      complianceTags: [
        { framework: 'SOC 2', control: 'CC6.3', title: 'Credential Hygiene', description: 'Mandates rotation intervals for cryptographic keys and secrets.' },
        { framework: 'CIS Azure 2.1', control: '1.2', title: 'Ensure Client Secrets Expire <= 180 Days', description: 'Rotate all application client credentials regularly.' }
      ],
      blastRadiusImpact: 'Prolonged exposure window if secret was committed to build artifacts.',
      whatBreaks: 'Invalidating secret without distributing new one breaks CI pipelines.'
    });
  }

  const riskScore = Math.min(100, Math.max(10, baseScore));
  const riskLevel = calculateRiskLevel(riskScore);

  return {
    id: `az-custom-${Date.now()}`,
    name,
    provider: 'Azure',
    identityType: isHuman ? 'Human' : 'Machine',
    scope: raw.subscriptionId || 'sub-enterprise-core-imported',
    accountOrSubscriptionId: raw.subscriptionId || 'sub-enterprise-core-imported',
    rolesOrPolicies: [roleName],
    riskScore,
    riskLevel,
    violations,
    lastActive: 'Just now (Imported)',
    secretExpiryDays: secretDays,
    currentPolicy: JSON.stringify(raw, null, 2),
    recommendedPolicy: `// Scoped Resource Group Assignment
resource "azurerm_role_assignment" "scoped_workload" {
  scope                = "/subscriptions/${raw.subscriptionId || 'sub-enterprise-core'}/resourceGroups/rg-workload-prod"
  role_definition_name = "Contributor"
  principal_id         = "${raw.principalId || '00000000-0000-0000-0000-000000000000'}"
}`,
    remediationCommand: `az role assignment delete --assignee ${raw.principalId || name} --role "${roleName}" --scope "/subscriptions/${raw.subscriptionId || 'sub-enterprise-core'}"\naz role assignment create --assignee ${raw.principalId || name} --role "Contributor" --scope "/subscriptions/${raw.subscriptionId || 'sub-enterprise-core'}/resourceGroups/rg-workload-prod"`,
    remediated: false,
    blastRadiusDetails: {
      servicesExposed: ['All Subscription Resources', 'Virtual Networks', 'Key Vaults'],
      privilegeEscalationVectors: ['Microsoft.Authorization/roleAssignments/write'],
      impactedResources: `/subscriptions/${raw.subscriptionId || 'sub-enterprise-core'}`,
      whatBreaksAnalysis: 'Scope role assignment to rg-workload-prod to prevent tampering with other business unit resources.',
      remediationSafetyNote: 'Verify Azure Activity Log to confirm all resources currently touched by this identity.'
    }
  };
}

function parseGcpJson(raw: any): CloudIdentity {
  const jsonStr = JSON.stringify(raw);
  const violations: Violation[] = [];
  let baseScore = 20;

  const isOwner = jsonStr.includes('roles/owner');
  const isEditor = jsonStr.includes('roles/editor');

  const name = raw.serviceAccountEmail || raw.name || (raw.bindings?.[0]?.members?.[0]?.replace('serviceAccount:', '')) || 'imported-gcp-service-account@iam.gserviceaccount.com';
  const isHuman = name.includes('user:') || (!name.includes('@') && !name.includes('serviceaccount'));

  if (isOwner || isEditor) {
    baseScore += isOwner ? 60 : 45;
    violations.push({
      id: `viol-${Date.now()}-gcp-1`,
      code: isOwner ? 'GCP-IAM-PRIMITIVE-OWNER-ROOT' : 'GCP-IAM-PRIMITIVE-EDITOR-ROOT',
      title: `Primitive ${isOwner ? 'roles/owner' : 'roles/editor'} Assigned at Project Root`,
      ruleType: 'Primitive Owner/Editor Role',
      severity: isOwner ? 'Critical' : 'High',
      description: `Service Account has primitive ${isOwner ? 'roles/owner' : 'roles/editor'} bound at project level, granting broad destructive capabilities.`,
      complianceTags: [
        { framework: 'SOC 2', control: 'CC6.1', title: 'Access Controls', description: 'Disallow primitive project roles for machine identities.' },
        { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Use predefined granular roles.' },
        { framework: 'CIS GCP 3.0', control: isOwner ? '1.4' : '1.5', title: `Ensure No Service Accounts Have ${isOwner ? 'roles/owner' : 'roles/editor'}`, description: 'Never bind primitive roles to automated workloads.' }
      ],
      blastRadiusImpact: 'Full project takeover including Cloud KMS, Cloud Spanner, and GKE cluster control planes.',
      whatBreaks: 'Dynamic project-level infrastructure deployment if granular roles lack specific API permissions.'
    });
  }

  const keyAge = typeof raw.keyAgeDays === 'number' ? raw.keyAgeDays : 135;
  if (keyAge > 90) {
    baseScore += 25;
    violations.push({
      id: `viol-${Date.now()}-gcp-2`,
      code: 'GCP-IAM-KEY-AGE-OVER-90-DAYS',
      title: `User-Managed Key Age (${keyAge} Days) Exceeds 90-Day Rotation Limit`,
      ruleType: 'Stale Service Account Key',
      severity: 'High',
      description: 'Service account private key has been active for more than 90 days without key rotation.',
      complianceTags: [
        { framework: 'SOC 2', control: 'CC6.3', title: 'Key Rotation Policy', description: 'Requires private key rotation within 90 days.' },
        { framework: 'CIS GCP 3.0', control: '1.7', title: 'Ensure Service Account Keys Are Rotated Every 90 Days', description: 'Automate or enforce regular key rotation.' }
      ],
      blastRadiusImpact: 'Increased risk of key leakage from build systems or developer laptops.',
      whatBreaks: 'Immediate key deletion breaks workloads using the old key.'
    });
  }

  const riskScore = Math.min(100, Math.max(10, baseScore));
  const riskLevel = calculateRiskLevel(riskScore);

  const projectId = raw.projectId || 'prj-imported-gcp-workload';

  return {
    id: `gcp-custom-${Date.now()}`,
    name,
    provider: 'GCP',
    identityType: isHuman ? 'Human' : 'Machine',
    scope: projectId,
    accountOrSubscriptionId: projectId,
    rolesOrPolicies: isOwner ? ['roles/owner'] : isEditor ? ['roles/editor'] : ['roles/viewer'],
    riskScore,
    riskLevel,
    violations,
    lastActive: 'Just now (Imported)',
    keyAgeDays: keyAge,
    currentPolicy: JSON.stringify(raw, null, 2),
    recommendedPolicy: `// Scoped Predefined GCP Roles
{
  "bindings": [
    {
      "role": "roles/container.developer",
      "members": [
        "serviceAccount:${name}"
      ]
    },
    {
      "role": "roles/clouddeploy.releaser",
      "members": [
        "serviceAccount:${name}"
      ]
    }
  ]
}`,
    remediationCommand: `gcloud projects remove-iam-policy-binding ${projectId} --member="serviceAccount:${name}" --role="${isOwner ? 'roles/owner' : 'roles/editor'}"\ngcloud projects add-iam-policy-binding ${projectId} --member="serviceAccount:${name}" --role="roles/container.developer"`,
    remediated: false,
    blastRadiusDetails: {
      servicesExposed: ['All GCP Services in Project', 'Cloud Storage', 'Cloud SQL', 'GKE'],
      privilegeEscalationVectors: ['resourcemanager.projects.setIamPolicy'],
      impactedResources: `projects/${projectId}`,
      whatBreaksAnalysis: 'Switching to container.developer and clouddeploy.releaser allows CI/CD to push images and roll out deployments without broad project ownership.',
      remediationSafetyNote: 'Consider Workload Identity Federation instead of static JSON service account keys.'
    }
  };
}

// Sample JSON payloads for quick test dropzones
export const SAMPLE_PAYLOADS = {
  awsWildcard: {
    Version: "2012-10-17",
    RoleName: "custom-pipeline-runner",
    AccountId: "987654321098",
    Statement: [
      {
        Sid: "WildcardFullAdmin",
        Effect: "Allow",
        Action: "*",
        Resource: "*"
      },
      {
        Sid: "ExternalAssumeRole",
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Principal: "*"
      }
    ]
  },
  azureOwner: {
    displayName: "devops-cluster-agent",
    appId: "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    subscriptionId: "sub-9911-banking-core",
    roleDefinitionName: "Owner",
    scope: "/subscriptions/sub-9911-banking-core",
    secretAgeDays: 380,
    roleAssignments: [
      {
        role: "Owner",
        scope: "/subscriptions/sub-9911-banking-core"
      }
    ]
  },
  gcpProjectOwner: {
    projectId: "prj-payments-backend-prod",
    serviceAccountEmail: "stripe-webhook-runner@prj-payments-backend-prod.iam.gserviceaccount.com",
    keyAgeDays: 165,
    bindings: [
      {
        role: "roles/owner",
        members: [
          "serviceAccount:stripe-webhook-runner@prj-payments-backend-prod.iam.gserviceaccount.com"
        ]
      }
    ]
  }
};
