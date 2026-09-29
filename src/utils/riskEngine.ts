import { CloudIdentity, CloudProvider, IdentityType, RiskLevel, Violation, ComplianceTag } from '../types';

/**
 * Result of ingesting cloud policy JSON documents.
 */
export interface IngestResult {
  success: boolean;
  providerDetected: CloudProvider | 'Unified' | 'Unknown';
  identities: CloudIdentity[];
  message: string;
}

/**
 * Sanitizes input strings before embedding them in shell commands,
 * stripping shell metacharacters to prevent command injection risks.
 */
function sanitizeShellIdentifier(val: string): string {
  if (!val) return 'unknown';
  // Allow alphanumeric characters, dashes, underscores, dots, slashes, @, and colons
  return val.replace(/[^a-zA-Z0-9_\-./@:]/g, '');
}

/**
 * Automatically inspects the top-level keys and structure of parsed JSON
 * to identify whether it matches AWS IAM, Azure RBAC/Entra ID, GCP Cloud IAM, or Unified schemas.
 *
 * @param rawJson - The parsed JSON data
 * @returns Detected provider and confidence explanation
 */
export function detectProviderSchema(rawJson: unknown): { provider: CloudProvider | 'Unified' | 'Unknown'; confidence: string } {
  if (!rawJson || typeof rawJson !== 'object') {
    return { provider: 'Unknown', confidence: 'Invalid JSON payload' };
  }

  // 1. Array-level inspection
  if (Array.isArray(rawJson)) {
    if (rawJson.length === 0) {
      return { provider: 'Unknown', confidence: 'Empty JSON array' };
    }
    const first = rawJson[0];
    if (first && typeof first === 'object') {
      // Check for Unified schema
      if ('provider' in first && ('riskScore' in first || 'rolesOrPolicies' in first)) {
        return { provider: 'Unified', confidence: 'Detected array of unified CloudAccessAuditor identities' };
      }
      // Check for Azure RBAC export array (e.g. from az role assignment list)
      if (
        ('type' in first && String(first.type).includes('Microsoft.Authorization')) ||
        ('properties' in first && typeof first.properties === 'object' && first.properties && 'roleDefinitionName' in first.properties) ||
        ('roleDefinitionName' in first)
      ) {
        return { provider: 'Azure', confidence: 'Detected Azure RBAC Role Assignment export list' };
      }
      // Check for AWS IAM statement array
      if ('Effect' in first && ('Action' in first || 'Resource' in first)) {
        return { provider: 'AWS', confidence: 'Detected AWS IAM Policy Statement array' };
      }
      // Check for GCP IAM bindings array
      if ('role' in first && 'members' in first) {
        return { provider: 'GCP', confidence: 'Detected GCP Cloud IAM Policy Bindings array' };
      }
    }
  }

  const obj = rawJson as Record<string, unknown>;

  // 2. Object with "identities" array (Unified)
  if ('identities' in obj && Array.isArray(obj.identities)) {
    return { provider: 'Unified', confidence: 'Detected unified CIEM multi-cloud manifest' };
  }

  // 3. AWS IAM detection (key-based precedence)
  const hasAwsExplicitKeys = 'Statement' in obj || 'PolicyDocument' in obj || 'RoleName' in obj || 'AssumeRolePolicyDocument' in obj;
  if (hasAwsExplicitKeys) {
    return { provider: 'AWS', confidence: 'Detected AWS IAM Policy / Role Document schema' };
  }

  // 4. Azure RBAC detection (key-based precedence)
  const hasAzureExplicitKeys = 'roleAssignments' in obj || 'roleDefinitionName' in obj || 'subscriptionId' in obj || 'servicePrincipal' in obj;
  if (hasAzureExplicitKeys) {
    return { provider: 'Azure', confidence: 'Detected Azure Entra ID / RBAC Role Assignment schema' };
  }

  // 5. GCP Cloud IAM detection (key-based precedence)
  const hasGcpExplicitKeys = 'bindings' in obj || 'serviceAccountEmail' in obj || 'projectId' in obj;
  if (hasGcpExplicitKeys) {
    return { provider: 'GCP', confidence: 'Detected Google Cloud IAM Policy Binding schema' };
  }

  // 6. Heuristic string checks as secondary fallback
  const jsonStr = JSON.stringify(obj);

  if (jsonStr.includes('arn:aws:iam') || jsonStr.includes('sts:AssumeRole') || jsonStr.includes('aws:MultiFactorAuthPresent')) {
    return { provider: 'AWS', confidence: 'Detected AWS IAM Policy signatures' };
  }

  if (jsonStr.includes('Microsoft.Authorization') || jsonStr.includes('/subscriptions/') || jsonStr.includes('onmicrosoft.com')) {
    return { provider: 'Azure', confidence: 'Detected Azure Entra / RBAC signatures' };
  }

  if (jsonStr.includes('iam.gserviceaccount.com') || (jsonStr.includes('roles/') && jsonStr.includes('serviceAccount:'))) {
    return { provider: 'GCP', confidence: 'Detected Google Cloud IAM signatures' };
  }

  return { provider: 'Unknown', confidence: 'Could not automatically identify provider schema' };
}

/**
 * Parses and evaluates an ingested JSON document, computing least-privilege risk scores
 * and extracting violations against CIS and SOC 2 frameworks.
 *
 * @param rawJson - The raw JSON data parsed from text or file upload
 * @returns IngestResult containing newly mapped CloudIdentities
 */
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
      const identities = parseAzureJson(rawJson);
      return {
        success: true,
        providerDetected: 'Azure',
        identities,
        message: `Parsed ${identities.length} Azure identity entitlement${identities.length === 1 ? '' : 's'} with risk scoring.`
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
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Syntax error';
    return {
      success: false,
      providerDetected: 'Unknown',
      identities: [],
      message: `Failed to parse policy document: ${errorMsg}`
    };
  }
}

/**
 * Normalizes an imported object matching the unified CIEM schema.
 */
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
    originalRiskScore: riskScore,
    originalRiskLevel: riskLevel,
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

/**
 * Calculates standard CIEM Risk Level band from numeric score (1-100).
 */
export function calculateRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}

/**
 * Parses AWS IAM Policy or Role Document.
 */
function parseAwsJson(raw: any): CloudIdentity {
  const jsonStr = JSON.stringify(raw);
  const statements = Array.isArray(raw)
    ? raw
    : raw.Statement || raw.PolicyDocument?.Statement || [];
  const violations: Violation[] = [];
  let baseScore = 15;

  const hasWildcardAction = statements.some((s: any) => {
    const act = s.Action;
    const res = s.Resource;
    return (act === '*' || (Array.isArray(act) && act.includes('*'))) && (res === '*' || (Array.isArray(res) && res.includes('*')));
  }) || jsonStr.includes('"Action":"*"') || jsonStr.includes('"Action": "*"');

  const hasUnrestrictedAssume = jsonStr.includes('sts:AssumeRole') && (jsonStr.includes('"Principal":"*"') || jsonStr.includes('"Principal": "*"'));

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
  const safeRoleName = sanitizeShellIdentifier(roleName);

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
    originalRiskScore: riskScore,
    originalRiskLevel: riskLevel,
    violations,
    lastActive: 'Just now (Imported)',
    mfaEnabled: isHuman ? false : undefined,
    currentPolicy: formattedCurrent,
    recommendedPolicy: recommended,
    remediationCommand: `aws iam put-role-policy --role-name ${safeRoleName} --policy-name ScopedLeastPrivilege --policy-document file://scoped.json`,
    remediated: false,
    blastRadiusDetails: {
      servicesExposed: hasWildcardAction ? ['All AWS Services', 'IAM', 'S3', 'RDS', 'KMS'] : ['Scoped AWS Services'],
      privilegeEscalationVectors: hasWildcardAction ? ['iam:PassRole', 'iam:CreateAccessKey'] : ['None identified'],
      impactedResources: `arn:aws:iam::123456789012:role/${safeRoleName}`,
      whatBreaksAnalysis: 'Switching to granular S3 and CloudWatch access prevents account takeover while maintaining core functionality.',
      remediationSafetyNote: 'Review CloudTrail Access Advisor logs for the past 90 days before applying.'
    }
  };
}

/**
 * Parses Azure RBAC Role Assignments (handles single items or arrays from `az role assignment list`).
 */
function parseAzureJson(raw: any): CloudIdentity[] {
  const items = Array.isArray(raw)
    ? raw
    : Array.isArray(raw.roleAssignments)
    ? raw.roleAssignments
    : [raw];

  return items.map((rawItem: any, index: number) => parseSingleAzureAssignment(rawItem, index));
}

function parseSingleAzureAssignment(raw: any, index: number): CloudIdentity {
  const jsonStr = JSON.stringify(raw);
  const props = (raw && typeof raw === 'object' && raw.properties) || raw || {};
  const violations: Violation[] = [];
  let baseScore = 15;

  const roleName = props.roleDefinitionName || props.roleName || raw.roleDefinitionName || (jsonStr.includes('"Owner"') ? 'Owner' : jsonStr.includes('"Contributor"') ? 'Contributor' : 'Reader');
  const isOwner = roleName.toLowerCase() === 'owner' || roleName.toLowerCase().includes('owner');
  const isContributor = roleName.toLowerCase() === 'contributor' || roleName.toLowerCase().includes('contributor');

  const scope = props.scope || raw.scope || raw.subscriptionId || '/subscriptions/sub-enterprise-core-imported';
  const isSubLevel = scope.startsWith('/subscriptions/') && !scope.includes('/resourceGroups/');

  const principalId = props.principalId || raw.principalId || '00000000-0000-0000-0000-000000000000';
  const name = props.principalName || raw.displayName || raw.name || principalId || `azure-principal-${index}`;
  const principalType = props.principalType || raw.principalType || (name.includes('@') ? 'User' : 'ServicePrincipal');
  const isHuman = principalType === 'User' || name.includes('@');

  // Check Subscription-level Owner or Contributor violation
  if ((isOwner || isContributor) && isSubLevel) {
    baseScore += isOwner ? 65 : 45;
    violations.push({
      id: `viol-${Date.now()}-az-${index}-1`,
      code: isOwner ? 'AZURE-RBAC-SUBSCRIPTION-OWNER' : 'AZURE-RBAC-SUBSCRIPTION-CONTRIBUTOR',
      title: `${isOwner ? 'Owner' : 'Contributor'} Role Assigned at Subscription Scope`,
      ruleType: 'Subscription Owner/Contributor',
      severity: isOwner ? 'Critical' : 'High',
      description: `Principal has ${roleName} assigned at the root subscription level instead of scoped to a specific resource group.`,
      complianceTags: [
        { framework: 'SOC 2', control: 'CC6.1', title: 'Logical Access', description: 'Prevent broad ownership permissions on workloads.' },
        { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Scope service principal role assignments.' },
        { framework: 'CIS Azure 2.1', control: '1.23', title: 'Avoid Subscription Owners', description: 'Service principals must not have Owner role at Subscription scope.' }
      ],
      blastRadiusImpact: 'Attacker with leaked secret can destroy all resource groups, modify network firewalls, and tamper with logs.',
      whatBreaks: 'Resource group creation outside the target resource group will be denied.'
    });
  }

  // Check client secret age if present
  const secretDays = typeof raw.secretAgeDays === 'number' ? raw.secretAgeDays : typeof props.secretAgeDays === 'number' ? props.secretAgeDays : undefined;
  if (secretDays !== undefined && secretDays > 180) {
    baseScore += 25;
    violations.push({
      id: `viol-${Date.now()}-az-${index}-2`,
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

  const safePrincipalId = sanitizeShellIdentifier(principalId);
  const safeRoleName = sanitizeShellIdentifier(roleName);
  const safeScope = sanitizeShellIdentifier(scope);

  const recommendedHcl = `resource "azurerm_role_assignment" "scoped_workload" {
  scope                = "${safeScope}/resourceGroups/rg-workload-prod"
  role_definition_name = "Contributor"
  principal_id         = "${safePrincipalId}"
}`;

  return {
    id: `az-custom-${Date.now()}-${index}`,
    name,
    provider: 'Azure',
    identityType: isHuman ? 'Human' : 'Machine',
    scope,
    accountOrSubscriptionId: scope,
    rolesOrPolicies: [roleName],
    riskScore,
    riskLevel,
    originalRiskScore: riskScore,
    originalRiskLevel: riskLevel,
    violations,
    lastActive: props.updatedOn || props.createdOn || 'Just now (Imported)',
    secretExpiryDays: secretDays,
    currentPolicy: JSON.stringify(raw, null, 2),
    recommendedPolicy: recommendedHcl,
    remediationCommand: `az role assignment delete --assignee "${safePrincipalId}" --role "${safeRoleName}" --scope "${safeScope}"\naz role assignment create --assignee "${safePrincipalId}" --role "Contributor" --scope "${safeScope}/resourceGroups/rg-workload-prod"`,
    remediated: false,
    blastRadiusDetails: {
      servicesExposed: isOwner ? ['All Subscription Resources', 'Virtual Networks', 'Key Vaults'] : ['Scoped Azure Resources'],
      privilegeEscalationVectors: isOwner ? ['Microsoft.Authorization/roleAssignments/write'] : ['None identified'],
      impactedResources: scope,
      whatBreaksAnalysis: 'Scope role assignment to rg-workload-prod to prevent tampering with other business unit resources.',
      remediationSafetyNote: 'Verify Azure Activity Log to confirm all resources currently touched by this identity.'
    }
  };
}

/**
 * Parses GCP Cloud IAM Policy Binding or Service Account document.
 */
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
  const safeName = sanitizeShellIdentifier(name);
  const safeProjectId = sanitizeShellIdentifier(projectId);

  // Clean valid JSON recommended policy (no invalid // comments)
  const recommendedJson = `{
  "bindings": [
    {
      "role": "roles/container.developer",
      "members": [
        "serviceAccount:${safeName}"
      ]
    },
    {
      "role": "roles/clouddeploy.releaser",
      "members": [
        "serviceAccount:${safeName}"
      ]
    }
  ]
}`;

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
    originalRiskScore: riskScore,
    originalRiskLevel: riskLevel,
    violations,
    lastActive: 'Just now (Imported)',
    keyAgeDays: keyAge,
    currentPolicy: JSON.stringify(raw, null, 2),
    recommendedPolicy: recommendedJson,
    remediationCommand: `gcloud projects remove-iam-policy-binding "${safeProjectId}" --member="serviceAccount:${safeName}" --role="${isOwner ? 'roles/owner' : 'roles/editor'}"\ngcloud projects add-iam-policy-binding "${safeProjectId}" --member="serviceAccount:${safeName}" --role="roles/container.developer"`,
    remediated: false,
    blastRadiusDetails: {
      servicesExposed: ['All GCP Services in Project', 'Cloud Storage', 'Cloud SQL', 'GKE'],
      privilegeEscalationVectors: ['resourcemanager.projects.setIamPolicy'],
      impactedResources: `projects/${safeProjectId}`,
      whatBreaksAnalysis: 'Switching to container.developer and clouddeploy.releaser allows CI/CD to push images and roll out deployments without broad project ownership.',
      remediationSafetyNote: 'Consider Workload Identity Federation instead of static JSON service account keys.'
    }
  };
}

/**
 * Sample JSON payloads for quick test dropzones.
 */
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
