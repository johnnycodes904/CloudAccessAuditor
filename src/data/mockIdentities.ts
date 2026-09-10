import { CloudIdentity } from '../types';

export const INITIAL_IDENTITIES: CloudIdentity[] = [
  // ==========================================
  // AWS IDENTITIES (6)
  // ==========================================
  {
    id: 'aws-id-01',
    name: 'prod-ci-deployer-role',
    provider: 'AWS',
    identityType: 'Machine',
    scope: '110293847561 (us-east-1)',
    accountOrSubscriptionId: '110293847561',
    rolesOrPolicies: ['AdministratorAccess', 'DirectAssumeRolePolicy'],
    riskScore: 96,
    riskLevel: 'Critical',
    lastActive: '12 minutes ago',
    mfaEnabled: false,
    remediated: false,
    violations: [
      {
        id: 'viol-aws-01',
        code: 'AWS-IAM-WILDCARD-FULL-ADMIN',
        title: 'Full Wildcard Administrator Privileges (*:*)',
        ruleType: 'Wildcard Policy',
        severity: 'Critical',
        description: 'Identity grants Action: "*" on Resource: "*", permitting unrestricted API calls including destructive delete and account takeover.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Logical Access Controls', description: 'Restricts logical access to authorized users and workloads.' },
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege Enforcement', description: 'Requires granular role-based entitlements.' },
          { framework: 'CIS AWS 3.0', control: '1.16', title: 'Avoid Full Admin Policies', description: 'Ensure no IAM policies allow unrestricted Action:* on Resource:*.' }
        ],
        blastRadiusImpact: 'Critical risk to all AWS infrastructure, databases (RDS, DynamoDB), KMS encryption keys, and S3 data stores.',
        whatBreaks: 'Restricting this role directly without preserving CI deploy targets (ECS, S3 artifact deployment, Lambda update) will disrupt master branch builds.'
      },
      {
        id: 'viol-aws-02',
        code: 'AWS-IAM-UNRESTRICTED-ASSUME',
        title: 'Unrestricted sts:AssumeRole Trust Policy',
        ruleType: 'Unrestricted AssumeRole',
        severity: 'Critical',
        description: 'AssumeRole trust relationship specifies Principal: "*" without sts:ExternalId or aws:PrincipalOrgID condition, exposing the role to confused deputy attacks.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.3', title: 'Revocation & Delegation', description: 'Safeguards privileged delegation workflows.' },
          { framework: 'CIS AWS 3.0', control: '1.20', title: 'External Trust Boundary Protection', description: 'Prevent cross-account delegation without condition checks.' }
        ],
        blastRadiusImpact: 'Any external AWS account can assume this role and compromise deployment pipelines.',
        whatBreaks: 'Third-party CI runners without specified ARN or ExternalID will fail authentication.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All AWS Services (200+ APIs)', 'IAM & KMS', 'S3 Production Buckets', 'RDS Multi-AZ Aurora Clusters'],
      privilegeEscalationVectors: ['iam:CreateAccessKey', 'iam:AttachUserPolicy', 'sts:AssumeRole on Root Accounts'],
      impactedResources: 'Account-wide (ARN: arn:aws:iam::110293847561:role/prod-ci-deployer-role)',
      whatBreaksAnalysis: 'Deploy pipelines running Terraform or AWS CDK may require specific resource write access (e.g. S3 build bucket, ECS service update). Recommended policy scopes actions strictly to target deployment stacks.',
      remediationSafetyNote: 'Validate that the CI runner uses the GitHub OIDC provider with exact repository subject claims.'
    },
    currentPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAllActionsWildcard",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "UnrestrictedTrustPolicy",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": "*"
    }
  ]
}`,
    recommendedPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ScopedEcsAndS3Deployment",
      "Effect": "Allow",
      "Action": [
        "ecs:UpdateService",
        "ecs:DescribeServices",
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:ecs:us-east-1:110293847561:service/production-cluster/*",
        "arn:aws:s3:::company-prod-build-artifacts/*"
      ]
    },
    {
      "Sid": "RestrictedOidcAssumeRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Principal": {
        "Federated": "arn:aws:iam::110293847561:oidc-provider/token.actions.githubusercontent.com"
      },
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:org/payments-service:ref:refs/heads/main"
        }
      }
    }
  ]
}`,
    remediationCommand: `aws iam put-role-policy --role-name prod-ci-deployer-role --policy-name ScopedDeployerPolicy --policy-document file://recommended-policy.json`,
    remediationTerraform: `resource "aws_iam_role_policy" "scoped_deployer" {
  name = "ScopedDeployerPolicy"
  role = aws_iam_role.prod_ci_deployer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:UpdateService", "s3:PutObject"]
        Resource = ["arn:aws:ecs:us-east-1:110293847561:service/production-cluster/*"]
      }
    ]
  })
}`
  },
  {
    id: 'aws-id-02',
    name: 'sre-lead-breakglass',
    provider: 'AWS',
    identityType: 'Human',
    scope: '110293847561 (us-east-1)',
    accountOrSubscriptionId: '110293847561',
    rolesOrPolicies: ['SystemAdministratorAccess'],
    riskScore: 82,
    riskLevel: 'Critical',
    lastActive: '2 days ago',
    mfaEnabled: false,
    remediated: false,
    violations: [
      {
        id: 'viol-aws-03',
        code: 'AWS-IAM-MFA-MISSING-ADMIN',
        title: 'Privileged Human User Missing Hardware MFA',
        ruleType: 'Missing MFA',
        severity: 'Critical',
        description: 'User possesses administrative access credentials with an active console password, but Multi-Factor Authentication (MFA) is not enforced.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Logical Access Controls', description: 'Requires MFA for all human administrative sessions.' },
          { framework: 'CIS AWS 3.0', control: '1.5', title: 'Ensure MFA is Enabled for All IAM Users', description: 'Enforce hardware or virtual MFA for all console-enabled accounts.' }
        ],
        blastRadiusImpact: 'High likelihood of account compromise via credential stuffing or phishing.',
        whatBreaks: 'Enforcing DenyUnlessMFA policy will temporarily lock the user out until they register a TOTP or FIDO2 key.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All AWS Production APIs', 'EC2, RDS, VPC Route Tables', 'CloudTrail Audit Logs'],
      privilegeEscalationVectors: ['Direct root-equivalent console access without second-factor'],
      impactedResources: 'arn:aws:iam::110293847561:user/sre-lead-breakglass',
      whatBreaksAnalysis: 'Immediate enforcement blocks non-MFA sessions. Provide emergency virtual MFA QR code enrollment path.',
      remediationSafetyNote: 'Enforce MFA via AWS IAM condition key aws:MultiFactorAuthPresent: true.'
    },
    currentPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowFullAdminWithoutMfa",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}`,
    recommendedPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceMfaForAdminAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}`,
    remediationCommand: `aws iam put-user-policy --user-name sre-lead-breakglass --policy-name EnforceMfaPolicy --policy-document file://enforce-mfa-policy.json`
  },
  {
    id: 'aws-id-03',
    name: 'analytics-data-pipeline-role',
    provider: 'AWS',
    identityType: 'Machine',
    scope: '482910482918 (us-west-2)',
    accountOrSubscriptionId: '482910482918',
    rolesOrPolicies: ['AmazonS3FullAccess', 'KmsKeyDecryptAll'],
    riskScore: 72,
    riskLevel: 'High',
    lastActive: '5 hours ago',
    mfaEnabled: false,
    remediated: false,
    violations: [
      {
        id: 'viol-aws-04',
        code: 'AWS-S3-WILDCARD-OVERPERMISSIVE',
        title: 'Over-permissive S3:* with KMS Decrypt on All Keys',
        ruleType: 'Wildcard Policy',
        severity: 'High',
        description: 'Role has s3:* privileges across all buckets, allowing unauthorized reads of PII customer records and payment transaction buckets.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Data pipelines must only access specific ingestion buckets.' },
          { framework: 'CIS AWS 3.0', control: '1.16', title: 'Restrict Data Store Actions', description: 'Restrict s3:* actions to designated data lake buckets.' }
        ],
        blastRadiusImpact: 'Potential data exfiltration of financial reports and user telemetry in other departmental S3 buckets.',
        whatBreaks: 'Spark ETL batch jobs will throw AccessDenied if intermediate scratch buckets are omitted from the Resource list.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All S3 Buckets in Account', 'KMS Master Decrypt Keys'],
      privilegeEscalationVectors: ['s3:DeleteBucket', 's3:PutBucketPolicy'],
      impactedResources: 'arn:aws:iam::482910482918:role/analytics-data-pipeline-role',
      whatBreaksAnalysis: 'Pipelines require Read on raw-data-lake and Write on processed-analytics. Remove DeleteBucket and unrestricted KMS wildcard.',
      remediationSafetyNote: 'Ensure KMS Key Policy grants kms:Decrypt specifically on key-alias/analytics-cmk.'
    },
    currentPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3FullAccess",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Sid": "KmsDecryptAll",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "*"
    }
  ]
}`,
    recommendedPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ScopedAnalyticsBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::fintech-data-lake-raw",
        "arn:aws:s3:::fintech-data-lake-raw/*",
        "arn:aws:s3:::fintech-data-lake-processed",
        "arn:aws:s3:::fintech-data-lake-processed/*"
      ]
    },
    {
      "Sid": "ScopedKmsDecrypt",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-west-2:482910482918:key/a1b2c3d4-e5f6-7890"
    }
  ]
}`,
    remediationCommand: `aws iam put-role-policy --role-name analytics-data-pipeline-role --policy-name ScopedS3Analytics --policy-document file://scoped-s3.json`
  },
  {
    id: 'aws-id-04',
    name: 'dev-ec2-instance-profile',
    provider: 'AWS',
    identityType: 'Machine',
    scope: '482910482918 (us-west-2)',
    accountOrSubscriptionId: '482910482918',
    rolesOrPolicies: ['EC2InstanceConnect', 'CustomIAMPolicy'],
    riskScore: 84,
    riskLevel: 'Critical',
    lastActive: '3 hours ago',
    mfaEnabled: false,
    remediated: false,
    violations: [
      {
        id: 'viol-aws-05',
        code: 'AWS-IAM-PRIVILEGE-ESCALATION',
        title: 'High-Risk Privilege Escalation via iam:PassRole & CreateAccessKey',
        ruleType: 'Privilege Escalation',
        severity: 'Critical',
        description: 'Instance profile grants iam:PassRole without resource limitation and iam:CreateAccessKey, allowing compromised EC2 workload to mint Admin keys.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Access Control', description: 'Prevent lateral privilege escalation pathways.' },
          { framework: 'CIS AWS 3.0', control: '1.24', title: 'Limit IAM PassRole Privileges', description: 'IAM PassRole must be scoped to specific target service roles.' }
        ],
        blastRadiusImpact: 'Direct attacker path from SSRF vulnerability on EC2 to full cloud administrator.',
        whatBreaks: 'Instance bootstrap scripts configuring local worker keys might need alternative instance role credentials.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['IAM Key Creation API', 'PassRole on all AWS Service Roles'],
      privilegeEscalationVectors: ['iam:CreateAccessKey on root admins', 'iam:PassRole to Lambda / EC2'],
      impactedResources: 'arn:aws:iam::482910482918:role/dev-ec2-instance-profile',
      whatBreaksAnalysis: 'Remove iam:CreateAccessKey entirely; EC2 instances should rely strictly on IMDSv2 temporary credentials.',
      remediationSafetyNote: 'Enforce IMDSv2 with hop limit 1 on the underlying EC2 instance.'
    },
    currentPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:PassRole",
        "iam:CreateAccessKey"
      ],
      "Resource": "*"
    }
  ]
}`,
    recommendedPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}`,
    remediationCommand: `aws iam delete-role-policy --role-name dev-ec2-instance-profile --policy-name CustomIAMPolicy`
  },
  {
    id: 'aws-id-05',
    name: 'security-audit-readonly',
    provider: 'AWS',
    identityType: 'Machine',
    scope: '110293847561 (us-east-1)',
    accountOrSubscriptionId: '110293847561',
    rolesOrPolicies: ['SecurityAudit', 'ViewOnlyAccess'],
    riskScore: 16,
    riskLevel: 'Low',
    lastActive: '45 minutes ago',
    mfaEnabled: true,
    remediated: false,
    violations: [],
    blastRadiusDetails: {
      servicesExposed: ['Read-only metadata inspection on IAM, CloudTrail, Config'],
      privilegeEscalationVectors: ['None detected'],
      impactedResources: 'arn:aws:iam::110293847561:role/security-audit-readonly',
      whatBreaksAnalysis: 'Compliant security posture. No breaking changes needed.',
      remediationSafetyNote: 'Periodic review every 180 days recommended.'
    },
    currentPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}`,
    recommendedPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}`,
    remediationCommand: `# Identity is compliant with least-privilege principles`
  },
  {
    id: 'aws-id-06',
    name: 'finops-cost-analyzer',
    provider: 'AWS',
    identityType: 'Human',
    scope: '110293847561 (us-east-1)',
    accountOrSubscriptionId: '110293847561',
    rolesOrPolicies: ['AWSBillingReadOnlyAccess'],
    riskScore: 22,
    riskLevel: 'Low',
    lastActive: '1 day ago',
    mfaEnabled: true,
    remediated: false,
    violations: [],
    blastRadiusDetails: {
      servicesExposed: ['AWS Cost Explorer', 'Cost and Usage Reports'],
      privilegeEscalationVectors: ['None'],
      impactedResources: 'arn:aws:iam::110293847561:user/finops-cost-analyzer',
      whatBreaksAnalysis: 'Read-only financial telemetry identity with active hardware FIDO2 key.',
      remediationSafetyNote: 'Compliant.'
    },
    currentPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "cur:DescribeReportDefinitions"
      ],
      "Resource": "*"
    }
  ]
}`,
    recommendedPolicy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "cur:DescribeReportDefinitions"
      ],
      "Resource": "*"
    }
  ]
}`,
    remediationCommand: `# Identity is compliant`
  },

  // ==========================================
  // AZURE IDENTITIES (6)
  // ==========================================
  {
    id: 'az-id-01',
    name: 'sp-terraform-enterprise-deployer',
    provider: 'Azure',
    identityType: 'Machine',
    scope: 'sub-0a81-core-infrastructure',
    accountOrSubscriptionId: 'sub-0a81-core-infrastructure',
    rolesOrPolicies: ['Owner (Subscription Root Scope)'],
    riskScore: 94,
    riskLevel: 'Critical',
    lastActive: '18 minutes ago',
    secretExpiryDays: 412, // Long lived secret!
    remediated: false,
    violations: [
      {
        id: 'viol-az-01',
        code: 'AZURE-RBAC-SUBSCRIPTION-OWNER',
        title: 'Subscription-Level Owner Role Assignment',
        ruleType: 'Subscription Owner/Contributor',
        severity: 'Critical',
        description: 'Service Principal is assigned the built-in "Owner" role at the root subscription scope (/subscriptions/sub-0a81-core-infrastructure), allowing modification of all RBAC role assignments, security controls, and resource deletion.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Access Control', description: 'Prevent broad ownership permissions on workloads.' },
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Service principals must be restricted to resource groups.' },
          { framework: 'CIS Azure 2.1', control: '1.23', title: 'Avoid Custom/Built-in Subscription Owners', description: 'Ensure no service principals possess Owner role at Subscription scope.' }
        ],
        blastRadiusImpact: 'A leaked client secret gives an attacker complete control over virtual networks, ExpressRoute circuits, and production databases.',
        whatBreaks: 'Downgrading to Resource Group Contributor may break Terraform runs creating new Resource Groups or assigning User Assigned Managed Identities.'
      },
      {
        id: 'viol-az-02',
        code: 'AZURE-ENTRA-LONG-LIVED-SECRET',
        title: 'App Registration Client Secret Expiry Exceeds 180 Days (412 Days Active)',
        ruleType: 'Long-Lived Client Secret',
        severity: 'High',
        description: 'Client secret on App Registration was created with no automatic rotation and remains valid for 412 days, violating CIS credential hygiene benchmarks.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.3', title: 'Credential Lifecycle', description: 'Mandates credential rotation intervals under 90-180 days.' },
          { framework: 'CIS Azure 2.1', control: '1.2', title: 'Ensure Client Secrets Expire in <= 180 Days', description: 'Rotate all Entra ID application credentials regularly.' }
        ],
        blastRadiusImpact: 'Increased window of opportunity if the secret is committed to source control or artifact caches.',
        whatBreaks: 'Automated CI runners will fail if secret is revoked prior to updating key vault or secret store.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All Subscription Resources', 'Role Assignments API', 'Microsoft Entra ID Service Management'],
      privilegeEscalationVectors: ['Microsoft.Authorization/roleAssignments/write', 'Microsoft.KeyVault/vaults/accessPolicies/write'],
      impactedResources: '/subscriptions/sub-0a81-core-infrastructure',
      whatBreaksAnalysis: 'Terraform pipelines need Contributor on specific Resource Groups (rg-networking, rg-compute), not Subscription Owner. Scoping avoids cross-boundary security policy tampering.',
      remediationSafetyNote: 'Migrate the Service Principal to Azure Workload Identity Federation with GitHub Actions / Azure DevOps to eliminate secrets entirely.'
    },
    currentPolicy: `// Current Azure Role Assignment (Subscription Level)
resource "azurerm_role_assignment" "sp_sub_owner" {
  scope                = "/subscriptions/sub-0a81-core-infrastructure"
  role_definition_name = "Owner"
  principal_id         = "7c4e5f2a-89a1-432d-99ff-12a45bc67890"
}`,
    recommendedPolicy: `// Recommended Least-Privilege Role Assignment (Scoped to RG)
resource "azurerm_role_assignment" "sp_scoped_contributor" {
  scope                = "/subscriptions/sub-0a81-core-infrastructure/resourceGroups/rg-production-workloads"
  role_definition_name = "Contributor"
  principal_id         = "7c4e5f2a-89a1-432d-99ff-12a45bc67890"
}`,
    remediationCommand: `az role assignment delete --assignee 7c4e5f2a-89a1-432d-99ff-12a45bc67890 --role "Owner" --scope "/subscriptions/sub-0a81-core-infrastructure"
az role assignment create --assignee 7c4e5f2a-89a1-432d-99ff-12a45bc67890 --role "Contributor" --scope "/subscriptions/sub-0a81-core-infrastructure/resourceGroups/rg-production-workloads"`
  },
  {
    id: 'az-id-02',
    name: 'azure-devops-sync-app',
    provider: 'Azure',
    identityType: 'Machine',
    scope: 'sub-9b22-ecommerce-prod',
    accountOrSubscriptionId: 'sub-9b22-ecommerce-prod',
    rolesOrPolicies: ['Contributor (Subscription Root Scope)'],
    riskScore: 78,
    riskLevel: 'High',
    lastActive: '4 hours ago',
    secretExpiryDays: 320,
    remediated: false,
    violations: [
      {
        id: 'viol-az-03',
        code: 'AZURE-RBAC-SUBSCRIPTION-CONTRIBUTOR',
        title: 'Contributor Role Assigned at Subscription Scope',
        ruleType: 'Subscription Owner/Contributor',
        severity: 'High',
        description: 'Service Principal has Contributor rights across the entire production subscription instead of scoped to application resource groups.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Enforce boundary separation between network and compute.' },
          { framework: 'CIS Azure 2.1', control: '1.24', title: 'Scope Service Principals to Resource Groups', description: 'Prevent subscription-wide write permissions.' }
        ],
        blastRadiusImpact: 'Workload can modify core networking, destroy Virtual WANs, and alter App Service configurations.',
        whatBreaks: 'Pipelines attempting to deploy to non-whitelisted resource groups will fail.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All Resource Groups', 'Azure CosmosDB', 'AKS Clusters'],
      privilegeEscalationVectors: ['Microsoft.Compute/virtualMachines/*/write', 'Microsoft.Network/*/write'],
      impactedResources: '/subscriptions/sub-9b22-ecommerce-prod',
      whatBreaksAnalysis: 'Scope role to rg-ecommerce-apps and rg-ecommerce-data only.',
      remediationSafetyNote: 'Verify ARM templates reference specific resource groups.'
    },
    currentPolicy: `az role assignment create \\
  --assignee "3f1a2b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c" \\
  --role "Contributor" \\
  --scope "/subscriptions/sub-9b22-ecommerce-prod"`,
    recommendedPolicy: `az role assignment create \\
  --assignee "3f1a2b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c" \\
  --role "Website Contributor" \\
  --scope "/subscriptions/sub-9b22-ecommerce-prod/resourceGroups/rg-ecommerce-apps"`,
    remediationCommand: `az role assignment delete --assignee 3f1a2b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c --role "Contributor" --scope "/subscriptions/sub-9b22-ecommerce-prod"`
  },
  {
    id: 'az-id-03',
    name: 'global-admin-external@partner.com',
    provider: 'Azure',
    identityType: 'Human',
    scope: 'sub-0a81-core-infrastructure',
    accountOrSubscriptionId: 'sub-0a81-core-infrastructure',
    rolesOrPolicies: ['Global Administrator (Entra ID)', 'Subscription Owner'],
    riskScore: 92,
    riskLevel: 'Critical',
    lastActive: '3 days ago',
    mfaEnabled: true,
    remediated: false,
    violations: [
      {
        id: 'viol-az-04',
        code: 'AZURE-ENTRA-EXTERNAL-GLOBAL-ADMIN',
        title: 'Guest/External Account with Standing Global Admin Privileges',
        ruleType: 'Privileged Guest Identity',
        severity: 'Critical',
        description: 'External B2B guest account maintains permanent, standing Global Administrator privileges without Privileged Identity Management (PIM) just-in-time activation.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Logical Access', description: 'Prevent unmonitored external partner administrative access.' },
          { framework: 'SOC 2', control: 'CC6.3', title: 'Privilege Lifecycle', description: 'Require just-in-time access for privileged duties.' },
          { framework: 'CIS Azure 2.1', control: '1.1', title: 'Ensure No Guest Accounts Have Administrative Roles', description: 'Restrict Entra directory admin roles to internal verified users.' }
        ],
        blastRadiusImpact: 'Compromise of the partner organization immediately yields total administrative takeover of the tenant.',
        whatBreaks: 'Revoking standing admin requires partner to authenticate via PIM eligibility with approval workflow.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['Entire Microsoft Entra ID Tenant', 'All Subscriptions', 'Exchange Online, SharePoint'],
      privilegeEscalationVectors: ['Full directory synchronization takeover', 'OAuth app consent bypass'],
      impactedResources: 'Tenant Root & /subscriptions/sub-0a81-core-infrastructure',
      whatBreaksAnalysis: 'Convert permanent assignment to PIM Eligible with maximum 4-hour activation window and manager approval.',
      remediationSafetyNote: 'Verify emergency break-glass account exists prior to revoking partner standing role.'
    },
    currentPolicy: `// Permanent standing assignment in Microsoft Graph
POST /v1.0/roleManagement/directory/roleAssignments
{
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10", // Global Admin
  "principalId": "88e7a1b2-c3d4-4e5f-9a0b-1c2d3e4f5a6b",
  "directoryScopeId": "/"
}`,
    recommendedPolicy: `// Convert to PIM Just-In-Time Eligible with MFA & Approval
POST /v1.0/roleManagement/directory/roleEligibilityScheduleRequests
{
  "action": "AdminAssign",
  "justification": "Eligible JIT access for contracted maintenance",
  "roleDefinitionId": "b24988ac-6180-42a0-ab88-20f7382dd24c", // Security Admin (Scoped)
  "directoryScopeId": "/",
  "principalId": "88e7a1b2-c3d4-4e5f-9a0b-1c2d3e4f5a6b",
  "scheduleInfo": {
    "expiration": {
      "type": "AfterDuration",
      "duration": "PT4H"
    }
  }
}`,
    remediationCommand: `az rest --method DELETE --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/perm-assignment-id"`
  },
  {
    id: 'az-id-04',
    name: 'payments-microservice-identity',
    provider: 'Azure',
    identityType: 'Machine',
    scope: 'sub-9b22-ecommerce-prod',
    accountOrSubscriptionId: 'sub-9b22-ecommerce-prod',
    rolesOrPolicies: ['Key Vault Secrets Officer (Subscription Scope)'],
    riskScore: 68,
    riskLevel: 'High',
    lastActive: '30 minutes ago',
    secretExpiryDays: 90,
    remediated: false,
    violations: [
      {
        id: 'viol-az-05',
        code: 'AZURE-KEYVAULT-SUBSCRIPTION-OFFICER',
        title: 'Key Vault Secrets Officer Assigned Across All Vaults',
        ruleType: 'Broad Secrets Access',
        severity: 'High',
        description: 'Workload can read and modify secrets across every Key Vault in the subscription, including database master passwords and SSL certificates.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Data Confidentiality', description: 'Segregate cryptographic key and secret management.' },
          { framework: 'CIS Azure 2.1', control: '8.4', title: 'Scope RBAC on Key Vaults', description: 'Assign Key Vault roles only at individual Key Vault scope.' }
        ],
        blastRadiusImpact: 'Blast radius extends beyond payment service to corporate VPN certificates and audit signing keys.',
        whatBreaks: 'Restricting scope to kv-payments-prod will break if the microservice tries to fetch secrets from kv-shared-services.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All Azure Key Vaults in Subscription'],
      privilegeEscalationVectors: ['Extract database credentials', 'Modify TLS certificates'],
      impactedResources: '/subscriptions/sub-9b22-ecommerce-prod/providers/Microsoft.KeyVault/*',
      whatBreaksAnalysis: 'Scope role assignment to the single vault /resourceGroups/rg-ecommerce-data/providers/Microsoft.KeyVault/vaults/kv-payments-prod.',
      remediationSafetyNote: 'Verify that the microservice only references kv-payments-prod in its application settings.'
    },
    currentPolicy: `az role assignment create \\
  --assignee "b7a6c5d4-e3f2-1a0b-9c8d-7e6f5a4b3c2d" \\
  --role "Key Vault Secrets Officer" \\
  --scope "/subscriptions/sub-9b22-ecommerce-prod"`,
    recommendedPolicy: `az role assignment create \\
  --assignee "b7a6c5d4-e3f2-1a0b-9c8d-7e6f5a4b3c2d" \\
  --role "Key Vault Secrets User" \\
  --scope "/subscriptions/sub-9b22-ecommerce-prod/resourceGroups/rg-ecommerce-data/providers/Microsoft.KeyVault/vaults/kv-payments-prod"`,
    remediationCommand: `az role assignment create --assignee b7a6c5d4-e3f2-1a0b-9c8d-7e6f5a4b3c2d --role "Key Vault Secrets User" --scope "/subscriptions/sub-9b22-ecommerce-prod/resourceGroups/rg-ecommerce-data/providers/Microsoft.KeyVault/vaults/kv-payments-prod"`
  },
  {
    id: 'az-id-05',
    name: 'support-technician@contoso.com',
    provider: 'Azure',
    identityType: 'Human',
    scope: 'sub-3c44-branch-dev',
    accountOrSubscriptionId: 'sub-3c44-branch-dev',
    rolesOrPolicies: ['Reader', 'Support Request Contributor'],
    riskScore: 18,
    riskLevel: 'Low',
    lastActive: '1 hour ago',
    mfaEnabled: true,
    remediated: false,
    violations: [],
    blastRadiusDetails: {
      servicesExposed: ['Read-only Azure Resource Manager telemetry'],
      privilegeEscalationVectors: ['None'],
      impactedResources: '/subscriptions/sub-3c44-branch-dev',
      whatBreaksAnalysis: 'Read-only access with FIDO2 MFA enforced through Conditional Access.',
      remediationSafetyNote: 'Compliant.'
    },
    currentPolicy: `az role assignment create \\
  --assignee "support-technician@contoso.com" \\
  --role "Reader" \\
  --scope "/subscriptions/sub-3c44-branch-dev"`,
    recommendedPolicy: `az role assignment create \\
  --assignee "support-technician@contoso.com" \\
  --role "Reader" \\
  --scope "/subscriptions/sub-3c44-branch-dev"`,
    remediationCommand: `# Identity is compliant`
  },
  {
    id: 'az-id-06',
    name: 'db-migration-app-registration',
    provider: 'Azure',
    identityType: 'Machine',
    scope: 'sub-9b22-ecommerce-prod',
    accountOrSubscriptionId: 'sub-9b22-ecommerce-prod',
    rolesOrPolicies: ['SQL DB Contributor'],
    riskScore: 46,
    riskLevel: 'Medium',
    lastActive: '6 hours ago',
    secretExpiryDays: 140,
    remediated: false,
    violations: [
      {
        id: 'viol-az-06',
        code: 'AZURE-RBAC-BROAD-SQL-CONTRIBUTOR',
        title: 'SQL DB Contributor Scope Across All Resource Groups',
        ruleType: 'Broad Resource Scope',
        severity: 'Medium',
        description: 'Identity can alter SQL servers in staging, dev, and production resource groups.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Limit database management privileges to designated databases.' },
          { framework: 'CIS Azure 2.1', control: '1.24', title: 'Scope RBAC Roles', description: 'Prevent subscription wide DB modification.' }
        ],
        blastRadiusImpact: 'Potential disruption of database firewall rules or connection strings.',
        whatBreaks: 'Flyway / Liquibase database migrations targeting non-prod environments.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['Azure SQL Servers and Managed Instances'],
      privilegeEscalationVectors: ['Microsoft.Sql/servers/firewallRules/write'],
      impactedResources: '/subscriptions/sub-9b22-ecommerce-prod/providers/Microsoft.Sql/*',
      whatBreaksAnalysis: 'Scope specifically to resource group rg-ecommerce-data.',
      remediationSafetyNote: 'Switch to Managed Identity authentication to remove secret entirely.'
    },
    currentPolicy: `az role assignment create --assignee db-app-id --role "SQL DB Contributor" --scope "/subscriptions/sub-9b22-ecommerce-prod"`,
    recommendedPolicy: `az role assignment create --assignee db-app-id --role "SQL DB Contributor" --scope "/subscriptions/sub-9b22-ecommerce-prod/resourceGroups/rg-ecommerce-data"`,
    remediationCommand: `az role assignment create --assignee db-app-id --role "SQL DB Contributor" --scope "/subscriptions/sub-9b22-ecommerce-prod/resourceGroups/rg-ecommerce-data"`
  },

  // ==========================================
  // GCP IDENTITIES (6)
  // ==========================================
  {
    id: 'gcp-id-01',
    name: 'github-actions-sa@fintech-prod.iam.gserviceaccount.com',
    provider: 'GCP',
    identityType: 'Machine',
    scope: 'prj-fintech-core-prod',
    accountOrSubscriptionId: 'prj-fintech-core-prod',
    rolesOrPolicies: ['roles/owner (Primitive Role)'],
    riskScore: 98,
    riskLevel: 'Critical',
    lastActive: '5 minutes ago',
    keyAgeDays: 194, // > 90 days!
    remediated: false,
    violations: [
      {
        id: 'viol-gcp-01',
        code: 'GCP-IAM-PRIMITIVE-OWNER-ROOT',
        title: 'Primitive roles/owner Assigned at Project Root',
        ruleType: 'Primitive Owner/Editor Role',
        severity: 'Critical',
        description: 'Service account has primitive roles/owner at project level (prj-fintech-core-prod), granting unrestricted control over billing links, IAM policy binding modifications, and service deletion.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Logical Access Control', description: 'Prohibits primitive ownership roles for automated service accounts.' },
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Requires granular predefined or custom IAM roles.' },
          { framework: 'CIS GCP 3.0', control: '1.4', title: 'Ensure No Service Accounts Have roles/owner', description: 'Service accounts should never possess primitive Owner or Editor roles.' }
        ],
        blastRadiusImpact: 'Total project compromise, including Cloud Spanner deletion, secret exfiltration, and disabling Cloud Audit Logs.',
        whatBreaks: 'If Terraform pipeline runs terraform apply creating new IAM bindings, it needs specific roles/resourcemanager.projectIamAdmin rather than broad Owner.'
      },
      {
        id: 'viol-gcp-02',
        code: 'GCP-IAM-KEY-AGE-OVER-90-DAYS',
        title: 'User-Managed Service Account Key Age Exceeds 90 Days (194 Days Active)',
        ruleType: 'Stale Service Account Key',
        severity: 'High',
        description: 'User-managed private key was generated 194 days ago without rotation, presenting high risk of credential leakage in CI logs.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.3', title: 'Credential Rotation', description: 'Mandates rotation of API tokens and private keys within 90 days.' },
          { framework: 'CIS GCP 3.0', control: '1.7', title: 'Ensure Service Account Keys Are Rotated Every 90 Days or Less', description: 'Audit and rotate or eliminate user-managed keys.' }
        ],
        blastRadiusImpact: 'Leaked JSON private key remains usable from any IP worldwide until manually revoked.',
        whatBreaks: 'Revoking the key immediately stops GitHub Actions pipelines until Workload Identity Federation or a new rotated key is configured.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All Google Cloud APIs in Project', 'Cloud KMS', 'Cloud Storage Buckets', 'Cloud SQL Instances', 'GKE Clusters'],
      privilegeEscalationVectors: ['resourcemanager.projects.setIamPolicy', 'iam.serviceAccounts.actAs on all SAs'],
      impactedResources: 'projects/prj-fintech-core-prod',
      whatBreaksAnalysis: 'Replacing roles/owner with roles/container.developer and roles/clouddeploy.releaser protects project governance while allowing CI deployments to proceed.',
      remediationSafetyNote: 'Transition CI pipeline to Google Cloud Workload Identity Federation to eliminate downloadable JSON keys.'
    },
    currentPolicy: `// GCP IAM Project Binding
{
  "bindings": [
    {
      "role": "roles/owner",
      "members": [
        "serviceAccount:github-actions-sa@fintech-prod.iam.gserviceaccount.com"
      ]
    }
  ]
}`,
    recommendedPolicy: `// Scoped Predefined Roles for CI/CD
{
  "bindings": [
    {
      "role": "roles/container.developer",
      "members": [
        "serviceAccount:github-actions-sa@fintech-prod.iam.gserviceaccount.com"
      ]
    },
    {
      "role": "roles/clouddeploy.releaser",
      "members": [
        "serviceAccount:github-actions-sa@fintech-prod.iam.gserviceaccount.com"
      ]
    }
  ]
}`,
    remediationCommand: `gcloud projects remove-iam-policy-binding prj-fintech-core-prod \\
  --member="serviceAccount:github-actions-sa@fintech-prod.iam.gserviceaccount.com" \\
  --role="roles/owner"

gcloud projects add-iam-policy-binding prj-fintech-core-prod \\
  --member="serviceAccount:github-actions-sa@fintech-prod.iam.gserviceaccount.com" \\
  --role="roles/container.developer"`
  },
  {
    id: 'gcp-id-02',
    name: 'data-lake-sync@analytics-pipeline.iam.gserviceaccount.com',
    provider: 'GCP',
    identityType: 'Machine',
    scope: 'prj-bigdata-lake-prod',
    accountOrSubscriptionId: 'prj-bigdata-lake-prod',
    rolesOrPolicies: ['roles/editor (Primitive Role)'],
    riskScore: 79,
    riskLevel: 'High',
    lastActive: '1 hour ago',
    keyAgeDays: 118,
    remediated: false,
    violations: [
      {
        id: 'viol-gcp-03',
        code: 'GCP-IAM-PRIMITIVE-EDITOR-ROOT',
        title: 'Primitive roles/editor Assigned at Project Root',
        ruleType: 'Primitive Owner/Editor Role',
        severity: 'High',
        description: 'Service account has primitive roles/editor, allowing creation and deletion of BigQuery datasets, Compute Engine VMs, and Pub/Sub topics across the project.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Avoid broad editor access for batch data ingestion.' },
          { framework: 'CIS GCP 3.0', control: '1.5', title: 'Ensure No Service Accounts Have roles/editor', description: 'Replace primitive Editor with granular BigQuery Data Editor.' }
        ],
        blastRadiusImpact: 'Unrestricted modification of BigQuery schemas and Cloud Storage bucket retention policies.',
        whatBreaks: 'If pipeline provisions BigQuery tables dynamically, it must have bigquery.tables.create permission.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All BigQuery Datasets', 'Compute Engine', 'Cloud Pub/Sub', 'Cloud Dataflow'],
      privilegeEscalationVectors: ['iam.serviceAccountUser on Compute Engine default SA'],
      impactedResources: 'projects/prj-bigdata-lake-prod',
      whatBreaksAnalysis: 'Swap roles/editor for roles/bigquery.dataEditor and roles/bigquery.jobUser.',
      remediationSafetyNote: 'Audit active BigQuery jobs before revoking roles/editor.'
    },
    currentPolicy: `gcloud projects add-iam-policy-binding prj-bigdata-lake-prod \\
  --member="serviceAccount:data-lake-sync@analytics-pipeline.iam.gserviceaccount.com" \\
  --role="roles/editor"`,
    recommendedPolicy: `gcloud projects add-iam-policy-binding prj-bigdata-lake-prod \\
  --member="serviceAccount:data-lake-sync@analytics-pipeline.iam.gserviceaccount.com" \\
  --role="roles/bigquery.dataEditor"

gcloud projects add-iam-policy-binding prj-bigdata-lake-prod \\
  --member="serviceAccount:data-lake-sync@analytics-pipeline.iam.gserviceaccount.com" \\
  --role="roles/bigquery.jobUser"`,
    remediationCommand: `gcloud projects remove-iam-policy-binding prj-bigdata-lake-prod --member="serviceAccount:data-lake-sync@analytics-pipeline.iam.gserviceaccount.com" --role="roles/editor"`
  },
  {
    id: 'gcp-id-03',
    name: 'lead-platform-architect@fintech.io',
    provider: 'GCP',
    identityType: 'Human',
    scope: 'prj-fintech-core-prod',
    accountOrSubscriptionId: 'prj-fintech-core-prod',
    rolesOrPolicies: ['roles/resourcemanager.organizationAdmin', 'roles/owner'],
    riskScore: 88,
    riskLevel: 'Critical',
    lastActive: '3 hours ago',
    mfaEnabled: false,
    remediated: false,
    violations: [
      {
        id: 'viol-gcp-04',
        code: 'GCP-IAM-ORG-ADMIN-NO-2FA',
        title: 'Organization Administrator Account Without Enforced 2FA/Security Key',
        ruleType: 'Missing MFA / Broad Role',
        severity: 'Critical',
        description: 'Account holds top-level organization admin and project owner privileges without compulsory FIDO2 hardware security key enforcement.',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.1', title: 'Access Control', description: 'Enforce multi-factor verification for all organizational architects.' },
          { framework: 'CIS GCP 3.0', control: '1.2', title: 'Ensure Multi-Factor Authentication is Enforced', description: 'Enforce Google Workspace 2-step verification with security keys.' }
        ],
        blastRadiusImpact: 'Total compromise of GCP Organization hierarchy, folder structures, and VPC Service Controls.',
        whatBreaks: 'Enforcing context-aware access blocks logins originating outside trusted corporate endpoints.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['Google Cloud Organization Level', 'All Folders and Projects', 'Billing Accounts'],
      privilegeEscalationVectors: ['Full Organization Administrator takeover'],
      impactedResources: 'organizations/829104829182',
      whatBreaksAnalysis: 'Require security key via Google Admin Console and implement Privileged Access Manager (PAM).',
      remediationSafetyNote: 'Ensure at least two separate Super Admins exist before modifying policies.'
    },
    currentPolicy: `// Assigned permanent Organization Administrator
gcloud organizations add-iam-policy-binding 829104829182 \\
  --member="user:lead-platform-architect@fintech.io" \\
  --role="roles/resourcemanager.organizationAdmin"`,
    recommendedPolicy: `// Enforce Privileged Access Manager (PAM) Just-in-Time Grant
gcloud pam entitlements create org-admin-jit \\
  --max-request-duration=2h \\
  --eligible-users="user:lead-platform-architect@fintech.io" \\
  --role="roles/resourcemanager.organizationAdmin"`,
    remediationCommand: `gcloud organizations remove-iam-policy-binding 829104829182 --member="user:lead-platform-architect@fintech.io" --role="roles/owner"`
  },
  {
    id: 'gcp-id-04',
    name: 'k8s-workload-backup-sa@fintech-prod.iam.gserviceaccount.com',
    provider: 'GCP',
    identityType: 'Machine',
    scope: 'prj-fintech-core-prod',
    accountOrSubscriptionId: 'prj-fintech-core-prod',
    rolesOrPolicies: ['roles/storage.admin (Project-Wide)'],
    riskScore: 56,
    riskLevel: 'Medium',
    lastActive: '2 days ago',
    keyAgeDays: 45,
    remediated: false,
    violations: [
      {
        id: 'viol-gcp-05',
        code: 'GCP-STORAGE-PROJECT-WIDE-ADMIN',
        title: 'Project-Wide roles/storage.admin on Service Account',
        ruleType: 'Broad Resource Scope',
        severity: 'Medium',
        description: 'Service account has roles/storage.admin assigned at the project level instead of scoped strictly to the backup bucket (gs://fintech-k8s-backups).',
        complianceTags: [
          { framework: 'SOC 2', control: 'CC6.2', title: 'Least Privilege', description: 'Object storage roles must be assigned at bucket level.' },
          { framework: 'CIS GCP 3.0', control: '1.6', title: 'Avoid Project-Wide Storage Admin', description: 'Restrict storage admin roles to specific bucket URIs.' }
        ],
        blastRadiusImpact: 'Workload can delete other mission-critical buckets like terraform state or compliance audit logs.',
        whatBreaks: 'If backup utility attempts to create new temporary buckets in the project, it will fail.'
      }
    ],
    blastRadiusDetails: {
      servicesExposed: ['All Google Cloud Storage Buckets in Project'],
      privilegeEscalationVectors: ['storage.buckets.delete', 'storage.buckets.setIamPolicy'],
      impactedResources: 'projects/prj-fintech-core-prod/buckets/*',
      whatBreaksAnalysis: 'Grant roles/storage.objectAdmin directly on gs://fintech-k8s-backups.',
      remediationSafetyNote: 'Ensure bucket object versioning is enabled on the target backup bucket.'
    },
    currentPolicy: `gcloud projects add-iam-policy-binding prj-fintech-core-prod \\
  --member="serviceAccount:k8s-workload-backup-sa@fintech-prod.iam.gserviceaccount.com" \\
  --role="roles/storage.admin"`,
    recommendedPolicy: `gsutil iam ch \\
  serviceAccount:k8s-workload-backup-sa@fintech-prod.iam.gserviceaccount.com:roles/storage.objectAdmin \\
  gs://fintech-k8s-backups`,
    remediationCommand: `gcloud projects remove-iam-policy-binding prj-fintech-core-prod --member="serviceAccount:k8s-workload-backup-sa@fintech-prod.iam.gserviceaccount.com" --role="roles/storage.admin"`
  },
  {
    id: 'gcp-id-05',
    name: 'stackdriver-monitoring-agent@fintech-prod.iam.gserviceaccount.com',
    provider: 'GCP',
    identityType: 'Machine',
    scope: 'prj-fintech-core-prod',
    accountOrSubscriptionId: 'prj-fintech-core-prod',
    rolesOrPolicies: ['roles/monitoring.metricWriter', 'roles/logging.logWriter'],
    riskScore: 14,
    riskLevel: 'Low',
    lastActive: '2 minutes ago',
    keyAgeDays: 0, // Using Compute Engine metadata server token
    remediated: false,
    violations: [],
    blastRadiusDetails: {
      servicesExposed: ['Cloud Monitoring and Cloud Logging ingestion endpoints'],
      privilegeEscalationVectors: ['None'],
      impactedResources: 'projects/prj-fintech-core-prod',
      whatBreaksAnalysis: 'Compliant telemetry agent using temporary OAuth2 access tokens via instance metadata.',
      remediationSafetyNote: 'No remediation required.'
    },
    currentPolicy: `{
  "bindings": [
    {
      "role": "roles/monitoring.metricWriter",
      "members": ["serviceAccount:stackdriver-monitoring-agent@fintech-prod.iam.gserviceaccount.com"]
    },
    {
      "role": "roles/logging.logWriter",
      "members": ["serviceAccount:stackdriver-monitoring-agent@fintech-prod.iam.gserviceaccount.com"]
    }
  ]
}`,
    recommendedPolicy: `{
  "bindings": [
    {
      "role": "roles/monitoring.metricWriter",
      "members": ["serviceAccount:stackdriver-monitoring-agent@fintech-prod.iam.gserviceaccount.com"]
    },
    {
      "role": "roles/logging.logWriter",
      "members": ["serviceAccount:stackdriver-monitoring-agent@fintech-prod.iam.gserviceaccount.com"]
    }
  ]
}`,
    remediationCommand: `# Identity is compliant with least privilege principles`
  },
  {
    id: 'gcp-id-06',
    name: 'finops-reporter@fintech.io',
    provider: 'GCP',
    identityType: 'Human',
    scope: 'prj-fintech-core-prod',
    accountOrSubscriptionId: 'prj-fintech-core-prod',
    rolesOrPolicies: ['roles/billing.viewer'],
    riskScore: 9,
    riskLevel: 'Low',
    lastActive: '4 hours ago',
    mfaEnabled: true,
    remediated: false,
    violations: [],
    blastRadiusDetails: {
      servicesExposed: ['Cloud Billing Cost Reports'],
      privilegeEscalationVectors: ['None'],
      impactedResources: 'billingAccounts/012345-6789AB-CDEF01',
      whatBreaksAnalysis: 'Read-only financial analyst with Google Titan hardware token 2FA.',
      remediationSafetyNote: 'Compliant.'
    },
    currentPolicy: `gcloud organizations add-iam-policy-binding 829104829182 \\
  --member="user:finops-reporter@fintech.io" \\
  --role="roles/billing.viewer"`,
    recommendedPolicy: `gcloud organizations add-iam-policy-binding 829104829182 \\
  --member="user:finops-reporter@fintech.io" \\
  --role="roles/billing.viewer"`,
    remediationCommand: `# Identity is compliant`
  }
];
