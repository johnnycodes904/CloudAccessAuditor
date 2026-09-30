# CloudAccessAuditor — Multi-Cloud CIEM Governance Engine

> **PROPRIETARY & CONFIDENTIAL**  
> Copyright © 2026. All Rights Reserved.  
> Commercialization & enterprise deployment documentation.

---

## 1. Executive Overview

**CloudAccessAuditor** is an enterprise-grade Cloud Infrastructure Entitlement Management (CIEM) access governance platform and blast-radius evaluation engine. It continuously discovers, inspects, normalizes, and mitigates excessive entitlements across **Amazon Web Services (AWS)**, **Microsoft Azure (Entra ID / RBAC)**, and **Google Cloud Platform (GCP)**.

The engine normalizes heterogeneous cloud policy documents into a unified, vendor-neutral security model, computes a deterministic **Risk Score (1–100)**, assesses **"What Breaks"** operational blast radius, maps findings to **SOC 2** and **CIS Benchmarks**, and synthesizes least-privilege remediation scripts (CLI and Terraform IaC).

```
                      ┌───────────────────────────────────────┐
                      │ Raw Cloud Policy Ingestion Engine    │
                      │ (AWS IAM / Azure RBAC / GCP IAM)      │
                      └──────────────────┬────────────────────┘
                                         │ Auto-Detection & Key Precedence
                                         ▼
                      ┌───────────────────────────────────────┐
                      │    Unified CIEM Data Model & Mapping  │
                      └──────────────────┬────────────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              ▼                          ▼                          ▼
    ┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
    │ Risk & Violation │       │   Blast-Radius   │       │ Compliance Engine│
    │  Scoring Engine  │       │  Impact Analysis │       │ (SOC 2 / CIS)    │
    │ (1-100 Posture)  │       │  ("What Breaks") │       │                  │
    └─────────┬────────┘       └─────────┬────────┘       └─────────┬────────┘
              │                          │                          │
              └──────────────────────────┼──────────────────────────┘
                                         ▼
                      ┌───────────────────────────────────────┐
                      │ Interactive Remediation & Diff Engine │
                      │ - Side-by-Side Native Policy Diff     │
                      │ - Native CLI Shell Scripting          │
                      │ - Scoped Terraform IaC Generation     │
                      │ - Formula-Safe CSV / GRC Evidence JSON│
                      └───────────────────────────────────────┘
```

---

## 2. Unified Data Model & JSON Schemas

### 2.1 Unified Identity Schema (`CloudIdentity`)

Every cloud identity ingested into the system—whether an AWS IAM Role, an Azure Service Principal, or a GCP Service Account—is mapped to the canonical `CloudIdentity` contract:

```typescript
export interface CloudIdentity {
  id: string;                      // Unique CIEM identifier
  name: string;                    // Principal name or display email
  provider: 'AWS' | 'Azure' | 'GCP';
  identityType: 'Human' | 'Machine';
  scope: string;                   // Account ID, Subscription ID, or Project ID
  accountOrSubscriptionId: string;
  rolesOrPolicies: string[];       // Assigned role definitions or policy names
  riskScore: number;               // Normalized score: 1 (Compliant) to 100 (Critical)
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  originalRiskScore?: number;      // Preserves pre-remediation score for rollback
  originalRiskLevel?: RiskLevel;
  violations: Violation[];         // Active policy violations
  lastActive: string;              // Activity timestamp or relative age
  mfaEnabled?: boolean;            // Human identity credential hygiene
  keyAgeDays?: number;             // Static key age (GCP / AWS)
  secretExpiryDays?: number;       // App registration secret age (Azure)
  currentPolicy: string;           // Native JSON/HCL over-permissioned policy
  recommendedPolicy: string;       // Scoped least-privilege policy replacement
  remediationCommand: string;      // Native cloud CLI command string
  remediationTerraform?: string;   // Terraform IaC replacement block
  remediated: boolean;             // Remediation enforcement status
  blastRadiusDetails: BlastRadiusDetails;
}
```

### 2.2 Ingestion Schemas & Precedence Rules

The ingestion engine evaluates dropped or pasted JSON payloads via `detectProviderSchema`:

| Target Provider | Required / Discriminator Keys | Structural Clues |
| :--- | :--- | :--- |
| **Unified CIEM** | `identities` array, or top-level array where `item.provider` and `item.riskScore` are present | Proprietary CloudAccessAuditor export schema |
| **AWS IAM** | `Statement`, `PolicyDocument`, `RoleName`, `AssumeRolePolicyDocument` | Contains `arn:aws:iam`, `sts:AssumeRole`, or `aws:MultiFactorAuthPresent` |
| **Azure RBAC** | `roleAssignments`, `properties.roleDefinitionName`, top-level array with `Microsoft.Authorization/roleAssignments` | Scope matches `/subscriptions/{subId}`, `principalType`, `principalName` |
| **GCP Cloud IAM** | `bindings`, `serviceAccountEmail`, `projectId` | Role matches `roles/{name}`, `serviceAccount:{email}`, or `user:{email}` |

#### Example 1: AWS IAM Input Schema
```json
{
  "Version": "2012-10-17",
  "RoleName": "production-ci-deployer",
  "AccountId": "110293847561",
  "Statement": [
    {
      "Sid": "UnscopedAdmin",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "ConfusedDeputyRisk",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Principal": "*"
    }
  ]
}
```

#### Example 2: Azure CLI RBAC Array Export (`az role assignment list`)
```json
[
  {
    "id": "/subscriptions/c45b8492-4f30-4e4b-9cf7-4f621ad75390/providers/Microsoft.Authorization/roleAssignments/8a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
    "name": "8a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d",
    "type": "Microsoft.Authorization/roleAssignments",
    "properties": {
      "roleDefinitionName": "Owner",
      "principalId": "c891f930-b9df-416a-932f-488f57fa2391",
      "principalName": "github-actions-deployer",
      "principalType": "ServicePrincipal",
      "scope": "/subscriptions/c45b8492-4f30-4e4b-9cf7-4f621ad75390",
      "createdOn": "2024-03-15T14:22:18.0000000Z"
    }
  }
]
```

#### Example 3: GCP Cloud IAM Policy Binding Schema
```json
{
  "projectId": "prj-payments-backend-prod",
  "serviceAccountEmail": "webhook-runner@prj-payments-backend-prod.iam.gserviceaccount.com",
  "keyAgeDays": 140,
  "bindings": [
    {
      "role": "roles/owner",
      "members": [
        "serviceAccount:webhook-runner@prj-payments-backend-prod.iam.gserviceaccount.com"
      ]
    }
  ]
}
```

---

## 3. Structured Prompts & LLM Reasoning Pipelines

When integrating with large language models or autonomous policy synthesis agents (e.g. Gemini API), the engine relies on strict, zero-shot structured prompts that enforce schema compliance and security boundaries.

### 3.1 Least-Privilege Remediation Synthesis Prompt

```markdown
SYSTEM:
You are an expert cloud security architect and CIEM policy analyst.
Your objective is to analyze an over-permissioned cloud access policy (AWS IAM, Azure RBAC, or GCP IAM)
and synthesize a minimal, least-privilege replacement policy with zero ambient privilege escalation paths.

INPUT CONSTRAINTS:
1. Provider: {{provider}} ("AWS" | "Azure" | "GCP")
2. Current Policy Document: {{currentPolicy}}
3. Principal Name & Scope: {{identityName}} in {{scope}}
4. Observed Workload Needs: {{observedActions}}

STRICT RULES:
- Never emit wildcard actions ("*", "s3:*", "roles/owner", "roles/editor").
- Never allow cross-account AssumeRole without external conditions or OIDC federated trust.
- For Azure, scope role assignments to the target Resource Group rather than the subscription root.
- For GCP, map primitive roles to predefined granular roles (e.g., container.developer, clouddeploy.releaser).
- Return valid JSON matching the Output Schema below without markdown fences or comments inside JSON strings.

OUTPUT SCHEMA:
{
  "riskScore": number, // Estimated new risk score (1-30)
  "scopedPolicy": string, // Formatted JSON string of the recommended least-privilege policy
  "remediationCommand": string, // One-line CLI command to apply change
  "remediationTerraform": string, // Terraform HCL code block
  "whatBreaksAnalysis": string, // Plain-English explanation of broken dependencies
  "servicesExposed": string[], // List of services explicitly allowed
  "mitigationSafeguardNote": string // Log verification check before cutover
}
```

### 3.2 Blast-Radius & "What Breaks" Evaluation Prompt

```markdown
SYSTEM:
You are an infrastructure reliability engineer and threat modeling specialist.

TASK:
Analyze the delta between an over-permissioned policy and its proposed least-privilege replacement.
Identify all services, dependencies, and deployment pipelines that could fail if this policy is applied
without prior coordination.

INPUT:
- Provider: {{provider}}
- Current Wildcards: {{wildcardList}}
- Scoped Targets: {{scopedResources}}

EVALUATION CHECKLIST:
1. CI/CD Pipeline Impact: Does this break automated Terraform/Pulumi/CDK deployments?
2. Secret Rotation: Does this revoke key rotation privileges in Key Vault / KMS?
3. Interservice Auth: Do background microservices lose SQS/PubSub/ServiceBus queues?
4. Rollback Feasibility: Can this change be reverted via an atomic CLI command in < 30 seconds?
```

---

## 4. API Integration & Execution Methods

### 4.1 Native Cloud CLI Ingestion & Enforcement

Remediations produce copyable, native cloud CLI commands that can be piped into CI/CD pipelines:

#### AWS CLI
```bash
# Apply scoped least-privilege policy to target role
aws iam put-role-policy \
  --role-name prod-ci-deployer-role \
  --policy-name ScopedLeastPrivilege \
  --policy-document file://scoped.json
```

#### Azure CLI
```bash
# Revoke broad subscription-level assignment
az role assignment delete \
  --assignee "c891f930-b9df-416a-932f-488f57fa2391" \
  --role "Owner" \
  --scope "/subscriptions/c45b8492-4f30-4e4b-9cf7-4f621ad75390"

# Re-assign granular Contributor at Resource Group scope
az role assignment create \
  --assignee "c891f930-b9df-416a-932f-488f57fa2391" \
  --role "Contributor" \
  --scope "/subscriptions/c45b8492-4f30-4e4b-9cf7-4f621ad75390/resourceGroups/rg-workload-prod"
```

#### Google Cloud SDK (`gcloud`)
```bash
# Remove primitive project root owner binding
gcloud projects remove-iam-policy-binding "prj-payments-backend-prod" \
  --member="serviceAccount:webhook-runner@prj-payments-backend-prod.iam.gserviceaccount.com" \
  --role="roles/owner"

# Grant predefined container developer role
gcloud projects add-iam-policy-binding "prj-payments-backend-prod" \
  --member="serviceAccount:webhook-runner@prj-payments-backend-prod.iam.gserviceaccount.com" \
  --role="roles/container.developer"
```

### 4.2 GRC Evidence Export Methods

The engine provides client-side reporting APIs:

* **CSV Evidence Export (`exportIdentitiesToCsv`)**:
  - Compliant with **RFC 4180**.
  - **CWE-1236 Neutralization**: Sanitizes values starting with `=`, `+`, `-`, `@`, `\t`, or `\r` by prefixing a single quote `'` to prevent Excel Formula Injection.
* **JSON Audit Archive (`exportIdentitiesToJson`)**:
  - Full structured JSON export containing timestamp, framework coverage metadata, posture score, over-privileged ratios, and complete identity records.
* **Deferred Revocation**:
  - Browser Blob downloads defer `URL.revokeObjectURL(url)` via `setTimeout` (200ms) to ensure WebKit and Chromium network pipelines do not abort active streams.

---

## 5. Security & Risk Engine Specifications

### 5.1 Dynamic Risk Scoring Matrix

The risk engine computes a continuous score between **1 and 100**:

$$\text{Risk Score} = \min\left(100, \max\left(10, \text{Base} + \sum \text{Violation Weights}\right)\right)$$

| Severity Band | Risk Score Range | Criteria | Badge Styling |
| :--- | :--- | :--- | :--- |
| **Critical** | $\ge 80$ | Wildcard admin (`*:*`), Unrestricted AssumeRole, Subscription `Owner` | Red Pulse |
| **High** | $60 - 79$ | Primitive `roles/editor`, Stale secrets (>180d), Missing MFA on human admins | Amber |
| **Medium** | $30 - 59$ | Stale service account keys (>90d), Unscoped read on confidential buckets | Yellow |
| **Low** | $< 30$ | Scoped least-privilege policies, MFA enabled, Key rotation compliant | Emerald |

### 5.2 Compliance Framework Mappings

All violations are cross-indexed to regulatory standards:

* **SOC 2 Type II (Trust Services Criteria)**:
  - `CC6.1`: Logical access restrictions on workloads and data.
  - `CC6.2`: Implementation of role-based least privilege.
  - `CC6.3`: Revocation, credential hygiene, and key rotation within 90 days.
* **CIS Benchmarks**:
  - `CIS AWS Benchmark v3.0` (Controls 1.16, 1.20)
  - `CIS Microsoft Azure Benchmark v2.1` (Controls 1.2, 1.23)
  - `CIS Google Cloud Platform Benchmark v3.0` (Controls 1.4, 1.5, 1.7)

### 5.3 Shell Metacharacter Neutralization

Any values interpolated into shell strings are sanitized through a strict whitelist filter:
```typescript
function sanitizeShellIdentifier(val: string): string {
  if (!val) return 'unknown';
  return val.replace(/[^a-zA-Z0-9_\-./@:]/g, '');
}
```
This guarantees that identity names or project IDs containing backticks, semicolons, or command substitutions cannot execute arbitrary shell code when security engineers copy remediation commands.

---

## 6. Architecture & Tech Stack

| Layer | Technology |
| :--- | :--- |
| **Framework** | Next.js / React 19 (SPA Architecture) |
| **Styling** | Tailwind CSS v4 |
| **Icons** | Lucide-React |
| **Compilation** | Vite 6 + TypeScript (Strict Mode) |
| **State** | Zero-latency pure client-side state with rollback history |
| **Security** | Zero-trust input sanitization, CWE-1236 mitigation, non-root execution |

---

## 7. Development & Verification Commands

```bash
# Install dependencies
npm install

# Run development server (Port 3000)
npm run dev

# Run TypeScript linter
npm run lint

# Production build verification
npm run build
```

---

## 8. Proprietary Notice

This software is **Proprietary and Confidential**. All title, copyright, intellectual property, and commercialization rights remain strictly with the owner. Unauthorized copying, reverse engineering, redistribution, or deployment is strictly prohibited under the terms of the project [LICENSE](./LICENSE).
