# CitadelSecure Data Model

This document describes the database tables added by CitadelSecure on top of the base CISO Assistant platform.

---

## Quick Reference

| Table | Purpose | Created In |
|-------|---------|------------|
| `Integration` | Connections to AWS, GitHub, etc. | Phase 1 |
| `Asset` (extended) | Cloud resources with source tracking | Phase 2 |
| `AssetRelationship` | How assets connect to each other | Phase 4 |
| `SecurityCheck` | Security test definitions from Prowler | Phase 5 |
| `CheckResult` | Pass/fail results per asset | Phase 6 |
| `ControlRequirementMapping` | Links controls to framework requirements | Phase 6.5 |
| `SCFControl` | Unified controls from SCF framework | Phase 6.6 |
| `SCFFrameworkMapping` | Links SCF controls to framework requirements | Phase 6.6 |
| `Evidence` (extended) | Scan evidence with raw output | Phase 7 |

---

## Phase 1: Integrations

### Integration

Stores connection details for external services (AWS accounts, GitHub orgs, etc.).

| Field | What It Stores |
|-------|----------------|
| `name` | Display name (e.g., "ACME Production AWS") |
| `provider` | Service type: `aws`, `github`, `okta`, `azure`, `jira` |
| `status` | Connection state: `pending`, `connected`, `disconnected`, `error` |
| `aws_role_arn` | AWS IAM role ARN for cross-account access |
| `aws_external_id` | Security token for role assumption |
| `aws_regions` | Which AWS regions to scan |
| `sync_enabled` | Whether automatic sync is on |
| `last_sync_at` | When assets were last synced |
| `last_error` | Most recent error message |
| `error_count` | How many consecutive errors |

**Example:** An Integration record for ACME's AWS account stores the IAM role ARN that lets us read their cloud resources.

---

## Phase 2: Asset Discovery

### Asset (Extended Fields)

The base Asset model exists in CISO Assistant. We added fields to track where assets came from.

| Field | What It Stores |
|-------|----------------|
| `source` | Where the asset came from: `aws`, `azure`, `manual`, etc. |
| `source_id` | External identifier (e.g., AWS ARN) |
| `source_integration` | Link to the Integration that discovered it |
| `raw_source_data` | Full API response from the cloud provider (JSON) |
| `last_seen_at` | When we last saw this asset in a sync |
| `is_active` | False if the asset was deleted in the cloud |

**Example:** An EC2 instance discovered from AWS has `source=aws`, `source_id=arn:aws:ec2:us-east-1:123456789:instance/i-abc123`.

---

## Phase 4: Asset Relationships

### AssetRelationship

Tracks how assets connect to each other for dependency mapping.

| Field | What It Stores |
|-------|----------------|
| `source_asset` | The "from" asset |
| `target_asset` | The "to" asset |
| `relationship_type` | How they relate (see types below) |
| `is_active` | False if relationship no longer exists |
| `discovered_at` | When we found this relationship |
| `ended_at` | When the relationship ended (if inactive) |
| `evidence` | Raw API data proving the relationship |

**Relationship Types:**

| Type | Meaning | Example |
|------|---------|---------|
| `belongs_to` | Contained within | EC2 instance → VPC |
| `protected_by` | Secured by | EC2 instance → Security Group |
| `assumes` | Uses identity of | Lambda function → IAM Role |
| `encrypted_by` | Data encrypted with | S3 bucket → KMS Key |
| `routes_to` | Sends traffic to | Load Balancer → EC2 instance |
| `attached_to` | Physically connected | EBS volume → EC2 instance |
| `allows_from` | Accepts traffic from | Security Group → Security Group |

**Example:** An EC2 instance "belongs_to" a VPC and is "protected_by" a Security Group.

---

## Phase 5: Security Checks

### SecurityCheck

Definitions of security tests from Prowler (what to check).

| Field | What It Stores |
|-------|----------------|
| `check_id` | Prowler check ID (e.g., `s3_bucket_default_encryption`) |
| `provider` | Scanner: `prowler`, `aws_config`, `custom` |
| `title` | Human-readable name |
| `description` | What the check verifies |
| `severity` | Risk level: `critical`, `high`, `medium`, `low`, `informational` |
| `service` | AWS service: `s3`, `ec2`, `iam`, etc. |
| `is_active` | Whether to run this check |
| `mapped_requirements` | Framework requirements this check satisfies (M2M) |
| `mapped_controls` | Reference controls this implements (M2M) |

**Example:** The check `s3_bucket_default_encryption` verifies S3 buckets have encryption enabled. It maps to SOC2 CC6.1 and ISO 27001 A.8.24.

### SecurityCheckImport

Audit trail of when Prowler checks were imported.

| Field | What It Stores |
|-------|----------------|
| `imported_at` | When the import ran |
| `prowler_version` | Which Prowler version |
| `checks_created` | How many new checks added |
| `checks_updated` | How many existing checks modified |
| `mappings_added` | How many requirement mappings created |

---

## Phase 6: Automated Scanning

### CheckResult

Results from running security checks against assets (pass/fail per asset).

| Field | What It Stores |
|-------|----------------|
| `security_check` | Which check was run |
| `asset` | Which asset was tested |
| `integration` | Which integration triggered the scan |
| `status` | Result: `pass`, `fail`, `error`, `not_applicable` |
| `status_extended` | Detailed explanation from Prowler |
| `scanned_at` | When the check ran |
| `raw_output` | Full Prowler JSON output |

**Example:** A CheckResult shows that `acme-web-server` failed the `ec2_instance_public_ip` check because it has a public IP address.

---

## Phase 6.5: Auto-Create Controls

### AppliedControl (Extended Fields)

Controls are what you implement to meet compliance requirements. We added fields to track scan results.

| Field | What It Stores |
|-------|----------------|
| `origin` | How created: `manual` (user) or `scan` (auto-generated) |
| `security_checks` | Which checks validate this control (M2M) |
| `security_posture` | Overall status: `passing`, `partial`, `issues`, `not_scanned` |
| `security_checks_passed` | Count of passing checks |
| `security_checks_failed` | Count of failing checks |
| `security_checks_error` | Count of errored checks |
| `security_checks_total` | Total applicable checks |
| `last_security_scan_at` | When posture was last updated |
| `scf_control` | Link to unified SCF control (Phase 6.6) |
| `source_requirement` | *Deprecated* - use `scf_control` instead |

**Example:** Control "SCF-IAC-01: Identity & Access Management" has 5 security checks, 4 passing and 1 failing, so `security_posture=partial`.

### ControlRequirementMapping

Links controls to the framework requirements they satisfy.

| Field | What It Stores |
|-------|----------------|
| `applied_control` | The control |
| `requirement` | The framework requirement (e.g., SOC2 CC6.1) |
| `mapping_type` | How linked: `auto` (from scan) or `manual` (user assigned) |

**Example:** Control "Data Encryption" maps to both SOC2 CC6.1 and ISO 27001 A.8.24.

---

## Phase 6.6: Unified Control Layer (SCF)

### SCFControl

Controls from the Secure Controls Framework - a unified taxonomy that maps across 100+ compliance frameworks.

| Field | What It Stores |
|-------|----------------|
| `scf_id` | SCF identifier (e.g., `TEC-10.1`, `IAC-01`) |
| `name` | Control name |
| `description` | What the control requires |
| `domain` | Category code: `TEC`, `IAC`, `GOV`, etc. |
| `domain_name` | Category name: "Technology", "Identity & Access", "Governance" |
| `security_checks` | Prowler checks that validate this control (M2M) |

**Why SCF?** Instead of creating separate controls for SOC2, ISO, and NIST, one SCF control satisfies all three. "Prove once, satisfy many."

**Example:** SCF control `TEC-10.1` (Data Protection at Rest) maps to SOC2 CC6.1, ISO 27001 A.8.24, and NIST CSF PR.DS-1.

### SCFFrameworkMapping

Links SCF controls to specific framework requirements.

| Field | What It Stores |
|-------|----------------|
| `scf_control` | The unified SCF control |
| `requirement` | The framework requirement it satisfies |
| `relationship` | Mapping type: `equal`, `subset`, `superset`, `intersects` |

**Example:** `SCFControl(TEC-10.1)` → `RequirementNode(SOC2 CC6.1)` with relationship `intersects`.

---

## Phase 7: Evidence Automation

### Evidence (Extended Fields)

Evidence proves compliance. We added fields to link scan results as automated evidence.

| Field | What It Stores |
|-------|----------------|
| `origin` | How created: `manual` or `scan` |
| `source_integration` | Which integration generated this evidence |
| `source_check_result` | Link to the specific scan result (1:1) |
| `generated_at` | When auto-generated |
| `is_continuous` | True if auto-updated on each scan |

**Example:** When Prowler finds an S3 bucket is encrypted, it creates Evidence linked to that CheckResult. The evidence contains the full Prowler JSON as proof.

---

## How It All Connects

**The compliance automation flow:**

1. **Integration** connects to customer's AWS account
2. **Asset** records are created for each cloud resource discovered
3. **AssetRelationship** records show how assets connect
4. **SecurityCheck** definitions specify what to test
5. **CheckResult** records store pass/fail per asset per check
6. **SCFControl** provides unified control taxonomy
7. **AppliedControl** tracks overall control status across all assets
8. **ControlRequirementMapping** links controls to framework requirements
9. **Evidence** stores scan results as audit-ready proof

**Key relationships:**

| From | To | Relationship |
|------|-----|--------------|
| Asset | Integration | `source_integration` FK |
| Asset | Asset | via `AssetRelationship` |
| CheckResult | Asset | FK |
| CheckResult | SecurityCheck | FK |
| CheckResult | Integration | FK |
| Evidence | CheckResult | `source_check_result` FK |
| AppliedControl | SCFControl | `scf_control` FK |
| AppliedControl | SecurityCheck | M2M |
| AppliedControl | RequirementNode | via `ControlRequirementMapping` |
| SCFControl | RequirementNode | via `SCFFrameworkMapping` |
| SCFControl | SecurityCheck | M2M |
| SecurityCheck | RequirementNode | `mapped_requirements` M2M |

---

## Database Tables Summary

All tables use `core_` prefix except Integration (`integrations_integration`).

| Table Name | Records (typical) |
|------------|-------------------|
| `integrations_integration` | 1-5 per customer |
| `core_asset` | 50-500 per customer |
| `core_assetrelationship` | 100-1000 per customer |
| `core_securitycheck` | ~580 (Prowler checks) |
| `core_securitycheckimport` | 1-5 (import history) |
| `core_checkresult` | 100-5000 per scan |
| `core_scfcontrol` | ~1,340 (SCF framework) |
| `core_scfframeworkmapping` | ~500+ (SCF→framework links) |
| `core_appliedcontrol` | 10-200 per customer |
| `core_controlrequirementmapping` | 20-500 per customer |
| `core_evidence` | 100-5000 per customer |

---

## Related Documentation

- [DATABASE.md](./DATABASE.md) - Multi-tenant infrastructure and routing
- [data-model.md](../../documentation/architecture/data-model.md) - Base CISO Assistant models
- [Feature Roadmap](../features/ROADMAP.md) - Phase descriptions
- [Unified Control Architecture](../features/UNIFIED_CONTROL_ARCHITECTURE.md) - SCF deep dive
