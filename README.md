# Phase 7: Evidence Automation

Automatically generate Evidence records from Prowler security scan results with full raw output preservation.

---

## Overview

When security scans run, this phase automatically creates one Evidence record per CheckResult. Each Evidence contains the complete raw Prowler JSON output as proof, linked via foreign key to the CheckResult for live data access.

---

## Data Model Changes

**Evidence** (extended):
| Field | Type | Purpose |
|-------|------|---------|
| `origin` | CharField | `manual` or `scan` (auto-created) |
| `source_integration` | FK → Integration | The integration that generated this evidence |
| `source_check_result` | OneToOne → CheckResult | The specific scan result this evidence documents |
| `generated_at` | DateTime | When the evidence was auto-generated |
| `is_continuous` | Boolean | True for auto-updated evidence (vs point-in-time) |

**EvidenceRevision** (existing):
| Field | Type | Purpose |
|-------|------|---------|
| `observation` | TextField | Contains pretty-printed raw_output JSON |

---

## Evidence Naming Convention

```
{Asset Name}: {Security Check Title}

Examples:
acme-web-1: Check for EC2 Instances with Public IP.
acme-backups: Ensure there are no S3 buckets open to Everyone or Any AWS user.
acme-db-primary: Check for EC2 Instances with Public IP.
```

---

## Data Flow

```
Prowler Scan
     │
     ▼
CheckResult (with raw_output JSON)
     │
     ▼
AutoEvidenceService.process_check_results()
     │
     ▼
Evidence (1:1 with CheckResult)
     │
     ├── source_check_result (FK to CheckResult)
     ├── status = IN_REVIEW (requires human approval)
     ├── origin = 'scan'
     └── is_continuous = True

     │
     ▼
EvidenceRevision
     └── observation = raw_output JSON (pretty-printed)
```

---

## Key Design Decisions

| Question | Decision |
|----------|----------|
| Evidence per Asset or per CheckResult? | **Per CheckResult** (granular, one evidence = one proof) |
| Store raw_output copy or FK to CheckResult? | **FK** (no duplication, always current) |
| What if CheckResult is deleted? | Evidence remains, `source_check_result` becomes NULL |
| Evidence for failing checks? | **Yes** - evidence documents both pass AND fail |
| Initial status? | `IN_REVIEW` - requires human approval before acceptance |

---

## Key Files

| File | Purpose |
|------|---------|
| [auto_evidence_service.py](../../../backend/core/security_check_utils/auto_evidence_service.py) | Main service - creates Evidence per CheckResult |
| [serializers.py](../../../backend/core/serializers.py) | EvidenceReadSerializer with `source_check_result` nested data |
| [+page.svelte](../../../frontend/src/routes/(app)/(third-party)/evidences/[id=uuid]/+page.svelte) | Evidence detail page with raw log viewer |
| [0122_add_evidence_checkresult_link.py](../../../backend/core/migrations/0122_add_evidence_checkresult_link.py) | Migration - cleanup old evidence |
| [0123_add_evidence_source_check_result_fk.py](../../../backend/core/migrations/0123_add_evidence_source_check_result_fk.py) | Migration - add FK field |

---

## Frontend: Evidence Detail Page

For scan-generated evidence, the detail page shows:

1. **Asset Section** - Name, type, ARN/source_id
2. **Security Check Section** - Check ID, severity, title, pass/fail result
3. **Raw Evidence Log** - Full Prowler JSON with "Copy JSON" button
4. **Scan Details** - Timestamp, integration, "Auto-generated" badge

These sections appear below the standard detail view for evidence with `origin = 'Security Scan'` and a linked `source_check_result`.

---

## API Response

The Evidence API returns nested CheckResult data:

```json
{
  "id": "2b937968-5078-46cb-88cd-7475e70e5e24",
  "name": "acme-web-1: Check for EC2 Instances with Public IP.",
  "origin": "Security Scan",
  "status": "In review",
  "source_check_result": {
    "id": "663a8fad-f3b7-44fd-aa23-ee7867b27139",
    "status": "pass",
    "status_extended": "EC2 Instance i-acme-web-1 has a private IP",
    "scanned_at": "2026-01-07T16:55:51.123Z",
    "raw_output": {
      "AccountId": "000000000000",
      "Region": "us-east-1",
      "ResourceArn": "arn:aws:ec2:us-east-1:000000000000:instance/i-acme-web-1",
      "Status": "PASS",
      "StatusExtended": "EC2 Instance i-acme-web-1 has a private IP",
      "_engine": {
        "name": "prowler",
        "version": "3.x",
        "region": "us-east-1",
        "account_id": "000000000000"
      }
    },
    "asset": {
      "id": "...",
      "name": "acme-web-1",
      "type": "ec2_instance",
      "source_id": "arn:aws:ec2:us-east-1:000000000000:instance/i-acme-web-1"
    },
    "security_check": {
      "id": "...",
      "check_id": "ec2_instance_public_ip",
      "title": "Check for EC2 Instances with Public IP.",
      "severity": "high"
    }
  }
}
```

---

## Usage

The AutoEvidenceService is called automatically after Prowler scans complete (in `ComplianceEngineService`):

```python
from core.security_check_utils.auto_evidence_service import AutoEvidenceService

service = AutoEvidenceService(integration=integration, scan_time=scan_time)
created, updated = service.process_check_results(check_results)
```

---

## Scan Result Metrics

After a scan, the result includes evidence counts:

```json
{
  "results_created": 7,
  "checks_passed": 4,
  "checks_failed": 3,
  "controls_created": 5,
  "controls_updated": 2,
  "evidence_created": 7,
  "evidence_updated": 0
}
```

---

## Phase 7.1: Resource Snapshots

In addition to the Prowler OCSF output, the system captures actual AWS resource configuration:

- **Resource Snapshot**: Actual AWS API response (e.g., `s3:GetPublicAccessBlock`)
- **Snapshot API Call**: The AWS API used to capture the config
- **Compliance History**: Timeline of status changes with snapshots

This gives auditors proof of what AWS returned when the check was evaluated, not just Prowler's verdict.

---

## Phase 7.2: Configuration Drift Tracking

History entries are created when:
1. **Status changes** (pass→fail or fail→pass)
2. **Config changes** (even if status stays the same)

Each history entry stores the **previous** config snapshot, creating a complete audit trail of configuration evolution. The UI distinguishes between:
- **Status changes**: Green/red border with old→new status badges
- **Config-only changes**: Blue border with "(config changed)" label

---

## Migration Notes

**Migration 0122**: Cleans up old scan evidence from the previous design (which stored summary text per AppliedControl instead of raw output per CheckResult).

**Migration 0123**: Adds the `source_check_result` OneToOneField to Evidence model.

**Migration 0125**: Adds `resource_snapshot`, `snapshot_api_call`, `snapshot_captured` fields to CheckResult and creates `CheckResultHistory` model.

The migrations were split to avoid PostgreSQL trigger conflicts (django-auditlog) when combining data cleanup with schema changes in the same transaction.

---

## Related Documentation

- [Auto-Create Controls](../auto-create-controls/README.md) - Phase 6.5: Controls from scans
- [Asset Discovery](../asset-discovery/README.md) - Asset sync from cloud providers
- [Feature Roadmap](../ROADMAP.md) - Overall project phases
