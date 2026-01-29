# Scanning Layer Flow

Complete documentation of the scan-to-mapping data flow in CitadelSecure, verified against actual code implementation.

**Last Updated:** 2026-01-19
**Verified Against:** Current codebase (all claims cross-referenced with source code)

---

## Overview

When a user triggers "Sync & Scan" from the Integrations page, CitadelSecure executes a 6-step pipeline that creates and links:

1. **Assets** - AWS resources discovered via API
2. **CheckResults** - Pass/fail results per asset per security check
3. **AppliedControls** - Unified controls satisfying framework requirements
4. **Policies** - Policy records auto-created from templates
5. **Evidence** - Audit trail records for compliance proof
6. **Requirement Mappings** - Links controls to framework requirements

---

## Complete Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           USER TRIGGERS SCAN                                    │
│                    Frontend: /integrations/[id]/+page.svelte                    │
│                    Backend: IntegrationViewSet.scan() (views.py:140-248)        │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         STEP 1: ASSET SYNC                                      │
│                    SyncService.sync_assets() (sync.py:135-300)                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  • Queries AWS via AWSProvider for all resources                                │
│  • Creates/updates Asset records (dedupe by source + source_id)                 │
│  • Extracts relationships (EC2→VPC, Lambda→IAM Role, etc.)                      │
│  • Sets: service_type, source="aws", source_id=ARN, raw_source_data             │
│  • Marks stale assets is_active=False                                           │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       STEP 2: PROWLER EXECUTION                                 │
│                ComplianceEngineService.run_scan() (services.py:114-255)         │
├─────────────────────────────────────────────────────────────────────────────────┤
│  • Gets check IDs where mapped_requirements IS NOT NULL (line 281)              │
│  • ProwlerEngine runs subprocess with `prowler aws --checks ...`                │
│  • Parses OCSF JSON output                                                      │
│  • Returns list of CheckEvaluation objects                                      │
│                                                                                 │
│  IMPORTANT: Only checks WITH mapped_requirements are executed                   │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      STEP 3: CREATE CHECK RESULTS                               │
│              _process_evaluations() (services.py:289-509)                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│  For each Prowler finding:                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  CheckResult.objects.get_or_create(                                       │  │
│  │      security_check = SecurityCheck (from check_id)                       │  │
│  │      asset = Asset (matched by ARN)                                       │  │
│  │      integration = Integration                                            │  │
│  │      status = "pass" | "fail" | "error" | "not_applicable"                │  │
│  │      status_extended = "Detailed message from Prowler"                    │  │
│  │      raw_output = {full OCSF JSON}                                        │  │
│  │      resource_snapshot = {AWS resource config} (Phase 7.1)                │  │
│  │  )                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│  • If status changed from previous scan: Creates CheckResultHistory record      │
│  • Unique constraint: (security_check, asset, scanned_at)                       │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     STEP 4: AUTO-CREATE CONTROLS                                │
│           AutoControlService.process_check_results() (auto_control_service.py)  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  STAGE A: SCF-Based (Hub-and-Spoke) - PREFERRED                                 │
│  ─────────────────────────────────────────────────                              │
│  1. Aggregate CheckResults by SCFControl (lines 418-537)                        │
│  2. Collect requirements from DUAL sources:                                     │
│     • PRIMARY: SecurityCheck.mapped_requirements (Prowler native)               │
│     • FALLBACK: SCFFrameworkMapping (SCF→Requirements)                          │
│  3. Create AppliedControl:                                                      │
│     ┌─────────────────────────────────────────────────────────────────────┐     │
│     │  AppliedControl.objects.get_or_create(                              │     │
│     │      folder = folder                                                │     │
│     │      scf_control = SCFControl  ◄── DEDUP KEY                        │     │
│     │      origin = "scan"                                                │     │
│     │      defaults = {                                                   │     │
│     │          name: "SCF-TEC-10.1: Data Protection at Rest"              │     │
│     │          ref_id: "SCF-TEC-10.1"                                     │     │
│     │          description: from SCFControl.description                   │     │
│     │          is_automated: True                                         │     │
│     │          status: "active"                                           │     │
│     │      }                                                              │     │
│     │  )                                                                  │     │
│     └─────────────────────────────────────────────────────────────────────┘     │
│                                                                                 │
│  STAGE B: Requirement-Based - FALLBACK (for checks without SCF)                 │
│  ──────────────────────────────────────────────────────────────                 │
│  1. Aggregate remaining CheckResults by RequirementNode (lines 539-632)         │
│  2. Create AppliedControl with source_requirement as dedup key                  │
│  3. Name format: "SEC-LOG-001: Audit Logging Configuration"                     │
│                                                                                 │
│  FOR BOTH STAGES:                                                               │
│  ────────────────                                                               │
│  4. Create ControlRequirementMapping for EACH linked requirement                │
│  5. Update security posture (PASSING | PARTIAL | ISSUES | NOT_SCANNED)          │
│  6. Link: control.assets.add(*assets), control.security_checks.add(*checks)     │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      STEP 5: AUTO-CREATE POLICIES                               │
│      AutoPolicyService.create_policies_for_scf_controls() (auto_policy_service) │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ONLY triggered for SCF-based controls (not requirement-based fallback)         │
│                                                                                 │
│  1. Collect unique SCFControls from newly created controls                      │
│  2. Find policy templates mapped to those SCF controls:                         │
│     ┌─────────────────────────────────────────────────────────────────────┐     │
│     │  ReferenceControl.objects.filter(                                   │     │
│     │      category = "policy"                                            │     │
│     │      scf_mappings__scf_control__in = scf_controls                   │     │
│     │  )                                                                  │     │
│     └─────────────────────────────────────────────────────────────────────┘     │
│     (Uses ReferenceControlSCFMapping - seeded via seed_policy_scf_mappings)     │
│                                                                                 │
│  3. For each template + SCF match, create Policy:                               │
│     ┌─────────────────────────────────────────────────────────────────────┐     │
│     │  Policy.objects.create(    # Policy is proxy for AppliedControl     │     │
│     │      folder = folder                                                │     │
│     │      name = "POL.ACCESS [IAC-01]"                                   │     │
│     │      ref_id = "POL.ACCESS-IAC-01"                                   │     │
│     │      reference_control = template  ◄── Links to policy template     │     │
│     │      scf_control = scf_control     ◄── Links to SCF hub             │     │
│     │      origin = "scan"                                                │     │
│     │      status = "to_do"                                               │     │
│     │  )                                                                  │     │
│     └─────────────────────────────────────────────────────────────────────┘     │
│                                                                                 │
│  4. Create ControlRequirementMapping for policy via SCFFrameworkMapping         │
└─────────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      STEP 6: AUTO-CREATE EVIDENCE                               │
│         AutoEvidenceService.process_check_results() (auto_evidence_service.py)  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  For EACH CheckResult (1:1 relationship):                                       │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  Evidence.objects.get_or_create(                                          │  │
│  │      source_check_result = check_result  ◄── OneToOne FK (dedup)          │  │
│  │      defaults = {                                                         │  │
│  │          name: "{asset_name}: {check_title}"                              │  │
│  │          origin: "scan"                                                   │  │
│  │          status: "in_review"  ◄── Awaits auditor approval                 │  │
│  │          is_continuous: True  ◄── Auto-updates on rescan                  │  │
│  │          source_integration: integration                                  │  │
│  │          # Orphan protection (if asset deleted later):                    │  │
│  │          asset_name: asset.name                                           │  │
│  │          asset_type: asset.service_type                                   │  │
│  │          asset_source_id: asset.source_id                                 │  │
│  │      }                                                                    │  │
│  │  )                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  • Creates EvidenceRevision with raw_output JSON                                │
│  • Links Evidence to AppliedControls via M2M (that share SecurityCheck)         │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Model Relationships

### Complete Relationship Diagram

```
                                SCANNING LAYER
                    ┌─────────────────────────────────────┐
                    │           SecurityCheck              │
                    │  (578 Prowler checks)               │
                    │  • mapped_requirements (M2M)        │
                    │  • mapped_controls (M2M)            │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
     ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
     │  CheckResult   │   │  SCFControl    │   │ ReferenceControl│
     │  (per asset)   │   │  (1340 hub)    │   │ (policy templates)
     │  • status      │   │  • scf_id      │   │  • category     │
     │  • raw_output  │   │  • security_   │   │  • scf_mappings │
     │  • snapshot    │   │    checks (M2M)│   │    (through)    │
     └───────┬────────┘   └───────┬────────┘   └────────┬───────┘
             │                    │                     │
             │            SCFFrameworkMapping    ReferenceControlSCFMapping
             │                    │                     │
             │                    ▼                     │
             │         ┌────────────────┐              │
             │         │ RequirementNode│◄─────────────┘
             │         │ (CC6.1, A.5.1) │
             │         │  • assessable  │
             │         │  • weight      │
             │         └───────┬────────┘
             │                 │
             │    ControlRequirementMapping
             │                 │
             ▼                 ▼
     ┌────────────────────────────────────────────────────┐
     │               AppliedControl                       │
     │  origin="scan" | "manual"                          │
     │  • scf_control (FK)      ◄── Phase 6.6 hub        │
     │  • security_checks (M2M) ◄── Validates            │
     │  • assets (M2M)          ◄── Protects             │
     │  • evidences (M2M)       ◄── Proves               │
     │  • security_posture      ◄── Calculated           │
     └──────────────────┬─────────────────────────────────┘
                        │
            ┌───────────┴───────────┐
            │                       │
            ▼                       ▼
     ┌────────────┐         ┌────────────┐
     │   Policy   │         │  Evidence  │
     │  (proxy)   │         │  (1:1 CR)  │
     │ category=  │         │ • status   │
     │  "policy"  │         │ • origin   │
     │ reference_ │         │ • is_      │
     │  control   │         │   continuous
     └────────────┘         └────────────┘
```

### Key Relationship Table

| Entity | Links To | Relationship Type | Created By |
|--------|----------|-------------------|------------|
| **CheckResult** | SecurityCheck | FK | Prowler scan |
| **CheckResult** | Asset | FK | Prowler scan |
| **CheckResult** | Integration | FK | Prowler scan |
| **AppliedControl** | SCFControl | FK (null=True) | AutoControlService |
| **AppliedControl** | RequirementNode | Through ControlRequirementMapping | AutoControlService |
| **AppliedControl** | SecurityCheck | M2M | AutoControlService |
| **AppliedControl** | Asset | M2M | AutoControlService |
| **AppliedControl** | Evidence | M2M | AutoEvidenceService |
| **Policy** | ReferenceControl | FK | AutoPolicyService |
| **Policy** | SCFControl | FK | AutoPolicyService |
| **Policy** | RequirementNode | Through ControlRequirementMapping | AutoPolicyService |
| **Evidence** | CheckResult | OneToOne FK | AutoEvidenceService |
| **SCFControl** | SecurityCheck | M2M (owns the field) | Import |
| **SCFControl** | RequirementNode | Through SCFFrameworkMapping | STRM Import |
| **ReferenceControl** | SCFControl | Through ReferenceControlSCFMapping | seed_policy_scf_mappings |

---

## Important Implementation Details

### 1. SCFControl ↔ SecurityCheck Relationship

**IMPORTANT:** SecurityCheck does NOT have a `mapped_scf_control` field. The relationship is defined on SCFControl:

```python
# backend/core/models.py:1964-1970
class SCFControl(AbstractBaseModel):
    security_checks = models.ManyToManyField(
        "SecurityCheck",
        blank=True,
        related_name="scf_controls",  # Reverse accessor
    )
```

To get SCF controls for a SecurityCheck:
```python
security_check.scf_controls.all()  # Uses reverse relation
```

### 2. Dual Requirement Sources

AutoControlService collects requirements from TWO sources:

| Source | Priority | Data Path |
|--------|----------|-----------|
| Prowler Native | PRIMARY | `SecurityCheck.mapped_requirements` |
| SCF Framework | FALLBACK | `SCFControl.framework_mappings → SCFFrameworkMapping.requirement` |

### 3. Two Mapping Systems Coexist

| System | Table | Created By | Purpose |
|--------|-------|------------|---------|
| User Manual | `RequirementAssessment.applied_controls` (M2M) | User UI | Manual control assignment |
| Auto Scan | `ControlRequirementMapping` | AutoControlService | Automatic from scans |

Both are merged in serializers for display (see `serializers.py:1727-1745`).

### 4. Compliance Scoring

**Controls do NOT affect compliance scoring.** Scoring comes entirely from:
- `RequirementAssessment.answers` (user responses to questions)
- Weighted by `RequirementNode.weight`

Controls are tracked for visibility but not used in score calculation.

### 5. Security Posture Calculation

```python
# auto_control_service.py:634-670
def _calculate_posture(passed, failed, error):
    total = passed + failed + error

    if total == 0:
        return "not_scanned"
    if failed == 0 and error == 0:
        return "passing"
    if passed == 0:
        return "issues"
    return "partial"
```

| Passed | Failed | Error | Posture |
|--------|--------|-------|---------|
| 10 | 0 | 0 | PASSING |
| 0 | 10 | 0 | ISSUES |
| 5 | 5 | 0 | PARTIAL |
| 0 | 0 | 0 | NOT_SCANNED |

### 6. Policy is a Proxy Model

Policy is NOT a separate table. It's a Django proxy model:

```python
# backend/core/models.py:4754-4764
class Policy(AppliedControl):
    class Meta:
        proxy = True

    objects = PolicyManager()  # Filters by category="policy"
```

All policies are `AppliedControl` rows with `category="policy"`.

---

## Source Code References

| Component | File | Key Lines |
|-----------|------|-----------|
| Scan Endpoint | `backend/integrations/views.py` | 140-248 |
| Asset Sync | `backend/integrations/services/sync.py` | 135-300 |
| Compliance Engine | `backend/compliance_engines/services.py` | 76-255 |
| Prowler Engine | `backend/compliance_engines/prowler/engine.py` | 194-372 |
| CheckResult Creation | `backend/compliance_engines/services.py` | 322-509 |
| Auto Control Service | `backend/core/security_check_utils/auto_control_service.py` | 46-670 |
| Auto Policy Service | `backend/core/security_check_utils/auto_policy_service.py` | 14-179 |
| Auto Evidence Service | `backend/core/security_check_utils/auto_evidence_service.py` | 35-272 |
| SecurityCheck Model | `backend/core/models.py` | 7415-7562 |
| CheckResult Model | `backend/core/models.py` | 7565-7662 |
| AppliedControl Model | `backend/core/models.py` | 4165-4620 |
| Policy Model | `backend/core/models.py` | 4754-4764 |
| Evidence Model | `backend/core/models.py` | 3797-3938 |
| Asset Model | `backend/core/models.py` | 2185-2534 |
| SCFControl Model | `backend/core/models.py` | 1921-1979 |
| SCFFrameworkMapping | `backend/core/models.py` | 1981-2040 |
| ControlRequirementMapping | `backend/core/models.py` | 7849-7894 |
| ReferenceControlSCFMapping | `backend/core/models.py` | 1469-1509 |

---

## API Response Structure

When a scan completes, the response includes:

```json
{
  "success": true,
  "message": "Scan complete: X issues found",

  "assets_created": 0,
  "assets_updated": 15,
  "assets_deactivated": 0,
  "total_assets": 47,
  "relationships_created": 12,

  "results_created": 234,
  "arns_skipped": 5,
  "checks_executed": 89,
  "checks_passed": 180,
  "checks_failed": 54,
  "checks_error": 0,
  "checks_not_applicable": 0,

  "controls_created": 12,
  "controls_updated": 45,

  "policies_created": 8,
  "policies_skipped": 15,

  "evidence_created": 234,
  "evidence_updated": 0,

  "snapshots_captured": 200,
  "snapshots_failed": 34,
  "history_entries_created": 15,

  "duration_seconds": 45.2
}
```

---

## Related Documentation

- [Unified Control Architecture](../../features/UNIFIED_CONTROL_ARCHITECTURE.md) - Hub-and-spoke design
- [Policy-SCF Linking](../../features/policy-scf-linking/README.md) - Policy auto-creation
- [Data Model](../sql-tables/CITADELSECURE_DATA_MODEL.md) - Complete schema reference
