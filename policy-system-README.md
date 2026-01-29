# Policy System Architecture

The Policy System manages organizational policies with lifecycle workflows, document generation, versioning, and compliance requirement linkage.

## Overview

Policies are implemented as a **proxy model** of `AppliedControl` with `category="policy"`. This allows policies to share the core control infrastructure while having specialized lifecycle and document features.

```
AppliedControl (base)
      │
      └── Policy (proxy, category="policy")
              │
              ├── PolicyVersion (snapshots)
              ├── PolicyRequirementMapping (requirement links)
              └── PolicyAcknowledgment (employee sign-off)
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **DOCX content is manual-only** | Document content is never auto-modified by scans. Users manually edit `document_content` field. |
| **Applied Controls auto-linked** | Relationships between policies and controls CAN be auto-updated by scans via requirement mappings. |
| **Versioning on approval** | When a policy is approved, a `PolicyVersion` snapshot is created with content and variables. |
| **Framework-triggered creation** | Policies are created when frameworks are selected (via QuickStart), not from scans. |
| **Lazy PDF caching** | PDFs generated on first view and cached. Regenerated only when document fields change. Optimal for low-traffic GRC pattern. |

---

## Data Models

### Policy (Proxy Model)

**Location**: `backend/core/models.py`

```python
class Policy(AppliedControl):
    """Proxy model for AppliedControl where category='policy'."""
    class Meta:
        proxy = True
```

**Lifecycle Fields** (on AppliedControl):

| Field | Type | Description |
|-------|------|-------------|
| `policy_status` | CharField | draft, pending_review, approved, active, archived |
| `approver` | ForeignKey(User) | Designated approver |
| `approved_at` | DateTimeField | Approval timestamp |
| `next_review_date` | DateField | Scheduled review date |
| `current_version` | CharField | Version number (e.g., "1.0", "2.1") |
| `document_content` | JSONField | Rendered sections `[{title, content, order}]` |
| `variable_values` | JSONField | Template variables `{company_name, ...}` |
| `cached_pdf` | FileField | Cached PDF file for preview (lazy generation) |
| `pdf_cache_valid` | BooleanField | Whether the cached PDF is up to date |

### PolicyVersion

**Location**: `backend/core/models.py`

Stores immutable snapshots when policies are approved.

| Field | Type | Description |
|-------|------|-------------|
| `policy` | ForeignKey(Policy) | Parent policy |
| `version_number` | CharField | e.g., "1.0", "1.1" |
| `content_snapshot` | JSONField | Copy of `document_content` |
| `variables_snapshot` | JSONField | Copy of `variable_values` |
| `change_summary` | TextField | Description of changes |
| `created_by` | ForeignKey(User) | Who created this version |
| `approved_by` | ForeignKey(User) | Who approved |
| `approved_at` | DateTimeField | Approval timestamp |

### PolicyTemplate

**Location**: `backend/core/models.py`

Links to ReferenceControl to provide default document structure.

| Field | Type | Description |
|-------|------|-------------|
| `reference_control` | OneToOneField | Source template |
| `sections` | JSONField | Default sections structure |
| `variables` | JSONField | Variable definitions |
| `version` | CharField | Template version |
| `review_frequency_months` | PositiveIntegerField | Default review cycle |

### PolicyRequirementMapping

**Location**: `backend/core/models.py`

Direct mapping between policies and compliance requirements (bypasses SCF hub).

| Field | Type | Description |
|-------|------|-------------|
| `policy` | ForeignKey(Policy) | The policy |
| `requirement` | ForeignKey(RequirementNode) | The requirement |
| `source` | CharField | "framework" or "manual" |

### PolicyAcknowledgment

**Location**: `backend/core/models.py`

Tracks employee acknowledgment of policies.

| Field | Type | Description |
|-------|------|-------------|
| `policy` | ForeignKey(Policy) | The policy |
| `user` | ForeignKey(User) | Who acknowledged |
| `acknowledged_at` | DateTimeField | When |
| `policy_version` | CharField | Which version |
| `ip_address` | GenericIPAddressField | Audit trail |
| `user_agent` | TextField | Browser info |

---

## Services

### PolicyGenerationService

**Location**: `backend/core/services/policy_generation_service.py`

Creates policies when frameworks are selected.

**Methods**:

| Method | Description |
|--------|-------------|
| `seed_base_policies()` | Create base policies from ReferenceControl library |
| `generate_policies_for_framework(framework)` | Link policies to framework requirements |
| `generate_policies_for_all_frameworks()` | Process all frameworks |

**Flow**:
```
QuickStart → create ComplianceAssessment
           → PolicyGenerationService.generate_policies_for_framework()
           → Creates PolicyRequirementMapping records
```

### PolicyDocumentService

**Location**: `backend/core/services/policy_document_service.py`

Generates DOCX and PDF documents from policy data.

**Methods**:

| Method | Returns | Description |
|--------|---------|-------------|
| `get_document_info()` | `DocumentInfo` | Metadata + sections for preview |
| `generate_docx()` | `bytes` | DOCX file content |

**Document Structure**:
1. Header (title, version)
2. Metadata table (status, dates, owner, approver)
3. Content sections (from `document_content`)
4. Related requirements table
5. Approval signatures section
6. Footer (confidentiality notice)

### PolicyLifecycleService

**Location**: `backend/core/services/policy_lifecycle_service.py`

Manages policy state transitions and versioning.

**Methods**:

| Method | Transition | Side Effects |
|--------|------------|--------------|
| `submit_for_review(approver)` | draft → pending_review | Assigns approver |
| `approve(change_summary)` | pending_review → approved | Creates version, increments version number |
| `activate(effective_date)` | approved → active | Sets start_date, next_review_date |
| `archive(reason)` | active → archived | Sets expiry_date |
| `request_revision(feedback)` | * → draft | Returns to draft for edits |

---

## Lifecycle Workflow

```
┌─────────┐    submit    ┌────────────────┐   approve   ┌──────────┐
│  DRAFT  │ ──────────▶  │ PENDING_REVIEW │ ─────────▶  │ APPROVED │
└─────────┘              └────────────────┘             └──────────┘
     ▲                          │                            │
     │                          │ revision                   │ activate
     │                          ▼                            ▼
     │                    ┌─────────┐                  ┌──────────┐
     └────────────────────│  DRAFT  │◀─────────────── │  ACTIVE  │
                          └─────────┘    revision      └──────────┘
                                                            │
                                                            │ archive
                                                            ▼
                                                       ┌──────────┐
                                                       │ ARCHIVED │
                                                       └──────────┘
```

**Version Creation**: A `PolicyVersion` snapshot is created only when `approve()` is called.

---

## API Endpoints

**Base**: `/api/policies/`

### CRUD Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/policies/` | List policies |
| POST | `/policies/` | Create policy |
| GET | `/policies/{id}/` | Get policy detail |
| PUT | `/policies/{id}/` | Update policy |
| DELETE | `/policies/{id}/` | Delete policy |

### Lifecycle Actions

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/policies/{id}/submit-for-review/` | Submit for review |
| POST | `/policies/{id}/approve/` | Approve policy |
| POST | `/policies/{id}/activate/` | Activate policy |
| POST | `/policies/{id}/archive/` | Archive policy |
| POST | `/policies/{id}/request-revision/` | Return to draft |

### Document Actions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/policies/{id}/download-docx/` | Download DOCX |
| GET | `/policies/{id}/download-pdf/` | Download PDF |
| GET | `/policies/{id}/preview_pdf/` | Preview PDF with caching (for iframe display) |
| GET | `/policies/{id}/document-info/` | Get document metadata |
| GET | `/policies/{id}/versions/` | Get version history |

---

## Frontend Components

### PolicyDocumentModal

**Location**: `frontend/src/lib/components/PolicyDocumentModal.svelte`

Modal that displays policy document preview (PDF in iframe).

**Props**:
- `policyId: string` - Policy UUID
- `open: boolean` - Modal visibility
- `onClose: () => void` - Close callback

### Detail Page Integration

Policies are displayed via the AppliedControl detail view with additional policy-specific components:
- Document preview button (eye icon)
- Download buttons (DOCX, PDF)
- Lifecycle action buttons

---

## Document Generation

### DOCX Generation

Uses `python-docx` library to programmatically build documents:

```python
from core.services.policy_document_service import PolicyDocumentService

service = PolicyDocumentService(policy)
docx_bytes = service.generate_docx()
```

### PDF Generation

PDFs are generated by **converting DOCX to PDF via LibreOffice** (`soffice --headless --convert-to pdf`). This ensures PDF output matches DOCX formatting exactly. Requires LibreOffice installed (see `Dockerfile.api`).

---

## PDF Caching for Preview

The system uses **lazy generation with file-based caching** to optimize PDF preview performance.

### How It Works

```
User clicks Preview
        │
        ▼
┌───────────────────┐
│ pdf_cache_valid?  │──── Yes ──▶ Serve cached_pdf (fast, ~50ms)
└───────────────────┘
        │ No
        ▼
┌───────────────────┐
│ Generate DOCX     │ (python-docx)
│ Convert to PDF    │ (LibreOffice, 2-5 seconds)
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Save to cached_pdf│
│ Set valid = True  │
└───────────────────┘
        │
        ▼
    Serve PDF
```

### Cache Invalidation

The cache is automatically invalidated in the `AppliedControl.save()` method when any of these fields change:

| Field | Reason |
|-------|--------|
| `document_content` | Main document content changed |
| `variable_values` | Template variables changed |
| `name` | Policy title changed |
| `policy_status` | Status shown in document header |

```python
# In AppliedControl.save()
if self.pk and self.category == "policy":
    old = AppliedControl.objects.get(pk=self.pk)
    if (old.document_content != self.document_content
        or old.variable_values != self.variable_values
        or old.name != self.name
        or old.policy_status != self.policy_status):
        self.pdf_cache_valid = False
```

### Resource Efficiency

| Aspect | Performance |
|--------|-------------|
| **First view** | 2-5 seconds (DOCX generation + LibreOffice conversion) |
| **Subsequent views** | ~50ms (cached file read) |
| **Storage per PDF** | ~100-500KB |
| **Memory during conversion** | ~100-200MB (LibreOffice process, brief) |

### Why Lazy Generation?

| Approach | Pros | Cons |
|----------|------|------|
| **Real-time** | Always fresh | High CPU per request |
| **Eager (on save)** | Zero view latency | Generates PDFs never viewed |
| **Lazy (current)** | Only generates when needed | First view has latency |

Lazy generation is optimal for GRC platforms where:
- Policies aren't viewed constantly
- Updates are infrequent after approval
- Users expect document generation to take a moment

### Frontend Integration

The preview modal uses an iframe that loads from a SvelteKit server route:

```
PolicyDocumentModal.svelte
        │
        ▼ (iframe src)
/policies/{id}/view-pdf  (SvelteKit route)
        │
        ▼ (fetch)
/api/policies/{id}/preview_pdf/  (Django endpoint)
        │
        ▼
Returns cached or freshly generated PDF
```

**Files involved**:
- `frontend/src/lib/components/PolicyDocumentModal.svelte` - Modal with iframe
- `frontend/src/routes/(app)/(internal)/policies/[id=uuid]/view-pdf/+server.ts` - Proxy route
- `backend/core/views.py` - `preview_pdf` action with caching logic

---

## Policy Creation Flow

### Via QuickStart

```
1. User creates company via QuickStart
2. Selects compliance framework(s)
3. QuickStartSerializer calls PolicyGenerationService
4. Base policies created (if not exist)
5. PolicyRequirementMapping records link policies to requirements
```

### Manual Creation

```
1. User navigates to Policies section
2. Creates new policy (AppliedControl with category="policy")
3. Edits document_content via form
4. Proceeds through lifecycle workflow
```

---

## Integration Points

### Scans

Scans do **NOT** modify policy document content. They only:
- Update Applied Controls linked to policies
- These relationships shown in policy detail "Applied Controls" table

### Compliance Assessment

Policies linked to requirements via `PolicyRequirementMapping`:
- Shows which requirements a policy addresses
- Requirements table included in generated documents

---

## Database Schema

```sql
-- Policy lifecycle fields (on core_appliedcontrol)
ALTER TABLE core_appliedcontrol ADD COLUMN policy_status VARCHAR(30);
ALTER TABLE core_appliedcontrol ADD COLUMN approver_id UUID;
ALTER TABLE core_appliedcontrol ADD COLUMN approved_at TIMESTAMP;
ALTER TABLE core_appliedcontrol ADD COLUMN next_review_date DATE;
ALTER TABLE core_appliedcontrol ADD COLUMN current_version VARCHAR(20);
ALTER TABLE core_appliedcontrol ADD COLUMN document_content JSONB;
ALTER TABLE core_appliedcontrol ADD COLUMN variable_values JSONB;

-- PDF caching fields (on core_appliedcontrol)
ALTER TABLE core_appliedcontrol ADD COLUMN cached_pdf VARCHAR(100);  -- FileField path
ALTER TABLE core_appliedcontrol ADD COLUMN pdf_cache_valid BOOLEAN DEFAULT FALSE;

-- PolicyVersion
CREATE TABLE core_policyversion (
    id UUID PRIMARY KEY,
    policy_id UUID REFERENCES core_appliedcontrol(id),
    version_number VARCHAR(20),
    content_snapshot JSONB,
    variables_snapshot JSONB,
    change_summary TEXT,
    created_by_id UUID,
    approved_by_id UUID,
    approved_at TIMESTAMP,
    created_at TIMESTAMP,
    UNIQUE(policy_id, version_number)
);

-- PolicyRequirementMapping
CREATE TABLE core_policyrequirementmapping (
    id UUID PRIMARY KEY,
    policy_id UUID REFERENCES core_appliedcontrol(id),
    requirement_id UUID REFERENCES core_requirementnode(id),
    source VARCHAR(20),
    UNIQUE(policy_id, requirement_id)
);

-- PolicyAcknowledgment
CREATE TABLE core_policyacknowledgment (
    id UUID PRIMARY KEY,
    policy_id UUID REFERENCES core_appliedcontrol(id),
    user_id UUID REFERENCES iam_user(id),
    policy_version VARCHAR(20),
    acknowledged_at TIMESTAMP,
    ip_address INET,
    user_agent TEXT,
    UNIQUE(policy_id, user_id, policy_version)
);
```

---

## Migration History

| Migration | Description |
|-----------|-------------|
| `0129_policy_system_redesign` | Adds all policy models and lifecycle fields |
| `0130_appliedcontrol_pdf_cache` | Adds `cached_pdf` and `pdf_cache_valid` fields for preview caching |

---

## Future Enhancements

- [ ] Acknowledgment workflow (employee sign-off)
- [ ] Dedicated policy frontend routes (`/policies/`, `/policies/[id]/`)
- [ ] Policy templates marketplace
- [ ] Automated review reminders
- [x] ~~PDF caching for preview performance~~ (Implemented)
