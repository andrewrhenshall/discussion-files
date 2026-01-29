# Integration Architecture Plan

**Goal**: Add Vanta/Drata-style automated compliance to CitadelSecure

**Branch**: `feature/integration-foundation`

---

## Executive Summary

| Decision | Choice |
|----------|--------|
| First Integration | AWS (via Prowler - 300+ security checks) |
| Evidence Strategy | New record per test run (full audit trail) |
| Framework Mapping | Pre-mapped to all 10 frameworks |
| Log Collection | Pull from S3 (CloudTrail logs) |
| Log Storage | PostgreSQL (upgrade to TimescaleDB if needed) |
| Security | Explicit deny policy for dangerous AWS actions |
| **NEW: URN System** | Universal identifiers for all resources |
| **NEW: Unified Assets** | ALL asset sources → ONE Asset model |
| Future | AI search, code suggestions, endpoint agent |

---

## Architectural Foundations (Phase 0.5)

### Problem: Parallel Systems

**Bad** (original plan):
```
┌─────────────┐  ┌──────────────────┐  ┌────────────────────┐
│   Asset     │  │ IntegrationAsset │  │ VendorAsset (?)    │
│ (manual)    │  │ (cloud)          │  │ (endpoint agent)   │
└─────────────┘  └──────────────────┘  └────────────────────┘
```

**Good** (updated plan):
```
┌─────────────────────────────────────────────────────────────┐
│                    UNIFIED ASSET MODEL                       │
│  urn: "urn:citadel:asset:acme:550e8400-e29b-..."            │
│  source: aws | azure | endpoint | vendor | manual           │
│  source_id: "arn:aws:ec2:..." | "device:LAPTOP-123" | null  │
└─────────────────────────────────────────────────────────────┘
```

### Universal URN Scheme

Every CitadelSecure resource gets a URN:

```
urn:citadel:{type}:{tenant}:{uuid}

Examples:
- urn:citadel:asset:acme:550e8400-e29b-41d4-a716-446655440000
- urn:citadel:control:acme:7c9e6679-7425-40de-944b-e07fc1f90ae7
- urn:citadel:vendor:acme:a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11
```

**Why now**: Adding URNs after 10,000 assets exist = painful migration.

---

## Data Flow (Updated)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                                  │
├──────────────┬──────────────┬──────────────┬───────────────────────┤
│ AWS/Azure    │ GitHub/Okta  │ Endpoint     │ Manual Entry          │
│ Integration  │ Integration  │ Agent        │                       │
└──────┬───────┴──────┬───────┴──────┬───────┴───────────┬───────────┘
       │              │              │                   │
       ▼              ▼              ▼                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      UNIFIED ASSET MODEL                             │
│  urn: "urn:citadel:asset:acme:..."                                  │
│  source: aws | azure | github | okta | endpoint | manual            │
│  source_id: external identifier                                     │
│  source_integration: FK → Integration                               │
│  source_endpoint: FK → Endpoint                                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      VENDOR DISCOVERY                                │
│  From endpoint agent: "User accessed notion.so, slack.com"          │
│  Auto-creates Vendor records with risk tracking                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      CONTROL TESTS                                   │
│  Prowler checks, custom tests                                       │
│  Maps to Asset via URN                                              │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      AI SEARCH INDEX                                 │
│  All resources indexed by URN                                       │
│  Context-aware search based on current page                         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Database Models (Updated)

### Core Models (Modified)

| Model | Change |
|-------|--------|
| `AbstractBaseModel` | Add `urn` field (URNMixin) |
| `Asset` | Add source tracking fields |

### New Models

| Model | Purpose |
|-------|---------|
| `Integration` | Connection to AWS, GitHub, etc. (stores credentials) |
| `ControlTest` | Automated test definitions (Prowler checks) |
| `ControlTestResult` | Pass/fail results per test run |
| `ControlTestMapping` | Maps tests to AppliedControls |
| `CloudTrailEvent` | Parsed CloudTrail logs for analysis |
| `Vendor` | Third-party SaaS providers discovered/approved |
| `VendorAccess` | Tracks which users access which vendors |
| `Endpoint` | Device with agent installed (future) |
| `EndpointEvent` | Events from endpoint agent (future) |

### Removed Models

| Model | Reason |
|-------|--------|
| ~~`IntegrationAsset`~~ | Merged into Asset with source tracking |

---

## Implementation Phases (Updated)

### Phase 0.5: Foundation (NEW - CURRENT)
- [x] Create FOUNDATION_URN_SYSTEM.md design doc
- [ ] Add URNMixin to AbstractBaseModel
- [ ] Backfill URNs for all existing records
- [ ] Add source tracking fields to Asset model
- [ ] Create `vendors` app (schema only)
- [ ] Create `endpoints` app (schema only)
- [ ] Add AI context fields (searchable_text, placeholder for vectors)

### Phase 1: Integration Foundation ✅ COMPLETE
- [x] LocalStack (`citadel-acme-aws-sim`) for local dev
- [x] Django `integrations` app with Integration model
- [x] AWS connection flow (CloudFormation + IAM role)
- [x] Frontend integrations page
- [x] Architecture documentation

### Phase 2: Asset Discovery + CloudTrail
- [ ] AWS asset sync → Asset model (with source tracking)
- [ ] CloudTrail log ingestion from S3
- [ ] Compliance tagging for events

### Phase 3: Prowler Integration
- [ ] Prowler execution wrapper
- [ ] ControlTest and ControlTestResult models
- [ ] On-demand ECS task for production
- [ ] Daily + on-demand scan scheduling

### Phase 4: Evidence Automation
- [ ] Auto-create Evidence from test results
- [ ] ControlTestMapping for framework linking
- [ ] Evidence dashboard (automated vs manual)

### Phase 5: Framework Mapping & Dashboard
- [ ] Map Prowler checks to 10 frameworks
- [ ] Compliance dashboard with trends
- [ ] Auto-update RequirementAssessment results

### Phase 6: Vendor Management (Future)
- [ ] Vendor model with risk tracking
- [ ] Manual vendor entry UI
- [ ] Vendor risk assessment workflow

### Phase 7: Endpoint Agent (Future)
- [ ] Endpoint model and registration
- [ ] Agent API endpoints
- [ ] Web activity → Vendor discovery
- [ ] Software inventory → Asset discovery

### Phase 8: AI Integration (Future)
- [ ] URN-based resource indexing
- [ ] Context-aware search bar
- [ ] Code suggestions for failing controls
- [ ] Natural language compliance queries

---

## Future-Proofing

### AI Search Architecture

```python
# POST /api/ai/search
{
    "query": "Show me all S3 buckets without encryption",
    "context_urn": "urn:citadel:assessment:acme:...",  # Current page
    "scope": ["assets", "controls", "evidence"]
}
```

### Endpoint Agent Data Flow

```
┌────────────────┐      ┌─────────────────┐      ┌──────────────────┐
│ Endpoint Agent │ ───► │ API: /events    │ ───► │ EndpointEvent    │
│ (on laptop)    │      │ (batch upload)  │      │ (parsed/tagged)  │
└────────────────┘      └─────────────────┘      └──────────────────┘
                                                          │
                                                          ▼
                               ┌───────────────────────────────────────┐
                               │ Vendor Discovery Pipeline             │
                               │ - Extract domain from web_visit       │
                               │ - Match to known vendors OR           │
                               │ - Create new Vendor (status=DISCOVERED)│
                               └───────────────────────────────────────┘
```

---

## Local Development

**Simulated Customer AWS**: `citadel-acme-aws-sim` (LocalStack on port 4566)

```bash
# Test AWS connection locally
docker exec citadel-acme-aws-sim awslocal s3 ls
docker exec citadel-acme-aws-sim awslocal ec2 describe-instances
```

**Backend env vars**:
```
AWS_ENDPOINT_URL=http://citadel-acme-aws-sim:4566
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
```

---

## Cost Optimization (Prowler)

| Approach | Monthly Cost | Notes |
|----------|--------------|-------|
| In backend container | $0 | Blocks app during scans |
| 24/7 Celery worker | ~$15-30 | Runs even when idle |
| **On-demand ECS task** | **~$1-5** | **Recommended** |

Daily scans for 10 customers = ~$6/month

---

## Security

- **IAM Role Assumption**: Cross-account access with ExternalId
- **SecurityAudit Policy**: Read-only, no write access
- **Explicit Deny**: Dangerous actions blocked (like Vanta)
- **Encryption**: Role ARNs encrypted at rest (django-fernet-fields)

---

## Related Docs

- [FOUNDATION_URN_SYSTEM.md](../architecture/FOUNDATION_URN_SYSTEM.md) - Phase 0.5 URN design
- [INTEGRATION_ARCHITECTURE.md](../architecture/INTEGRATION_ARCHITECTURE.md) - Full technical details
- [integration_dev_log.md](./integration_dev_log.md) - Development progress
