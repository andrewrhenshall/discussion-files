# Integration Roadmap

## Current Status: Phase 1 Complete, Phase 0.5 Complete

---

## Phase 0.5: URN Foundation ✅ COMPLETE
- [x] URNMixin added to AbstractBaseModel
- [x] All records backfilled with `urn:citadel:{type}:{uuid}` format
- [x] Source tracking fields added to Asset model
- [x] `vendors` app created (schema only)
- [x] `endpoints` app created (schema only)

## Phase 1: Integration Foundation ✅ COMPLETE
- [x] LocalStack container (`citadel-acme-aws-sim`) for local dev
- [x] Django `integrations` app with Integration model
- [x] AWS connection flow (CloudFormation + IAM role)
- [x] Frontend integrations page
- [x] Architecture documentation

## Phase 2: Asset Discovery 🔄 NEXT
- [ ] AWS asset sync → Asset model (EC2, S3, RDS, Lambda)
- [ ] CloudTrail log ingestion from S3
- [ ] Asset deduplication by `source_id`
- [ ] "Last seen" tracking for stale assets

## Phase 3: Prowler Integration
- [ ] Prowler execution wrapper
- [ ] ControlTest and ControlTestResult models
- [ ] On-demand ECS task for production
- [ ] Daily + on-demand scan scheduling

## Phase 4: Evidence Automation
- [ ] Auto-create Evidence from test results
- [ ] ControlTestMapping for framework linking
- [ ] Evidence dashboard (automated vs manual)

## Phase 5: Framework Mapping
- [ ] Map Prowler checks to frameworks (SOC2, ISO27001, etc.)
- [ ] Auto-update RequirementAssessment results
- [ ] Compliance trend tracking

---

## Provider Roadmap

| Provider | Status | Priority |
|----------|--------|----------|
| AWS | Phase 2 | High |
| GitHub | Planned | Medium |
| Okta | Planned | Medium |
| Google Workspace | Planned | Low |
| Azure | Planned | Low |

---

## Related Docs
- [AWS Integration Details](./aws.md)
- [Integration Architecture](./README.md)
- [Development Log](../integration_dev_log.md)
