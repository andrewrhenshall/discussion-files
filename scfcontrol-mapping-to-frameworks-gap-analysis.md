# SCF Control Mapping to Frameworks - Gap Analysis

**Date:** 2026-01-12
**Updated:** 2026-01-12 (verified current scan stats)
**Purpose:** Analyze coverage gaps in compliance framework mappings

## Executive Summary

We use a **dual-source mapping architecture** to connect Prowler security checks to compliance framework requirements:

1. **PRIMARY: Prowler Native Mappings** - Direct mappings from Prowler's compliance JSON files
2. **FALLBACK: SCF Hub Mappings** - Indirect mappings via SCF (Secure Controls Framework)

### Current Scan Coverage (282 of 578 checks ran)

Coverage depends on which AWS resources exist. More resources = more checks run = higher coverage.

| Framework | Total Reqs | Covered | Coverage |
|-----------|------------|---------|----------|
| NIST CSF v2.0 | 106 | 106 | **100.0%** |
| NIST CSF v1.1 | 108 | 83 | **76.9%** |
| SOC2 | 301 | 230 | **76.4%** |
| PCI DSS v4.0 | 351 | 183 | **52.1%** |
| ISO 27001:2022 | 123 | 49 | **39.8%** |
| CMMC v2.0 | 110 | 7 | **6.4%** |
| GDPR | 287 | 16 | **5.6%** |

### Theoretical Maximum (if all 578 checks ran)

With a full AWS environment where all Prowler checks execute:

| Framework | Total Reqs | Prowler Native | SCF Path | Est. Max Coverage |
|-----------|------------|----------------|----------|-------------------|
| NIST CSF v2.0 | 106 | 0 | 121 | **~100%** |
| SOC2 | 301 | 20 | 271 | **~88%** |
| NIST CSF v1.1 | 108 | 53 | 85 | **~87%** |
| PCI DSS v4.0 | 351 | 0 | 227 | **~52%** |
| ISO 27001:2022 | 123 | 37 | 57 | **~49%** |
| GDPR | 287 | 0 | 26 | **~8%** |
| CMMC v2.0 | 110 | 0 | 11 | **~6%** |

### Improvement from Dual-Source Fix

| Framework | Before | After | Improvement |
|-----------|--------|-------|-------------|
| ISO 27001:2022 | 36.6% | 49% | **+12%** |
| NIST CSF v1.1 | 66.7% | 77% | **+10%** |

**Note:** Theoretical max assumes all 578 Prowler checks run. Actual coverage varies based on AWS resources present during the scan.

## Critical Gaps by Framework

### ISO 27001:2022 (39.8% current / ~49% max)

**What's mapped:** Clauses 4-10 (ISMS requirements) + many Annex A controls via dual-source.

**Still unmapped:** Some Annex A controls (depends on which checks run):

| Category | Unmapped | Examples |
|----------|----------|----------|
| A.5 (Organizational) | 33 | A.5.1 Policies, A.5.15 Access control, A.5.24-28 Incident mgmt |
| A.8 (Technological) | 30 | A.8.2 Privileged access, A.8.5 Authentication, A.8.24 Cryptography |
| A.7 (Physical) | 9 | A.7.1 Physical perimeters, A.7.4 Physical security monitoring |
| A.6 (People) | 6 | A.6.1 Screening, A.6.3 Security awareness |

**Impact:** Annex A contains the actual security controls organizations implement. Missing these means scans can't demonstrate ISO 27001 compliance for most controls.

### CMMC v2.0 (6.4% current / ~6% max)

| Domain | Coverage | Status |
|--------|----------|--------|
| PE (Physical) | 73.3% | Partial |
| SI (System Integrity) | 72.7% | Partial |
| AC (Access Control) | 58.1% | Partial |
| IA (Identification) | 40.0% | Poor |
| MP (Media Protection) | 38.5% | Poor |
| SC (System Comms) | 22.2% | Poor |
| RA (Risk Assessment) | **0%** | None |
| AT (Awareness Training) | **0%** | None |
| CA (Security Assessment) | **0%** | None |
| AU (Audit) | **0%** | None |
| PS (Personnel Security) | **0%** | None |
| MA (Maintenance) | **0%** | None |
| IR (Incident Response) | **0%** | None |
| CM (Config Management) | **0%** | None |

**Impact:** 8 entire CMMC domains have zero coverage. CMMC compliance cannot be demonstrated via scans.

### GDPR (5.6% current / ~8% max)

GDPR has 287 assessable requirements but only 16 are currently covered. This is expected since:
- GDPR is a legal/regulatory framework, not a technical controls framework
- Most GDPR requirements relate to data subject rights, legal bases, etc.
- Only ~10% of GDPR requirements are technical in nature

**Impact:** Low coverage is acceptable for GDPR - it's not primarily a technical framework.

## Root Cause Analysis

### Prowler Native Mapping Availability

Not all frameworks have usable Prowler native mappings. Investigation (2026-01-12):

| Framework | Prowler File | Status | Notes |
|-----------|--------------|--------|-------|
| ISO 27001:2022 | `iso27001_2022_aws.json` | ✅ Works | Requirement-level mappings |
| ISO 27001:2013 | `iso27001_2013_aws.json` | ✅ Works | Requirement-level mappings |
| NIST CSF v1.1 | `nist_csf_1.1_aws.json` | ✅ Works | Requirement-level mappings |
| SOC2 | `soc2_aws.json` | ✅ Works | Requirement-level mappings |
| HIPAA | `hipaa_aws.json` | ✅ Works | Via NIST 800-66 |
| GDPR | `gdpr_aws.json` | ⚠️ Limited | Article-level only |
| PCI DSS | `pci_3.2.1_aws.json` | ❌ Unusable | Service-based IDs, not requirement IDs |
| CMMC | None | ❌ Missing | No Prowler compliance file |
| NIST CSF v2.0 | None | ❌ Missing | No Prowler compliance file |

**PCI DSS Limitation:** Prowler's PCI DSS file uses AWS service names as IDs (e.g., "autoscaling", "cloudtrail") instead of PCI requirement IDs (e.g., "1.1.1", "3.4.1"). This makes it incompatible with our requirement-level mapping system. The 52% coverage via SCF is the maximum achievable through automation.

**CMMC Limitation:** Prowler has no CMMC compliance file. However, CMMC Level 2 = NIST 800-171, and Prowler has `nist_800_171_revision_2_aws.json`. A bridge mapping could improve coverage (not implemented).

### Why SCF Mappings Are Incomplete

1. **Community-maintained**: SCF is an open-source project, not an official standard
2. **Version lag**: ISO 27001:2022 is relatively new; SCF STRM files may reflect older versions
3. **Interpretation differences**: What "maps" to what is subjective
4. **Focus areas**: SCF may prioritize certain frameworks over others

### The Dual-Source Architecture (Fixed)

```
                    ┌─────────────────────────────────────┐
                    │ PRIMARY: Prowler Native Mappings    │
Prowler Checks ────►│ SecurityCheck.mapped_requirements   │────► Framework Requirements
                    └─────────────────────────────────────┘
                                    │
                                    │ FALLBACK (if no Prowler mapping)
                                    ▼
                    ┌─────────────────────────────────────┐
                    │ SCF Hub Mappings                    │
                    │ SecurityCheck → SCFControl → Reqs   │────► Framework Requirements
                    └─────────────────────────────────────┘
```

**Fix implemented:** `auto_control_service.py` now combines BOTH sources when creating ControlRequirementMappings.

## Recommended Alternative Sources

### 1. NIST Cybersecurity Framework Mappings (Official)

**Source:** [NIST CSF Reference Tool](https://www.nist.gov/cyberframework/reference-tool)

**What it provides:**
- Official NIST-maintained mappings
- CSF ↔ NIST 800-53 ↔ CIS Controls
- High accuracy, authoritative

**Use for:** NIST CSF v1.1, NIST CSF v2.0, NIST 800-53

### 2. Cloud Security Alliance CCM (CSA)

**Source:** [CSA Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**What it provides:**
- CCM ↔ ISO 27001 ↔ SOC2 ↔ PCI DSS ↔ NIST
- Cloud-focused mappings
- Well-maintained, widely used

**Use for:** ISO 27001, SOC2, PCI DSS

### 3. CIS Controls Mappings

**Source:** [CIS Controls Navigator](https://www.cisecurity.org/controls/cis-controls-navigator)

**What it provides:**
- CIS Controls ↔ NIST CSF ↔ ISO 27001
- Practical, implementation-focused
- Strong Prowler alignment (Prowler checks map to CIS)

**Use for:** NIST CSF, ISO 27001

### 4. CMMC Assessment Guide (DoD)

**Source:** [CMMC Assessment Guide](https://dodcio.defense.gov/CMMC/)

**What it provides:**
- Official CMMC ↔ NIST 800-171 mappings
- DoD-authoritative
- Practice-level detail

**Use for:** CMMC v2.0

### 5. AICPA SOC2 Trust Services Criteria

**Source:** [AICPA Trust Services Criteria](https://www.aicpa.org/resources/download/trust-services-criteria)

**What it provides:**
- Official SOC2 criteria definitions
- Points of focus for each criterion
- Authoritative for SOC2 audits

**Use for:** SOC2 (validate existing mappings)

## Recommended Actions

### Short-term (Quick Wins)

1. **Document limitations** in user-facing compliance reports
2. **Prioritize frameworks** - NIST CSF v2.0 and SOC2 work well today
3. **Add disclaimers** - "Scan coverage is partial for ISO 27001"
4. **Set expectations for PCI DSS** - 52% is the automated maximum

### Medium-term (Supplement SCF)

1. **Import CIS Controls mappings** as secondary source for ISO 27001
2. **Create manual mappings** for critical gaps (e.g., IRO-02 → A.5.24-28)
3. **Add NIST 800-53** as intermediate hub (Prowler → 800-53 → Frameworks)
4. **CMMC via 800-171 bridge** - Add NIST 800-171 support, create CMMC mapping

### Long-term (Architecture Change)

1. **Multi-source mapping system** - Don't rely solely on SCF
2. **Direct Prowler-to-framework mappings** where available
3. **User-editable mappings** - Let customers customize for their needs
4. **Manual requirement evidence** - Allow users to mark requirements as satisfied with uploaded evidence

## Appendix: Unmapped ISO 27001 Annex A Controls

| Ref ID | Control Name |
|--------|--------------|
| A.5.1 | Policies for information security |
| A.5.10 | Acceptable use of information and other associated assets |
| A.5.11 | Return of assets |
| A.5.12 | Classification of information |
| A.5.13 | Labelling of information |
| A.5.14 | Information transfer |
| A.5.15 | Access control |
| A.5.16 | Identity management |
| A.5.17 | Authentication information |
| A.5.18 | Access rights |
| A.5.19 | Information security in supplier relationships |
| A.5.20 | Addressing information security within supplier agreements |
| A.5.21 | Managing information security in the ICT supply chain |
| A.5.22 | Monitor, review and change management of supplier services |
| A.5.23 | Information security for use of cloud services |
| A.5.24 | Information security incident management planning and preparation |
| A.5.25 | Assessment and decision on information security events |
| A.5.26 | Response to information security incidents |
| A.5.27 | Learning from information security incidents |
| A.5.28 | Collection of evidence |
| A.5.29 | Information security during disruption |
| A.5.30 | ICT readiness for business continuity |
| A.5.31 | Legal, statutory, regulatory and contractual requirements |
| A.5.32 | Intellectual property rights |
| A.5.33 | Protection of records |
| A.5.34 | Privacy and protection of PII |
| A.5.35 | Independent review of information security |
| A.5.36 | Compliance with policies, rules and standards |
| A.5.37 | Documented operating procedures |
| A.5.6 | Contact with special interest groups |
| A.5.7 | Threat intelligence |
| A.5.8 | Information security in project management |
| A.5.9 | Inventory of information and other associated assets |

## Related Documentation

- [SCF Website](https://securecontrolsframework.com)
- [SCF STRM Files](https://github.com/securecontrolsframework/strm)
- [sql-table-flow.md](../../features/prowler-scans/sql-table-flow.md)
