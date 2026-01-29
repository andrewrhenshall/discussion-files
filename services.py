"""
Compliance Engine Service

Orchestrates compliance scanning:
1. Gets mapped check IDs from SecurityCheck model
2. Runs the appropriate compliance engine
3. Matches findings to Assets by ARN (or auto-creates)
4. Creates CheckResult records

This is the main entry point for triggering scans.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

import structlog
from django.db import transaction
from django.utils import timezone

from compliance_engines.base import CheckEvaluation, CheckStatus
from compliance_engines.prowler import ProwlerEngine

if TYPE_CHECKING:
    from core.models import Asset, CheckResult, SecurityCheck
    from integrations.models import Integration

logger = structlog.get_logger(__name__)


@dataclass
class ScanResult:
    """Results from a compliance scan operation."""

    results_created: int = 0
    arns_skipped: int = 0  # ARNs not found in asset database (run asset sync first!)
    checks_executed: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_error: int = 0
    checks_not_applicable: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)
    skipped_arns: List[str] = field(default_factory=list)  # For debugging
    # Phase 6.5: Auto-created controls
    controls_created: int = 0
    controls_updated: int = 0
    # Phase 7: Auto-created evidence
    evidence_created: int = 0
    evidence_updated: int = 0
    # Phase 7.1: Resource snapshots and audit trail
    snapshots_captured: int = 0
    snapshots_failed: int = 0
    history_entries_created: int = 0

    def to_dict(self) -> dict:
        return {
            "results_created": self.results_created,
            "arns_skipped": self.arns_skipped,
            "checks_executed": self.checks_executed,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "checks_error": self.checks_error,
            "checks_not_applicable": self.checks_not_applicable,
            "duration_seconds": round(self.duration_seconds, 2),
            "errors": self.errors,
            "controls_created": self.controls_created,
            "controls_updated": self.controls_updated,
            "evidence_created": self.evidence_created,
            "evidence_updated": self.evidence_updated,
            "snapshots_captured": self.snapshots_captured,
            "snapshots_failed": self.snapshots_failed,
            "history_entries_created": self.history_entries_created,
        }


class ComplianceEngineService:
    """
    Service for running compliance scans via various engines.

    This is the main entry point for triggering scans. It:
    1. Loads check IDs that have mapped requirements (meaningful for compliance)
    2. Runs the specified engine (default: Prowler)
    3. Matches findings to Assets by ARN (must exist from prior asset sync)
    4. SKIPS findings for unknown ARNs (asset sync should run first!)
    5. Creates CheckResult records

    IMPORTANT: The scan endpoint should run asset discovery BEFORE Prowler
    to ensure all resources are properly cataloged with full metadata.
    Unknown ARNs are skipped (not auto-created as skeleton records).

    Usage:
        service = ComplianceEngineService(integration)
        result = service.run_scan()
    """

    def __init__(self, integration: "Integration"):
        self.integration = integration
        self.scan_time = timezone.now()
        self._asset_cache: Dict[str, "Asset"] = {}
        self._check_cache: Dict[str, "SecurityCheck"] = {}
        self._snapshot_service = None

    @property
    def snapshot_service(self):
        """Lazily instantiate ResourceSnapshotService."""
        if self._snapshot_service is None:
            from core.security_check_utils.resource_snapshot_service import (
                ResourceSnapshotService,
            )

            self._snapshot_service = ResourceSnapshotService(self.integration)
        return self._snapshot_service

    def run_scan(self, engine_name: str = "prowler") -> ScanResult:
        """
        Run a compliance scan for this integration.

        Args:
            engine_name: Which engine to use ("prowler" for now)

        Returns:
            ScanResult with counts and any errors
        """

        result = ScanResult()

        # Validate integration
        if not self.integration.is_connected:
            result.errors.append("Integration must be connected before scanning")
            return result

        if self.integration.provider != "aws":
            result.errors.append(
                f"Scan not implemented for provider: {self.integration.provider}"
            )
            return result

        # Get checks with mapped requirements
        check_ids = self._get_mapped_check_ids()
        if not check_ids:
            result.errors.append(
                "No SecurityCheck records with mapped_requirements found"
            )
            return result

        logger.info(
            "Starting compliance scan",
            integration_id=str(self.integration.id),
            engine=engine_name,
            check_count=len(check_ids),
        )

        # Get engine
        engine = self._get_engine(engine_name)
        if not engine:
            result.errors.append(f"Unknown engine: {engine_name}")
            return result

        # Run engine
        try:
            engine_result = engine.evaluate_checks(
                integration=self.integration,
                check_ids=check_ids,
            )
        except Exception as e:
            logger.error("Engine execution failed", error=str(e))
            result.errors.append(f"Engine error: {e}")
            return result

        result.duration_seconds = engine_result.duration_seconds
        result.checks_executed = engine_result.checks_executed
        result.errors.extend(engine_result.errors)

        # Process findings
        created_check_results = []
        if engine_result.evaluations:
            with transaction.atomic():
                created_check_results = self._process_evaluations(
                    engine_result.evaluations, result
                )

        # Phase 6.5: Auto-create controls from scan results
        auto_control_service = None
        if created_check_results:
            try:
                from core.security_check_utils.auto_control_service import (
                    AutoControlService,
                )

                auto_control_service = AutoControlService(
                    integration=self.integration,
                    scan_time=self.scan_time,
                )
                # Pass the actual CheckResult objects, not a timestamp-filtered query
                created, updated = auto_control_service.process_check_results(
                    created_check_results
                )
                result.controls_created = created
                result.controls_updated = updated
            except Exception as e:
                logger.error(
                    "Auto-control creation failed",
                    error=str(e),
                    integration_id=str(self.integration.id),
                )
                result.errors.append(f"Auto-control error: {e}")

        # Phase 7: Auto-create evidence from scan results (1 Evidence per CheckResult)
        if created_check_results:
            try:
                from core.security_check_utils.auto_evidence_service import (
                    AutoEvidenceService,
                )

                evidence_service = AutoEvidenceService(
                    integration=self.integration,
                    scan_time=self.scan_time,
                )
                # Pass CheckResults directly - creates 1 Evidence per CheckResult
                ev_created, ev_updated = evidence_service.process_check_results(
                    created_check_results
                )
                result.evidence_created = ev_created
                result.evidence_updated = ev_updated
            except Exception as e:
                logger.error(
                    "Auto-evidence creation failed",
                    error=str(e),
                    integration_id=str(self.integration.id),
                )
                result.errors.append(f"Auto-evidence error: {e}")

        logger.info(
            "Compliance scan complete",
            integration_id=str(self.integration.id),
            results_created=result.results_created,
            passed=result.checks_passed,
            failed=result.checks_failed,
            arns_skipped=result.arns_skipped,
            controls_created=result.controls_created,
            controls_updated=result.controls_updated,
            evidence_created=result.evidence_created,
            evidence_updated=result.evidence_updated,
        )

        # Warn if many ARNs were skipped (may indicate stale asset data)
        if result.arns_skipped > 0:
            logger.warning(
                "Some findings were skipped due to unknown ARNs. "
                "Ensure asset sync runs before scans.",
                arns_skipped=result.arns_skipped,
                sample_arns=result.skipped_arns[:5],  # Log first 5 for debugging
            )

        return result

    def _get_engine(self, engine_name: str):
        """Get engine instance by name."""
        engines = {
            "prowler": ProwlerEngine,
        }
        engine_class = engines.get(engine_name)
        if engine_class:
            return engine_class()
        return None

    def _get_mapped_check_ids(self) -> List[str]:
        """
        Get check IDs that have mapped compliance requirements.

        Only runs checks that:
        1. Are active
        2. Have at least one mapped_requirements relation
        3. Are from the prowler provider
        """
        from core.models import SecurityCheck

        checks = SecurityCheck.objects.filter(
            is_active=True,
            provider="prowler",
            mapped_requirements__isnull=False,
        ).distinct()

        # Cache checks for later lookup
        self._check_cache = {c.check_id: c for c in checks}

        return list(self._check_cache.keys())

    def _process_evaluations(
        self,
        evaluations: List[CheckEvaluation],
        result: ScanResult,
    ) -> List:
        """Process engine evaluations and create CheckResult records.

        History is preserved when status changes (pass→fail or fail→pass).
        If status is unchanged, only the scanned_at timestamp is updated.

        Returns:
            List of created/updated CheckResult objects for Phase 6.5 auto-control processing
        """

        # Build asset cache for fast lookups
        self._build_asset_cache()

        created_results = []
        for evaluation in evaluations:
            try:
                check_result = self._process_single_evaluation(evaluation, result)
                if check_result:
                    created_results.append(check_result)
            except Exception as e:
                logger.warning(
                    "Failed to process evaluation",
                    check_id=evaluation.check_id,
                    error=str(e),
                )
                result.errors.append(f"Processing error for {evaluation.check_id}: {e}")

        return created_results

    def _process_single_evaluation(
        self,
        evaluation: CheckEvaluation,
        result: ScanResult,
    ) -> Optional["CheckResult"]:
        """Process a single evaluation into a CheckResult.

        History tracking:
        - If status changed (pass→fail or fail→pass): create CheckResultHistory record
        - If status unchanged: update existing record's scanned_at timestamp
        - If no existing record: create new record

        Snapshot capture (Phase 7.1):
        - Captures actual AWS resource configuration at scan time
        - Stores in CheckResult.resource_snapshot for auditor evidence
        - Also stored in CheckResultHistory for audit trail

        Returns:
            The created/updated CheckResult, or None if skipped
        """
        from core.models import CheckResult, CheckResultHistory

        # Find SecurityCheck
        security_check = self._check_cache.get(evaluation.check_id)
        if not security_check:
            logger.debug("Check not in mapped set", check_id=evaluation.check_id)
            return None

        # Find Asset (must exist from prior asset sync - no auto-creation)
        asset = self._find_asset(evaluation.asset_source_id)
        if not asset:
            # Skip this finding - asset not found (should have been discovered by sync)
            result.arns_skipped += 1
            if len(result.skipped_arns) < 50:  # Limit stored ARNs for memory
                result.skipped_arns.append(evaluation.asset_source_id)
            logger.debug(
                "Skipping finding for unknown ARN",
                check_id=evaluation.check_id,
                source_id=evaluation.asset_source_id,
            )
            return None

        # Map status to CheckResult.Status
        status = self._map_status(evaluation.status)

        # Prepare raw_output with engine metadata
        raw_output = evaluation.raw_output.copy() if evaluation.raw_output else {}
        raw_output["_engine"] = {
            "name": evaluation.engine_name,
            "version": evaluation.engine_version,
            "region": evaluation.region,
            "account_id": evaluation.account_id,
        }

        scan_time = evaluation.evaluated_at or self.scan_time

        # Phase 7.1: Capture resource snapshot
        resource_snapshot = {}
        snapshot_api_call = ""
        snapshot_captured = False

        if self.snapshot_service.supports_check(evaluation.check_id):
            try:
                snapshot_result = self.snapshot_service.capture_snapshot(
                    check_id=evaluation.check_id,
                    resource_arn=evaluation.asset_source_id,
                    region=evaluation.region,
                )
                resource_snapshot = snapshot_result["snapshot"]
                snapshot_api_call = snapshot_result["api_call"]
                snapshot_captured = snapshot_result["success"]

                if snapshot_captured:
                    result.snapshots_captured += 1
                else:
                    result.snapshots_failed += 1
            except Exception as e:
                logger.warning(
                    "Snapshot capture failed",
                    check_id=evaluation.check_id,
                    error=str(e),
                )
                result.snapshots_failed += 1

        # Check for existing result (get the latest one by scanned_at)
        existing = (
            CheckResult.objects.filter(
                security_check=security_check,
                asset=asset,
                integration=self.integration,
            )
            .order_by("-scanned_at")
            .first()
        )

        if existing:
            # Phase 7.2: Detect both status changes AND config changes
            status_changed = existing.status != status
            config_changed = (
                snapshot_captured
                and existing.resource_snapshot
                and resource_snapshot
                and existing.resource_snapshot != resource_snapshot
            )

            if status_changed or config_changed:
                # Create CheckResultHistory record BEFORE updating
                # Store the OLD config (what it was before the change)
                CheckResultHistory.objects.create(
                    check_result=existing,
                    old_status=existing.status,
                    new_status=status,
                    resource_snapshot=existing.resource_snapshot,  # OLD config
                    snapshot_api_call=existing.snapshot_api_call,
                )
                result.history_entries_created += 1

                change_type = "status" if status_changed else "config"
                logger.info(
                    f"{change_type.capitalize()} changed - created history record",
                    check_id=evaluation.check_id,
                    asset_id=str(asset.id),
                    old_status=existing.status,
                    new_status=status,
                    config_changed=config_changed,
                )

            # Update the existing record
            if status_changed:
                existing.status = status
                result.results_created += 1

            existing.scanned_at = scan_time
            existing.status_extended = (
                evaluation.status_extended[:1000] if evaluation.status_extended else ""
            )
            existing.raw_output = raw_output
            existing.resource_snapshot = resource_snapshot
            existing.snapshot_api_call = snapshot_api_call
            existing.snapshot_captured = snapshot_captured

            update_fields = [
                "scanned_at",
                "status_extended",
                "raw_output",
                "resource_snapshot",
                "snapshot_api_call",
                "snapshot_captured",
                "updated_at",
            ]
            if status_changed:
                update_fields.append("status")

            existing.save(update_fields=update_fields)
            check_result = existing
        else:
            # No existing record - create new
            check_result = CheckResult.objects.create(
                security_check=security_check,
                asset=asset,
                integration=self.integration,
                status=status,
                status_extended=evaluation.status_extended[:1000]
                if evaluation.status_extended
                else "",
                scanned_at=scan_time,
                raw_output=raw_output,
                resource_snapshot=resource_snapshot,
                snapshot_api_call=snapshot_api_call,
                snapshot_captured=snapshot_captured,
            )
            result.results_created += 1

        # Phase 7.3: Update asset's last_scanned_at timestamp
        asset.last_scanned_at = scan_time
        asset.save(update_fields=["last_scanned_at", "updated_at"])

        # Update counts
        if status == "pass":
            result.checks_passed += 1
        elif status == "fail":
            result.checks_failed += 1
        elif status == "error":
            result.checks_error += 1
        else:
            result.checks_not_applicable += 1

        return check_result

    def _map_status(self, check_status: CheckStatus) -> str:
        """Map CheckStatus to CheckResult.Status value."""
        return check_status.value  # They use the same string values

    def _build_asset_cache(self) -> None:
        """Load all assets for this integration into memory."""
        from core.models import Asset

        if self._asset_cache:
            return

        assets = Asset.objects.filter(
            source_integration=self.integration,
            is_active=True,
        )

        self._asset_cache = {a.source_id: a for a in assets if a.source_id}

    def _find_asset(self, source_id: str) -> Optional["Asset"]:
        """
        Find existing Asset by ARN/source_id.

        Does NOT auto-create - asset must exist from prior asset sync.
        This ensures all assets have full metadata from proper discovery.
        """
        from core.models import Asset

        if not source_id:
            return None

        # Try cache first
        if source_id in self._asset_cache:
            return self._asset_cache[source_id]

        # Try database lookup (exact match)
        asset = Asset.objects.filter(
            source_id=source_id,
            is_active=True,
        ).first()

        if asset:
            self._asset_cache[source_id] = asset

        return asset
