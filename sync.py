"""
Asset Sync Service

Discovers assets from external integrations and syncs them to the Asset model.
Handles deduplication, update-vs-create logic, stale asset detection, and
relationship extraction (e.g., EC2 → VPC, Lambda → IAM Role).
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Set

import structlog
from django.db import transaction
from django.utils import timezone

from core.models import Asset, AssetHistory, AssetRelationship
from integrations.models import Integration
from integrations.providers.aws import AWSProvider, AWSProviderError

logger = structlog.get_logger(__name__)


# Relationship extraction rules: maps service_type to list of
# (raw_data_field, relationship_type, target_service_type)
RELATIONSHIP_EXTRACTORS = {
    "ec2": [
        ("vpc_id", "belongs_to", "vpc"),
        ("subnet_id", "belongs_to", "subnet"),  # Phase 4.5: EC2 -> Subnet
        ("security_groups", "protected_by", "security_group"),  # List field
        # Phase 4.5: EC2 instance profile → IAM Role (fetches actual role ARN)
        ("iam_role_arn", "assumes", "iam_role"),
    ],
    "lambda": [
        ("vpc_id", "runs_in", "vpc"),
        ("role_arn", "assumes", "iam_role"),
        (
            "security_groups",
            "protected_by",
            "security_group",
        ),  # Phase 4.5: VPC Lambda SGs
    ],
    "security_group": [
        ("vpc_id", "belongs_to", "vpc"),
        # Phase 4.5: SG cross-references (inbound from other SGs)
        ("referenced_security_groups", "allows_from", "security_group"),  # List field
    ],
    "subnet": [
        ("vpc_id", "belongs_to", "vpc"),  # Phase 4.5: Subnet -> VPC
    ],
    "ebs": [
        ("kms_key_id", "encrypted_by", "kms"),
        # Phase 4.5: EBS volume → EC2 instance attachment
        ("attached_instance_ids", "attached_to", "ec2"),  # List field
    ],
    "cloudtrail": [
        ("s3_bucket_name", "logs_to", "s3"),
        ("kms_key_id", "encrypted_by", "kms"),
    ],
    "rds": [
        ("kms_key_id", "encrypted_by", "kms"),
        ("vpc_id", "belongs_to", "vpc"),
        # Phase 4.5: RDS → Security Groups
        ("security_groups", "protected_by", "security_group"),  # List field
    ],
    "elb": [
        ("vpc_id", "belongs_to", "vpc"),
        ("security_groups", "protected_by", "security_group"),
    ],
    "dynamodb": [
        ("kms_key_arn", "encrypted_by", "kms"),
    ],
    "s3": [
        ("kms_key_id", "encrypted_by", "kms"),
    ],
    "secrets_manager": [
        ("kms_key_id", "encrypted_by", "kms"),
    ],
    "sns": [
        ("kms_key_id", "encrypted_by", "kms"),
    ],
    "sqs": [
        ("kms_key_id", "encrypted_by", "kms"),
    ],
    "ecs": [
        ("cluster_arn", "belongs_to", "ecs_cluster"),
    ],
    # Phase 4.5: New Tier 1 extractors
    "cloudwatch": [
        ("kms_key_id", "encrypted_by", "kms"),
    ],
    "ssm_parameter": [
        ("key_id", "encrypted_by", "kms"),
    ],
    "kinesis": [
        ("key_id", "encrypted_by", "kms"),
    ],
    # Phase 4.5: Target Groups
    "target_group": [
        ("vpc_id", "belongs_to", "vpc"),
        ("load_balancer_arns", "receives_from", "elb"),  # Target Group ← Load Balancer
        ("target_ids", "routes_to", "ec2"),  # Target Group → EC2 (instance targets)
    ],
}


@dataclass
class SyncResult:
    """Results from an asset sync operation."""

    created: int = 0
    updated: int = 0
    deactivated: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    relationships_deactivated: int = 0
    errors: list = field(default_factory=list)

    @property
    def total_processed(self) -> int:
        return self.created + self.updated

    def to_dict(self) -> dict:
        return {
            "created": self.created,
            "updated": self.updated,
            "deactivated": self.deactivated,
            "total_processed": self.total_processed,
            "relationships_created": self.relationships_created,
            "relationships_updated": self.relationships_updated,
            "relationships_deactivated": self.relationships_deactivated,
            "errors": self.errors,
        }


class SyncService:
    """
    Service for syncing assets from integrations.

    Usage:
        service = SyncService(integration)
        result = service.sync_assets()
    """

    def __init__(self, integration: Integration):
        self.integration = integration
        self.sync_time = timezone.now()

    def sync_assets(self) -> SyncResult:
        """
        Sync all assets from the integration.

        Returns:
            SyncResult with counts of created, updated, deactivated assets
        """
        if not self.integration.is_connected:
            raise ValueError("Integration must be connected before syncing")

        if self.integration.provider == Integration.Provider.AWS:
            return self._sync_aws_assets()
        else:
            raise NotImplementedError(
                f"Sync not implemented for {self.integration.provider}"
            )

    def _sync_aws_assets(self) -> SyncResult:
        """Sync assets from AWS."""
        result = SyncResult()

        provider = AWSProvider(
            role_arn=self.integration.aws_role_arn or "",
            external_id=self.integration.aws_external_id,
            regions=self.integration.aws_regions or ["us-east-1"],
        )

        try:
            raw_assets = provider.discover_assets()
        except AWSProviderError as e:
            self.integration.mark_error(str(e))
            result.errors.append(str(e))
            return result

        # Track which source_ids we've seen (for deactivation)
        seen_source_ids: Set[str] = set()
        # Track assets by source_id for relationship extraction
        assets_by_source_id: Dict[str, Asset] = {}
        # Track which service types were synced (for scoped relationship deactivation)
        service_types_synced: Set[str] = set()

        with transaction.atomic():
            # Process EC2 instances
            for instance in raw_assets.get("ec2_instances", []):
                asset = self._process_ec2(instance, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("ec2")

            # Process S3 buckets
            for bucket in raw_assets.get("s3_buckets", []):
                asset = self._process_s3(bucket, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("s3")

            # Process IAM users
            for user in raw_assets.get("iam_users", []):
                asset = self._process_iam_user(user, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("iam_user")

            # Process IAM roles
            for role in raw_assets.get("iam_roles", []):
                asset = self._process_iam_role(role, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("iam_role")

            # Process RDS instances
            for db in raw_assets.get("rds_instances", []):
                asset = self._process_rds(db, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("rds")

            # Process Lambda functions
            for func in raw_assets.get("lambda_functions", []):
                asset = self._process_lambda(func, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("lambda")

            # Process IAM policies
            for policy in raw_assets.get("iam_policies", []):
                asset = self._process_iam_policy(policy, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("iam_policy")

            # Process CloudTrail trails
            for trail in raw_assets.get("cloudtrail_trails", []):
                asset = self._process_cloudtrail(trail, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("cloudtrail")

            # Process CloudWatch log groups
            for group in raw_assets.get("cloudwatch_log_groups", []):
                asset = self._process_log_group(group, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("cloudwatch")

            # Process AWS Config recorders
            for recorder in raw_assets.get("config_recorders", []):
                asset = self._process_config_recorder(recorder, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("config")

            # Process VPCs
            for vpc in raw_assets.get("vpcs", []):
                asset = self._process_vpc(vpc, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("vpc")

            # Phase 4.5: Process Subnets
            for subnet in raw_assets.get("subnets", []):
                asset = self._process_subnet(subnet, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("subnet")

            # Process Security Groups
            for sg in raw_assets.get("security_groups", []):
                asset = self._process_security_group(sg, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("security_group")

            # Process EBS volumes
            for vol in raw_assets.get("ebs_volumes", []):
                asset = self._process_ebs_volume(vol, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("ebs")

            # Process KMS keys
            for key in raw_assets.get("kms_keys", []):
                asset = self._process_kms_key(key, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("kms")

            # Process Secrets Manager secrets
            for secret in raw_assets.get("secrets", []):
                asset = self._process_secret(secret, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("secrets_manager")

            # Process GuardDuty detectors
            for detector in raw_assets.get("guardduty_detectors", []):
                asset = self._process_guardduty(detector, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("guardduty")

            # Process Security Hub
            for hub in raw_assets.get("security_hub", []):
                asset = self._process_security_hub(hub, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("security_hub")

            # Process WAF Web ACLs
            for acl in raw_assets.get("waf_web_acls", []):
                asset = self._process_waf(acl, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("waf")

            # Process ACM Certificates
            for cert in raw_assets.get("acm_certificates", []):
                asset = self._process_acm(cert, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("acm")

            # Process Inspector findings
            for finding in raw_assets.get("inspector_findings", []):
                asset = self._process_inspector(finding, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("inspector")

            # Process Macie findings
            for finding in raw_assets.get("macie_findings", []):
                asset = self._process_macie(finding, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("macie")

            # Process Load Balancers
            for lb in raw_assets.get("load_balancers", []):
                asset = self._process_elb(lb, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("elb")

            # Phase 4.5: Process Target Groups
            for tg in raw_assets.get("target_groups", []):
                asset = self._process_target_group(tg, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("target_group")

            # Process Route 53 zones
            for zone in raw_assets.get("route53_zones", []):
                asset = self._process_route53(zone, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("route53")

            # Process Access Analyzers
            for analyzer in raw_assets.get("access_analyzers", []):
                asset = self._process_access_analyzer(analyzer, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("access_analyzer")

            # Process SSM Parameters
            for param in raw_assets.get("ssm_parameters", []):
                asset = self._process_ssm_parameter(param, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("ssm_parameter")

            # Process ECR Repositories
            for repo in raw_assets.get("ecr_repositories", []):
                asset = self._process_ecr(repo, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("ecr")

            # Process EKS Clusters
            for cluster in raw_assets.get("eks_clusters", []):
                asset = self._process_eks(cluster, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("eks")

            # Process ECS Clusters
            for cluster in raw_assets.get("ecs_clusters", []):
                asset = self._process_ecs_cluster(cluster, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("ecs_cluster")

            # Process ECS Services
            for svc in raw_assets.get("ecs_services", []):
                asset = self._process_ecs_service(svc, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("ecs")

            # Process API Gateways
            for api in raw_assets.get("api_gateways", []):
                asset = self._process_api_gateway(api, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("api_gateway")

            # Process CloudFront Distributions
            for dist in raw_assets.get("cloudfront_distributions", []):
                asset = self._process_cloudfront(dist, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("cloudfront")

            # Process DynamoDB Tables
            for table in raw_assets.get("dynamodb_tables", []):
                asset = self._process_dynamodb(table, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("dynamodb")

            # Process ElastiCache Clusters
            for cluster in raw_assets.get("elasticache_clusters", []):
                asset = self._process_elasticache(cluster, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("elasticache")

            # Process SNS Topics
            for topic in raw_assets.get("sns_topics", []):
                asset = self._process_sns(topic, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("sns")

            # Process SQS Queues
            for queue in raw_assets.get("sqs_queues", []):
                asset = self._process_sqs(queue, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("sqs")

            # Process Kinesis Streams
            for stream in raw_assets.get("kinesis_streams", []):
                asset = self._process_kinesis(stream, result, seen_source_ids)
                if asset:
                    assets_by_source_id[asset.source_id] = asset
                    service_types_synced.add("kinesis")

            # Deactivate assets not seen in this sync
            deactivated = self._deactivate_stale_assets(seen_source_ids)
            result.deactivated = deactivated

            # Extract relationships from raw_source_data
            seen_relationships = self._extract_relationships(
                assets_by_source_id, result
            )

            # Deactivate relationships not seen (scoped to synced service types)
            rel_deactivated = self._deactivate_stale_relationships(
                seen_relationships, service_types_synced
            )
            result.relationships_deactivated = rel_deactivated

            # Update integration sync time
            self.integration.last_sync_at = self.sync_time
            self.integration.save(update_fields=["last_sync_at", "updated_at"])

        logger.info(
            "AWS asset sync complete",
            integration_id=str(self.integration.id),
            created=result.created,
            updated=result.updated,
            deactivated=result.deactivated,
            relationships_created=result.relationships_created,
            relationships_updated=result.relationships_updated,
            relationships_deactivated=result.relationships_deactivated,
        )

        return result

    def _extract_relationships(
        self, assets_by_source_id: Dict[str, Asset], result: SyncResult
    ) -> Set[int]:
        """
        Extract relationships from assets' raw_source_data.

        Handles two types of extraction:
        1. Field-based: Direct field references (e.g., vpc_id -> VPC)
        2. Policy-based: IAM policy document parsing for 'accesses' relationships

        Returns set of relationship IDs that were seen (for deactivation logic).
        """
        seen_relationship_ids: Set[int] = set()

        for source_id, asset in assets_by_source_id.items():
            service_type = asset.service_type

            # Field-based extraction (vpc_id, kms_key_id, etc.)
            extractors = RELATIONSHIP_EXTRACTORS.get(service_type, [])

            for field_name, rel_type, target_service_type in extractors:
                raw_data = asset.raw_source_data or {}
                target_refs = raw_data.get(field_name)

                if not target_refs:
                    continue

                # Handle both single values and lists
                if not isinstance(target_refs, list):
                    target_refs = [target_refs]

                for target_ref in target_refs:
                    if not target_ref:
                        continue

                    # Find target asset
                    target_asset = self._find_target_asset(
                        target_ref, target_service_type, assets_by_source_id
                    )

                    if not target_asset:
                        continue

                    # Create or update relationship
                    relationship = self._upsert_relationship(
                        source_asset=asset,
                        target_asset=target_asset,
                        relationship_type=rel_type,
                        raw_evidence={
                            "source_field": field_name,
                            "target_ref": target_ref,
                        },
                        result=result,
                    )

                    if relationship:
                        seen_relationship_ids.add(relationship.id)

            # Policy-based extraction for IAM roles and users
            if service_type in ("iam_role", "iam_user"):
                policy_rel_ids = self._extract_policy_relationships(
                    asset, assets_by_source_id, result
                )
                seen_relationship_ids.update(policy_rel_ids)

            # Phase 4.5: Trust policy extraction for trusted_by relationships (roles only)
            if service_type == "iam_role":
                trust_rel_ids = self._extract_trust_relationships(
                    asset, assets_by_source_id, result
                )
                seen_relationship_ids.update(trust_rel_ids)

            # Phase 4.5: Bucket policy extraction for S3
            if service_type == "s3":
                bucket_policy_rel_ids = self._extract_bucket_policy_relationships(
                    asset, assets_by_source_id, result
                )
                seen_relationship_ids.update(bucket_policy_rel_ids)

        return seen_relationship_ids

    def _find_target_asset(
        self,
        target_ref: str,
        target_service_type: str,
        assets_by_source_id: Dict[str, Asset],
    ) -> Optional[Asset]:
        """
        Find a target asset by reference (ARN, ID, or name).

        First checks the in-memory cache, then falls back to database lookup.
        Supports cross-integration relationships.
        """
        # Normalize the reference for lookup
        # For VPC IDs like "vpc-123", we need to find the asset with that ID
        # For ARNs, we can look up directly

        # First, check if it's a full ARN in our cache
        if target_ref in assets_by_source_id:
            return assets_by_source_id[target_ref]

        # For partial references (vpc-xxx, sg-xxx), search by ID
        # The ID might be in the ARN or in the raw_source_data
        for source_id, asset in assets_by_source_id.items():
            if asset.service_type != target_service_type:
                continue

            raw_data = asset.raw_source_data or {}

            # Check if the ID field matches
            if raw_data.get("id") == target_ref:
                return asset

            # Check if the ARN contains the reference
            if target_ref in source_id:
                return asset

            # For S3 buckets, check name
            if target_service_type == "s3" and raw_data.get("name") == target_ref:
                return asset

        # Fall back to database lookup (for cross-integration relationships)
        # Look for active assets with matching service_type
        try:
            # Try by source_id containing the reference
            asset = Asset.objects.filter(
                service_type=target_service_type,
                is_active=True,
                source_id__icontains=target_ref,
            ).first()
            if asset:
                return asset

            # For S3 buckets, also try by name
            if target_service_type == "s3":
                asset = Asset.objects.filter(
                    service_type="s3",
                    is_active=True,
                    name__icontains=target_ref,
                ).first()
                if asset:
                    return asset

        except Exception as e:
            logger.warning(
                "Error looking up target asset",
                target_ref=target_ref,
                target_service_type=target_service_type,
                error=str(e),
            )

        return None

    def _upsert_relationship(
        self,
        source_asset: Asset,
        target_asset: Asset,
        relationship_type: str,
        raw_evidence: dict,
        result: SyncResult,
    ) -> Optional[AssetRelationship]:
        """
        Create or update a relationship between assets.

        Uses soft-delete lifecycle: reactivates if previously deactivated.
        """
        try:
            # Look for existing relationship (active or inactive)
            relationship = AssetRelationship.objects.filter(
                source_asset=source_asset,
                target_asset=target_asset,
                relationship_type=relationship_type,
            ).first()

            if relationship:
                # Update existing
                was_inactive = not relationship.is_active
                relationship.is_active = True
                relationship.ended_at = None
                relationship.last_seen_at = self.sync_time
                relationship.raw_evidence = raw_evidence
                relationship.save()

                if was_inactive:
                    result.relationships_created += 1  # Reactivated counts as created
                else:
                    result.relationships_updated += 1

                return relationship

            # Create new relationship
            relationship = AssetRelationship.objects.create(
                source_asset=source_asset,
                target_asset=target_asset,
                relationship_type=relationship_type,
                is_active=True,
                last_seen_at=self.sync_time,
                discovered_from="aws_raw_data",
                raw_evidence=raw_evidence,
            )
            result.relationships_created += 1
            return relationship

        except Exception as e:
            logger.warning(
                "Failed to create relationship",
                source=str(source_asset),
                target=str(target_asset),
                type=relationship_type,
                error=str(e),
            )
            return None

    # ARN prefix to service_type mapping for policy parsing
    ARN_SERVICE_MAP = {
        "arn:aws:s3:::": "s3",
        "arn:aws:dynamodb:": "dynamodb",
        "arn:aws:rds:": "rds",
        "arn:aws:sqs:": "sqs",
        "arn:aws:sns:": "sns",
        "arn:aws:kms:": "kms",
        "arn:aws:secretsmanager:": "secrets_manager",
        "arn:aws:lambda:": "lambda",
        "arn:aws:ec2:": "ec2",
        "arn:aws:ecs:": "ecs",
        "arn:aws:ecr:": "ecr",
    }

    def _arn_to_service_type(self, arn: str) -> Optional[str]:
        """Map ARN prefix to asset service_type."""
        # Handle IAM ARNs specially since account ID is in the middle
        # Format: arn:aws:iam::<account-id>:role/<name> or :user/<name>
        if arn.startswith("arn:aws:iam:"):
            if ":role/" in arn:
                return "iam_role"
            if ":user/" in arn:
                return "iam_user"
            # Skip root accounts, groups, policies, etc.
            return None

        for prefix, service_type in self.ARN_SERVICE_MAP.items():
            if arn.startswith(prefix):
                return service_type
        return None

    def _extract_policy_relationships(
        self,
        asset: Asset,
        assets_by_source_id: Dict[str, Asset],
        result: SyncResult,
    ) -> Set[int]:
        """
        Extract 'accesses' relationships from IAM role's policy documents.

        Parses both attached managed policies and inline policies to find
        resource ARNs that the role can access.

        Returns set of relationship IDs created.
        """
        seen_ids: Set[int] = set()
        raw_data = asset.raw_source_data or {}

        # Collect all policy documents to parse
        policy_docs = []

        # Inline policies (already have the document)
        for inline in raw_data.get("inline_policies", []):
            doc = inline.get("policy_document")
            if doc:
                policy_docs.append(("inline", inline.get("policy_name"), doc))

        # For attached policies, we need to look up the policy asset
        for attached in raw_data.get("attached_policies", []):
            policy_arn = attached.get("policy_arn")
            if policy_arn:
                # Find the policy asset to get its document
                policy_asset = self._find_target_asset(
                    policy_arn, "iam_policy", assets_by_source_id
                )
                if policy_asset and policy_asset.raw_source_data:
                    doc = policy_asset.raw_source_data.get("policy_document")
                    if doc:
                        policy_docs.append(
                            ("attached", attached.get("policy_name"), doc)
                        )

        # Parse each policy document for resource ARNs
        for policy_type, policy_name, doc in policy_docs:
            for statement in doc.get("Statement", []):
                # Only process Allow statements
                if statement.get("Effect") != "Allow":
                    continue

                resources = statement.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]

                for resource_arn in resources:
                    # Skip wildcards - too broad to be useful
                    if resource_arn == "*" or resource_arn.endswith(":*"):
                        continue

                    # Determine target service type from ARN
                    target_type = self._arn_to_service_type(resource_arn)
                    if not target_type:
                        continue

                    # Find the target asset
                    target_asset = self._find_target_asset(
                        resource_arn, target_type, assets_by_source_id
                    )
                    if not target_asset:
                        continue

                    # Create the 'accesses' relationship
                    relationship = self._upsert_relationship(
                        source_asset=asset,
                        target_asset=target_asset,
                        relationship_type="accesses",
                        raw_evidence={
                            "policy_type": policy_type,
                            "policy_name": policy_name,
                            "statement": statement,
                            "resource_arn": resource_arn,
                        },
                        result=result,
                    )

                    if relationship:
                        seen_ids.add(relationship.id)

        return seen_ids

    def _extract_trust_relationships(
        self,
        asset: Asset,
        assets_by_source_id: Dict[str, Asset],
        result: SyncResult,
    ) -> Set[int]:
        """
        Phase 4.5: Extract 'trusted_by' relationships from IAM role's AssumeRolePolicyDocument.

        Parses the trust policy to find principals that can assume this role.
        Creates relationships:
        - IAM Role <- trusted_by <- IAM Role/User (if principal is another IAM entity)

        Service principals (lambda.amazonaws.com, ec2.amazonaws.com) are stored in
        raw_evidence but don't create relationships (services aren't assets).

        Returns set of relationship IDs created.
        """
        seen_ids: Set[int] = set()
        raw_data = asset.raw_source_data or {}
        trust_policy = raw_data.get("assume_role_policy")

        if not trust_policy:
            return seen_ids

        for statement in trust_policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principals = statement.get("Principal", {})

            # Handle the case where Principal is just "*" (dangerous!)
            if principals == "*":
                logger.warning(
                    "IAM role has dangerous trust policy allowing any principal",
                    role_arn=asset.source_id,
                )
                continue

            # Handle AWS principals (accounts, roles, users)
            aws_principals = principals.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for principal_arn in aws_principals:
                if not principal_arn or principal_arn == "*":
                    continue

                # Determine target service type from ARN
                # Handles: arn:aws:iam::123456:role/RoleName
                #          arn:aws:iam::123456:user/UserName
                #          arn:aws:iam::123456:root (account root)
                target_type = self._arn_to_service_type(principal_arn)
                if not target_type:
                    # Could be an account root or unknown format
                    continue

                # Find the target asset
                target_asset = self._find_target_asset(
                    principal_arn, target_type, assets_by_source_id
                )
                if not target_asset:
                    continue

                # Create the 'trusted_by' relationship
                # Direction: This role <- trusted_by <- the principal that can assume it
                relationship = self._upsert_relationship(
                    source_asset=asset,
                    target_asset=target_asset,
                    relationship_type="trusted_by",
                    raw_evidence={
                        "statement": statement,
                        "principal_arn": principal_arn,
                        "principal_type": "aws",
                    },
                    result=result,
                )

                if relationship:
                    seen_ids.add(relationship.id)

            # Note: Service principals (lambda.amazonaws.com, etc.) are not processed
            # into relationships because services aren't assets. The trust policy info
            # is still available in raw_source_data for display in the UI.

        return seen_ids

    def _extract_bucket_policy_relationships(
        self,
        asset: Asset,
        assets_by_source_id: Dict[str, Asset],
        result: SyncResult,
    ) -> Set[int]:
        """
        Phase 4.5: Extract 'accessible_by' relationships from S3 bucket policy.

        Parses the bucket policy to find IAM principals that have access.
        Creates relationships:
        - S3 Bucket <- accessible_by <- IAM Role/User

        Service principals and account-wide access are noted but don't create
        relationships (services/accounts aren't assets).

        Returns set of relationship IDs created.
        """
        seen_ids: Set[int] = set()
        raw_data = asset.raw_source_data or {}
        bucket_policy = raw_data.get("bucket_policy")

        if not bucket_policy:
            return seen_ids

        for statement in bucket_policy.get("Statement", []):
            # Only process Allow statements for access relationships
            if statement.get("Effect") != "Allow":
                continue

            principals = statement.get("Principal", {})

            # Handle wildcard principal (dangerous! - bucket is public)
            if principals == "*":
                logger.warning(
                    "S3 bucket has dangerous policy allowing any principal",
                    bucket_arn=asset.source_id,
                )
                continue

            # Handle AWS principals (accounts, roles, users)
            aws_principals = principals.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for principal_arn in aws_principals:
                if not principal_arn or principal_arn == "*":
                    continue

                # Determine target service type from ARN
                # Handles: arn:aws:iam::123456:role/RoleName
                #          arn:aws:iam::123456:user/UserName
                target_type = self._arn_to_service_type(principal_arn)
                if not target_type:
                    # Could be an account root or unknown format
                    continue

                # Find the target asset
                target_asset = self._find_target_asset(
                    principal_arn, target_type, assets_by_source_id
                )
                if not target_asset:
                    continue

                # Create the 'accessible_by' relationship
                # Direction: This bucket <- accessible_by <- the principal that has access
                relationship = self._upsert_relationship(
                    source_asset=asset,
                    target_asset=target_asset,
                    relationship_type="accessible_by",
                    raw_evidence={
                        "statement": statement,
                        "principal_arn": principal_arn,
                        "actions": statement.get("Action", []),
                        "resources": statement.get("Resource", []),
                    },
                    result=result,
                )

                if relationship:
                    seen_ids.add(relationship.id)

        return seen_ids

    def _deactivate_stale_relationships(
        self, seen_relationship_ids: Set[int], service_types_synced: Set[str]
    ) -> int:
        """
        Deactivate relationships not seen in this sync.

        IMPORTANT: Only deactivates relationships where the SOURCE asset's
        service_type was included in this sync. This prevents partial syncs
        from incorrectly deactivating unrelated relationships.
        """
        if not service_types_synced:
            return 0

        # Get IDs as a list for the exclude query
        seen_ids_list = list(seen_relationship_ids)

        stale_relationships = AssetRelationship.objects.filter(
            source_asset__source_integration=self.integration,
            source_asset__service_type__in=service_types_synced,
            is_active=True,
        )

        if seen_ids_list:
            stale_relationships = stale_relationships.exclude(id__in=seen_ids_list)

        count = stale_relationships.update(
            is_active=False,
            ended_at=self.sync_time,
        )

        if count > 0:
            logger.info(
                "Deactivated stale relationships",
                integration_id=str(self.integration.id),
                count=count,
            )

        return count

    def _upsert_asset(
        self,
        source_id: str,
        name: str,
        description: str,
        raw_data: dict,
        result: SyncResult,
        seen_source_ids: Set[str],
        service_type: str = "",
    ) -> Optional[Asset]:
        """
        Create or update an asset by source_id.

        Handles the case where resource IDs change (e.g., LocalStack restart)
        but the resource name stays the same. In this case, we update the
        existing asset's source_id rather than creating a duplicate.

        Phase 7.3: Creates AssetHistory entries for:
        - New asset creation
        - Config changes (raw_source_data changed)
        - Reactivation (asset was deactivated, now found again)

        Returns the created/updated Asset for relationship extraction.
        """
        seen_source_ids.add(source_id)

        truncated_name = name[:200]

        # First, try to find by exact source_id
        try:
            asset = Asset.objects.get(
                source=Asset.AssetSource.AWS,
                source_id=source_id,
            )
            # Phase 7.3: Track state for history
            was_inactive = not asset.is_active
            old_raw_data = asset.raw_source_data
            old_name = asset.name

            # Found by source_id - update it
            asset.name = truncated_name
            asset.description = description
            asset.source_integration = self.integration
            asset.last_seen_at = self.sync_time
            asset.is_active = True
            asset.deactivated_at = None  # Clear if previously deactivated
            asset.raw_source_data = raw_data
            if service_type:
                asset.service_type = service_type
            asset.save()

            # Phase 7.3: Create history entries
            if was_inactive:
                # Reactivation
                AssetHistory.objects.create(
                    asset=asset,
                    change_type=AssetHistory.ChangeType.REACTIVATED,
                    previous_raw_data=old_raw_data,
                    previous_name=old_name,
                    triggered_by="sync",
                )
            elif old_raw_data != raw_data:
                # Config changed
                AssetHistory.objects.create(
                    asset=asset,
                    change_type=AssetHistory.ChangeType.CONFIG_CHANGED,
                    previous_raw_data=old_raw_data,
                    previous_name=old_name,
                    triggered_by="sync",
                )

            result.updated += 1
            return asset
        except Asset.DoesNotExist:
            pass

        # Not found by source_id - check if an asset with this name exists
        # in the same folder from AWS source (resource ID may have changed)
        # Don't require exact source_integration match - LocalStack restarts
        # generate new IDs, and integration might have been modified
        try:
            asset = Asset.objects.get(
                source=Asset.AssetSource.AWS,
                name=truncated_name,
                folder=self.integration.folder,
            )
            # Phase 7.3: Track state for history
            was_inactive = not asset.is_active
            old_raw_data = asset.raw_source_data
            old_name = asset.name
            old_source_id = asset.source_id

            # Found by name - update its source_id and other fields
            asset.source_id = source_id
            asset.source_integration = self.integration  # Claim this asset
            asset.description = description
            asset.last_seen_at = self.sync_time
            asset.is_active = True
            asset.deactivated_at = None  # Clear if previously deactivated
            asset.raw_source_data = raw_data
            if service_type:
                asset.service_type = service_type
            asset.save()

            logger.info(
                "Updated asset source_id (resource ID changed)",
                name=truncated_name,
                old_source_id=old_source_id,
                new_source_id=source_id,
            )

            # Phase 7.3: Create history entries
            if was_inactive:
                # Reactivation
                AssetHistory.objects.create(
                    asset=asset,
                    change_type=AssetHistory.ChangeType.REACTIVATED,
                    previous_raw_data=old_raw_data,
                    previous_name=old_name,
                    triggered_by="sync",
                )
            elif old_raw_data != raw_data:
                # Config changed
                AssetHistory.objects.create(
                    asset=asset,
                    change_type=AssetHistory.ChangeType.CONFIG_CHANGED,
                    previous_raw_data=old_raw_data,
                    previous_name=old_name,
                    triggered_by="sync",
                )

            result.updated += 1
            return asset
        except Asset.DoesNotExist:
            pass

        # Not found - create new asset
        asset = Asset.objects.create(
            name=truncated_name,
            description=description,
            source=Asset.AssetSource.AWS,
            source_id=source_id,
            source_integration=self.integration,
            last_seen_at=self.sync_time,
            is_active=True,
            raw_source_data=raw_data,
            folder=self.integration.folder,
            type=Asset.Type.SUPPORT,
            service_type=service_type,
        )

        # Phase 7.3: Create history for new asset
        AssetHistory.objects.create(
            asset=asset,
            change_type=AssetHistory.ChangeType.CREATED,
            triggered_by="sync",
        )

        result.created += 1
        return asset

    def _process_ec2(
        self, instance: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an EC2 instance."""
        source_id = instance.get("arn")
        if not source_id:
            # Fallback ARN construction if not provided
            instance_id = instance.get("id")
            region = instance.get("region", "us-east-1")
            account_id = instance.get("account_id", "000000000000")
            source_id = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"

        name = instance.get("name") or f"EC2 {instance.get('id', 'unknown')}"
        state = instance.get("state", "unknown")
        instance_type = instance.get("type", "unknown")

        description = f"EC2 Instance ({instance_type}) - {state}"

        return self._upsert_asset(
            source_id, name, description, instance, result, seen, "ec2"
        )

    def _process_s3(
        self, bucket: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an S3 bucket."""
        source_id = bucket.get("arn")
        if not source_id:
            bucket_name = bucket.get("name")
            source_id = f"arn:aws:s3:::{bucket_name}"

        name = bucket.get("name", "Unknown Bucket")
        description = "S3 Bucket"
        if bucket.get("created"):
            description += f" (created: {bucket['created'][:10]})"

        return self._upsert_asset(
            source_id, name, description, bucket, result, seen, "s3"
        )

    def _process_iam_user(
        self, user: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an IAM user."""
        source_id = user.get("arn")
        if not source_id:
            return None  # Skip if no ARN

        name = f"IAM User: {user.get('name', 'unknown')}"
        description = "IAM User"
        if user.get("created"):
            description += f" (created: {user['created'][:10]})"

        return self._upsert_asset(
            source_id, name, description, user, result, seen, "iam_user"
        )

    def _process_iam_role(
        self, role: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an IAM role."""
        source_id = role.get("arn")
        if not source_id:
            return None  # Skip if no ARN

        name = f"IAM Role: {role.get('name', 'unknown')}"
        description = "IAM Role"

        return self._upsert_asset(
            source_id, name, description, role, result, seen, "iam_role"
        )

    def _process_rds(
        self, db: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an RDS instance."""
        source_id = db.get("arn")
        if not source_id:
            return None  # Skip if no ARN

        db_id = db.get("id", "unknown")
        name = db.get("name") or f"RDS {db_id}"

        engine = db.get("engine", "unknown")
        status = db.get("status", "unknown")
        description = f"RDS Database ({engine}) - {status}"

        return self._upsert_asset(source_id, name, description, db, result, seen, "rds")

    def _process_lambda(
        self, func: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a Lambda function."""
        source_id = func.get("arn")
        if not source_id:
            return None  # Skip if no ARN

        name = func.get("name", "Unknown Function")
        runtime = func.get("runtime", "unknown")
        in_vpc = func.get("in_vpc", False)
        description = f"Lambda Function ({runtime})"
        if in_vpc:
            description += " [VPC]"

        return self._upsert_asset(
            source_id, name, description, func, result, seen, "lambda"
        )

    def _process_iam_policy(
        self, policy: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an IAM policy."""
        source_id = policy.get("arn")
        if not source_id:
            return None

        name = f"IAM Policy: {policy.get('name', 'unknown')}"
        attachments = policy.get("attachment_count", 0)
        description = f"IAM Policy ({attachments} attachments)"

        return self._upsert_asset(
            source_id, name, description, policy, result, seen, "iam_policy"
        )

    def _process_cloudtrail(
        self, trail: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a CloudTrail trail."""
        source_id = trail.get("arn")
        if not source_id:
            return None

        name = f"CloudTrail: {trail.get('name', 'unknown')}"
        is_logging = trail.get("is_logging", False)
        multi_region = trail.get("is_multi_region", False)
        status = "logging" if is_logging else "NOT logging"
        description = f"CloudTrail ({status})"
        if multi_region:
            description += " [multi-region]"

        return self._upsert_asset(
            source_id, name, description, trail, result, seen, "cloudtrail"
        )

    def _process_log_group(
        self, group: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a CloudWatch Log Group."""
        source_id = group.get("arn")
        if not source_id:
            return None

        name = group.get("name", "unknown")
        retention = group.get("retention_days")
        description = "CloudWatch Log Group"
        if retention:
            description += f" ({retention}d retention)"
        else:
            description += " (no retention)"

        return self._upsert_asset(
            source_id, name, description, group, result, seen, "cloudwatch"
        )

    def _process_config_recorder(
        self, recorder: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an AWS Config recorder."""
        source_id = recorder.get("arn")
        if not source_id:
            return None

        name = f"Config Recorder: {recorder.get('name', 'unknown')}"
        recording = recorder.get("recording", False)
        status = "recording" if recording else "NOT recording"
        description = f"AWS Config ({status})"

        return self._upsert_asset(
            source_id, name, description, recorder, result, seen, "config"
        )

    def _process_vpc(
        self, vpc: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a VPC."""
        source_id = vpc.get("arn")
        if not source_id:
            return None

        vpc_id = vpc.get("id", "unknown")
        vpc_name = vpc.get("name")
        # Use descriptive name with ID to ensure uniqueness
        if vpc_name and vpc_name != vpc_id:
            name = f"VPC: {vpc_name} ({vpc_id})"
        else:
            name = f"VPC: {vpc_id}"

        is_default = vpc.get("is_default", False)
        flow_logs = vpc.get("flow_logs_enabled", False)

        description = "VPC"
        if is_default:
            description += " [DEFAULT]"
        if not flow_logs:
            description += " [no flow logs]"

        return self._upsert_asset(
            source_id, name, description, vpc, result, seen, "vpc"
        )

    def _process_subnet(
        self, subnet: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Phase 4.5: Process a Subnet."""
        source_id = subnet.get("arn")
        if not source_id:
            return None

        subnet_id = subnet.get("id", "unknown")
        subnet_name = subnet.get("name")
        # Use descriptive name with ID to ensure uniqueness
        if subnet_name and subnet_name != subnet_id:
            name = f"Subnet: {subnet_name} ({subnet_id})"
        else:
            name = f"Subnet: {subnet_id}"

        az = subnet.get("availability_zone", "")
        cidr = subnet.get("cidr_block", "")
        public = subnet.get("map_public_ip_on_launch", False)

        description = f"Subnet in {az}"
        if cidr:
            description += f" ({cidr})"
        if public:
            description += " [public]"

        return self._upsert_asset(
            source_id, name, description, subnet, result, seen, "subnet"
        )

    def _process_security_group(
        self, sg: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a Security Group."""
        source_id = sg.get("arn")
        if not source_id:
            return None

        sg_id = sg.get("id", "unknown")
        sg_name = sg.get("name")
        # Use descriptive name with ID to ensure uniqueness
        if sg_name and sg_name != sg_id:
            name = f"SG: {sg_name} ({sg_id})"
        else:
            name = f"SG: {sg_id}"

        has_risky = sg.get("has_risky_rules", False)
        open_ports = sg.get("open_to_world_ports", [])

        description = "Security Group"
        if has_risky:
            description += f" [OPEN: {','.join(map(str, open_ports))}]"

        return self._upsert_asset(
            source_id, name, description, sg, result, seen, "security_group"
        )

    def _process_ebs_volume(
        self, vol: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an EBS volume."""
        source_id = vol.get("arn")
        if not source_id:
            return None

        name = vol.get("name") or vol.get("id", "unknown")
        size = vol.get("size_gb", 0)
        encrypted = vol.get("encrypted", False)

        description = f"EBS Volume ({size}GB)"
        if not encrypted:
            description += " [UNENCRYPTED]"

        return self._upsert_asset(
            source_id, name, description, vol, result, seen, "ebs"
        )

    def _process_kms_key(
        self, key: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a KMS key."""
        source_id = key.get("arn")
        if not source_id:
            return None

        key_id = key.get("id", "unknown")[:8]
        name = f"KMS Key: {key_id}"
        rotation = key.get("rotation_enabled", False)
        state = key.get("state", "unknown")

        description = f"KMS Key ({state})"
        if not rotation:
            description += " [no rotation]"

        return self._upsert_asset(
            source_id, name, description, key, result, seen, "kms"
        )

    def _process_secret(
        self, secret: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a Secrets Manager secret."""
        source_id = secret.get("arn")
        if not source_id:
            return None

        name = f"Secret: {secret.get('name', 'unknown')}"
        rotation = secret.get("rotation_enabled", False)

        description = "Secrets Manager Secret"
        if not rotation:
            description += " [no rotation]"

        return self._upsert_asset(
            source_id, name, description, secret, result, seen, "secrets_manager"
        )

    def _process_guardduty(
        self, detector: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a GuardDuty detector."""
        source_id = detector.get("arn")
        if not source_id:
            return None

        region = detector.get("region", "unknown")
        name = f"GuardDuty: {region}"
        enabled = detector.get("enabled", False)

        description = "GuardDuty Detector"
        if enabled:
            description += " (enabled)"
        else:
            description += " (DISABLED)"

        return self._upsert_asset(
            source_id, name, description, detector, result, seen, "guardduty"
        )

    def _process_security_hub(
        self, hub: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process Security Hub."""
        source_id = hub.get("arn")
        if not source_id:
            return None

        region = hub.get("region", "unknown")
        name = f"Security Hub: {region}"
        standards = hub.get("standards", [])

        description = "Security Hub"
        if standards:
            description += f" ({len(standards)} standards)"

        return self._upsert_asset(
            source_id, name, description, hub, result, seen, "security_hub"
        )

    def _process_waf(
        self, acl: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a WAF Web ACL."""
        source_id = acl.get("arn")
        if not source_id:
            return None

        name = f"WAF: {acl.get('name', 'unknown')}"
        scope = acl.get("scope", "REGIONAL")
        description = f"WAF Web ACL ({scope})"

        return self._upsert_asset(
            source_id, name, description, acl, result, seen, "waf"
        )

    def _process_acm(
        self, cert: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an ACM certificate."""
        source_id = cert.get("arn")
        if not source_id:
            return None

        domain = cert.get("domain", "unknown")
        name = f"Certificate: {domain}"
        status = cert.get("status", "unknown")
        expires = cert.get("expires", "")

        description = f"ACM Certificate ({status})"
        if expires:
            description += f" expires {expires[:10]}"

        return self._upsert_asset(
            source_id, name, description, cert, result, seen, "acm"
        )

    def _process_inspector(
        self, finding: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an Inspector finding."""
        source_id = finding.get("arn")
        if not source_id:
            return None

        title = finding.get("title", "Unknown Finding")[:100]
        name = f"Inspector: {title}"
        severity = finding.get("severity", "unknown")
        description = f"Inspector Finding ({severity})"

        return self._upsert_asset(
            source_id, name, description, finding, result, seen, "inspector"
        )

    def _process_macie(
        self, finding: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a Macie finding."""
        source_id = finding.get("arn")
        if not source_id:
            return None

        title = finding.get("title", "Unknown Finding")[:100]
        name = f"Macie: {title}"
        severity = finding.get("severity", "unknown")
        description = f"Macie Finding ({severity})"

        return self._upsert_asset(
            source_id, name, description, finding, result, seen, "macie"
        )

    def _process_elb(
        self, lb: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a Load Balancer."""
        source_id = lb.get("arn")
        if not source_id:
            return None

        name = lb.get("name", "Unknown LB")
        lb_type = lb.get("type", "application")
        scheme = lb.get("scheme", "internet-facing")
        access_logs = lb.get("access_logs_enabled", False)

        description = f"Load Balancer ({lb_type}, {scheme})"
        if not access_logs:
            description += " [no access logs]"

        return self._upsert_asset(source_id, name, description, lb, result, seen, "elb")

    def _process_target_group(
        self, tg: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Phase 4.5: Process a Target Group."""
        source_id = tg.get("arn")
        if not source_id:
            return None

        tg_name = tg.get("name", "Unknown TG")
        target_type = tg.get("target_type", "instance")  # instance, ip, lambda
        protocol = tg.get("protocol", "HTTP")
        port = tg.get("port", 80)
        targets = tg.get("targets", [])
        healthy_count = sum(1 for t in targets if t.get("health_state") == "healthy")
        total_count = len(targets)

        name = f"Target Group: {tg_name}"
        description = f"Target Group ({protocol}:{port}, {target_type})"
        if total_count > 0:
            description += f" [{healthy_count}/{total_count} healthy]"

        return self._upsert_asset(
            source_id, name, description, tg, result, seen, "target_group"
        )

    def _process_route53(
        self, zone: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a Route 53 hosted zone."""
        source_id = zone.get("arn")
        if not source_id:
            return None

        zone_name = zone.get("name", "unknown")
        name = f"Route53: {zone_name}"
        private = zone.get("private", False)
        dnssec = zone.get("dnssec_status", "NOT_SIGNING")

        description = "Route 53 Hosted Zone"
        if private:
            description += " (private)"
        if dnssec != "SIGNING":
            description += " [no DNSSEC]"

        return self._upsert_asset(
            source_id, name, description, zone, result, seen, "route53"
        )

    def _process_access_analyzer(
        self, analyzer: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an IAM Access Analyzer."""
        source_id = analyzer.get("arn")
        if not source_id:
            return None

        name = f"Access Analyzer: {analyzer.get('name', 'unknown')}"
        analyzer_type = analyzer.get("type", "ACCOUNT")
        has_findings = analyzer.get("has_findings", False)

        description = f"IAM Access Analyzer ({analyzer_type})"
        if has_findings:
            description += " [has findings]"

        return self._upsert_asset(
            source_id, name, description, analyzer, result, seen, "access_analyzer"
        )

    def _process_ssm_parameter(
        self, param: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an SSM Parameter."""
        source_id = param.get("arn")
        if not source_id:
            return None

        param_name = param.get("name", "unknown")
        name = f"SSM: {param_name}"
        param_type = param.get("type", "String")

        description = f"SSM Parameter ({param_type})"
        if param_type == "SecureString":
            description = "SSM Parameter (encrypted)"

        return self._upsert_asset(
            source_id, name, description, param, result, seen, "ssm_parameter"
        )

    def _process_ecr(
        self, repo: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an ECR repository."""
        source_id = repo.get("arn")
        if not source_id:
            return None

        name = repo.get("name", "Unknown Repo")
        scan_on_push = repo.get("scan_on_push", False)

        description = "ECR Repository"
        if not scan_on_push:
            description += " [no scan on push]"

        return self._upsert_asset(
            source_id, name, description, repo, result, seen, "ecr"
        )

    def _process_eks(
        self, cluster: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an EKS cluster."""
        source_id = cluster.get("arn")
        if not source_id:
            return None

        name = cluster.get("name", "Unknown Cluster")
        version = cluster.get("version", "unknown")
        public = cluster.get("endpoint_public", True)

        description = f"EKS Cluster (v{version})"
        if public:
            description += " [public endpoint]"

        return self._upsert_asset(
            source_id, name, description, cluster, result, seen, "eks"
        )

    def _process_ecs_cluster(
        self, cluster: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an ECS cluster."""
        source_id = cluster.get("arn")
        if not source_id:
            return None

        name = cluster.get("name", "Unknown Cluster")
        running = cluster.get("running_tasks", 0)
        insights = cluster.get("container_insights", False)

        description = f"ECS Cluster ({running} tasks)"
        if not insights:
            description += " [no insights]"

        return self._upsert_asset(
            source_id, name, description, cluster, result, seen, "ecs_cluster"
        )

    def _process_ecs_service(
        self, svc: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an ECS service."""
        source_id = svc.get("arn")
        if not source_id:
            return None

        name = svc.get("name", "Unknown Service")
        running = svc.get("running_count", 0)
        desired = svc.get("desired_count", 0)
        launch_type = svc.get("launch_type", "EC2")

        description = f"ECS Service ({launch_type}, {running}/{desired})"

        return self._upsert_asset(
            source_id, name, description, svc, result, seen, "ecs"
        )

    def _process_api_gateway(
        self, api: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an API Gateway."""
        source_id = api.get("arn")
        if not source_id:
            return None

        name = api.get("name", "Unknown API")
        endpoint_type = api.get("endpoint_type", "EDGE")

        description = f"API Gateway ({endpoint_type})"

        return self._upsert_asset(
            source_id, name, description, api, result, seen, "api_gateway"
        )

    def _process_cloudfront(
        self, dist: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a CloudFront distribution."""
        source_id = dist.get("arn")
        if not source_id:
            return None

        domain = dist.get("domain_name", "unknown")
        name = f"CloudFront: {domain}"
        waf_attached = bool(dist.get("waf_web_acl_id"))

        description = "CloudFront Distribution"
        if not waf_attached:
            description += " [no WAF]"

        return self._upsert_asset(
            source_id, name, description, dist, result, seen, "cloudfront"
        )

    def _process_dynamodb(
        self, table: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a DynamoDB table."""
        source_id = table.get("arn")
        if not source_id:
            return None

        name = table.get("name", "Unknown Table")
        pitr = table.get("pitr_enabled", False)
        encryption = table.get("encryption_type", "NONE")

        description = "DynamoDB Table"
        if not pitr:
            description += " [no PITR]"
        if encryption == "NONE":
            description += " [unencrypted]"

        return self._upsert_asset(
            source_id, name, description, table, result, seen, "dynamodb"
        )

    def _process_elasticache(
        self, cluster: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an ElastiCache cluster."""
        source_id = cluster.get("arn")
        if not source_id:
            return None

        cluster_id = cluster.get("id", "unknown")
        name = f"ElastiCache: {cluster_id}"
        engine = cluster.get("engine", "redis")
        transit = cluster.get("transit_encryption", False)

        description = f"ElastiCache ({engine})"
        if not transit:
            description += " [no TLS]"

        return self._upsert_asset(
            source_id, name, description, cluster, result, seen, "elasticache"
        )

    def _process_sns(
        self, topic: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an SNS topic."""
        source_id = topic.get("arn")
        if not source_id:
            return None

        name = topic.get("name", "Unknown Topic")
        encrypted = topic.get("encrypted", False)

        description = "SNS Topic"
        if not encrypted:
            description += " [unencrypted]"

        return self._upsert_asset(
            source_id, name, description, topic, result, seen, "sns"
        )

    def _process_sqs(
        self, queue: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process an SQS queue."""
        source_id = queue.get("arn")
        if not source_id:
            return None

        name = queue.get("name", "Unknown Queue")
        encrypted = queue.get("encrypted", False)

        description = "SQS Queue"
        if not encrypted:
            description += " [unencrypted]"

        return self._upsert_asset(
            source_id, name, description, queue, result, seen, "sqs"
        )

    def _process_kinesis(
        self, stream: dict, result: SyncResult, seen: Set[str]
    ) -> Optional[Asset]:
        """Process a Kinesis stream."""
        source_id = stream.get("arn")
        if not source_id:
            return None

        name = stream.get("name", "Unknown Stream")
        encryption = stream.get("encryption_type", "NONE")
        shards = stream.get("shard_count", 0)

        description = f"Kinesis Stream ({shards} shards)"
        if encryption == "NONE":
            description += " [unencrypted]"

        return self._upsert_asset(
            source_id, name, description, stream, result, seen, "kinesis"
        )

    def _deactivate_stale_assets(self, seen_source_ids: Set[str]) -> int:
        """
        Mark assets as inactive if they weren't seen in this sync.

        Only deactivates assets from THIS integration that are currently active.
        Phase 7.3: Creates AssetHistory entries for each deactivated asset.
        """
        stale_assets = Asset.objects.filter(
            source=Asset.AssetSource.AWS,
            source_integration=self.integration,
            is_active=True,
        ).exclude(source_id__in=seen_source_ids)

        count = 0
        deactivation_time = timezone.now()

        # Phase 7.3: Iterate to create history entries for each
        for asset in stale_assets:
            # Create history entry before deactivation
            AssetHistory.objects.create(
                asset=asset,
                change_type=AssetHistory.ChangeType.DEACTIVATED,
                previous_raw_data=asset.raw_source_data,
                previous_name=asset.name,
                triggered_by="sync",
            )
            # Deactivate the asset
            asset.is_active = False
            asset.deactivated_at = deactivation_time
            asset.save(update_fields=["is_active", "deactivated_at", "updated_at"])
            count += 1

        if count > 0:
            logger.info(
                "Deactivated stale assets",
                integration_id=str(self.integration.id),
                count=count,
            )

        return count
