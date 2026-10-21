"""Read-only cloud security posture scans for AWS, Azure, and Google Cloud."""
import json
import itertools
import logging
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

import database

logger = logging.getLogger("bharatsec.cloud")
DB_PATH = Path(os.getenv("CLOUD_DATABASE_PATH", str(Path(__file__).resolve().parents[1] / "data" / "cloud.db")))
PROVIDERS = ("aws", "azure", "gcp")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
ADMIN_PORTS = (22, 3389)  # SSH and RDP: internet exposure of either is critical
_UNREADABLE = object()  # sentinel for a setting the scan was not allowed to read


def _port_spec_covers_admin(spec: str) -> bool:
    """True when an Azure port spec ("*", "22", "0-65535", "80,443") includes SSH or RDP."""
    for part in (spec or "").split(","):
        part = part.strip()
        if part == "*":
            return True
        low, _, high = part.partition("-")
        try:
            start, end = int(low), int(high or low)
        except ValueError:
            continue
        if any(start <= port <= end for port in ADMIN_PORTS):
            return True
    return False

PROVIDER_INFO = {
    "aws": {
        "name": "Amazon Web Services",
        "credential_chain": "AWS environment credentials, shared config/profile, web identity, container credentials, or instance role.",
        "setup": "Configure an AWS profile or role for the backend. Read-only checks need sts:GetCallerIdentity; s3:ListAllMyBuckets, s3:GetAccountPublicAccessBlock, s3:GetBucketPublicAccessBlock, s3:GetBucketPolicyStatus, s3:GetBucketAcl, s3:GetEncryptionConfiguration, s3:GetBucketLogging; iam:GetAccountAuthorizationDetails, iam:ListAccessKeys; and ec2:DescribeRegions, ec2:DescribeSecurityGroups, ec2:DescribeInstances.",
    },
    "azure": {
        "name": "Microsoft Azure",
        "credential_chain": "Azure DefaultAzureCredential: environment service principal, workload identity, managed identity, or Azure CLI login.",
        "setup": "Configure Azure service-principal environment variables, managed identity, or run az login for the backend user. Grant Reader plus Microsoft.Authorization/roleAssignments/read and Microsoft.Storage/storageAccounts/*/read on subscriptions to assess.",
    },
    "gcp": {
        "name": "Google Cloud",
        "credential_chain": "Application Default Credentials: GOOGLE_APPLICATION_CREDENTIALS, gcloud ADC, or attached workload identity.",
        "setup": "Configure Application Default Credentials for the backend. Grant resourcemanager.projects.list and resourcemanager.projects.getIamPolicy, storage.buckets.list/get/getIamPolicy, and compute.instances.list on projects you want to assess.",
    },
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _db() -> Generator[Any, None, None]:
    with database.transaction(DB_PATH) as connection:
        yield connection


def init_db() -> None:
    with _db() as connection:
        database.schema_lock(connection, "cloud")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cloud_scans (
                scan_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                account TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                result_json TEXT NOT NULL DEFAULT '{}',
                error TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS cloud_scans_recent ON cloud_scans(started_at DESC)")
        if "claimed" not in database.table_columns(connection, "cloud_scans"):
            connection.execute("ALTER TABLE cloud_scans ADD COLUMN claimed INTEGER NOT NULL DEFAULT 0")


def list_providers() -> list[dict[str, Any]]:
    return [
        {
            "id": provider,
            **details,
            "scans": _provider_scan_counts(provider),
        }
        for provider, details in PROVIDER_INFO.items()
    ]


def _provider_scan_counts(provider: str) -> dict[str, int]:
    with _db() as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM cloud_scans WHERE provider = ? GROUP BY status",
            (provider,),
        ).fetchall()
    return {row["status"]: row["total"] for row in rows}


def create_scan(provider: str) -> dict[str, Any]:
    if provider not in PROVIDERS:
        raise ValueError("Choose one of the supported cloud providers: AWS, Azure, or GCP.")
    scan_id = f"cloud_{uuid.uuid4().hex[:12]}"
    started_at = _now()
    with _db() as connection:
        connection.execute(
            "INSERT INTO cloud_scans (scan_id, provider, status, started_at) VALUES (?, ?, 'running', ?)",
            (scan_id, provider, started_at),
        )
    return {"scan_id": scan_id, "provider": provider, "status": "running", "started_at": started_at}


def claim_for_run(scan_id: str) -> bool:
    """Mark a newly created scan as started, so concurrent /run calls execute it only once."""
    with _db() as connection:
        cursor = connection.execute(
            "UPDATE cloud_scans SET claimed = 1 WHERE scan_id = ? AND status = 'running' AND claimed = 0",
            (scan_id,),
        )
        return cursor.rowcount == 1


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with _db() as connection:
        row = connection.execute("SELECT * FROM cloud_scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    payload = json.loads(result.pop("result_json"))
    result.update(payload)
    return result


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    with _db() as connection:
        rows = connection.execute(
            "SELECT * FROM cloud_scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    scans: list[dict[str, Any]] = []
    for row in rows:
        result = dict(row)
        payload = json.loads(result.pop("result_json"))
        result["summary"] = payload.get("summary", {})
        result["finding_count"] = len(payload.get("findings", []))
        scans.append(result)
    return scans


def run_scan(scan_id: str, provider: str) -> None:
    try:
        details = {
            "aws": scan_aws,
            "azure": scan_azure,
            "gcp": scan_gcp,
        }[provider]()
        findings = details.pop("findings")
        result = {
            "provider": provider,
            "provider_name": PROVIDER_INFO[provider]["name"],
            "account": details.pop("account", ""),
            "scanned_at": _now(),
            "summary": {
                "resources_scanned": details.pop("resources_scanned", 0),
                "critical": sum(item["severity"] == "CRITICAL" for item in findings),
                "high": sum(item["severity"] == "HIGH" for item in findings),
                "medium": sum(item["severity"] == "MEDIUM" for item in findings),
                "low": sum(item["severity"] == "LOW" for item in findings),
                "checks_with_errors": len(details.get("warnings", [])),
            },
            "findings": findings,
            "warnings": details.get("warnings", []),
            "coverage": details.get("coverage", []),
        }
        with _db() as connection:
            connection.execute(
                "UPDATE cloud_scans SET status = 'complete', account = ?, completed_at = ?, result_json = ? WHERE scan_id = ?",
                (result["account"], result["scanned_at"], json.dumps(result), scan_id),
            )
    except Exception as exc:
        logger.exception("Cloud %s scan %s failed", provider, scan_id)
        message = _safe_provider_error(exc)
        with _db() as connection:
            connection.execute(
                "UPDATE cloud_scans SET status = 'error', completed_at = ?, error = ? WHERE scan_id = ?",
                (_now(), message, scan_id),
            )


def _safe_provider_error(error: Exception) -> str:
    text = str(error).strip().replace("\n", " ")
    if len(text) > 500:
        text = text[:497] + "..."
    return text or f"{type(error).__name__}; check backend logs and provider setup."


def _azure_value(value: Any, *names: str) -> Any:
    if isinstance(value, dict):
        for name in names:
            if name in value:
                return value[name]
        return None
    for name in names:
        if hasattr(value, name):
            return getattr(value, name)
    return None


def _finding(
    provider: str,
    resource: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    evidence: str = "",
) -> dict[str, str]:
    return {
        "id": f"{provider}-{uuid.uuid4().hex[:10]}",
        "provider": provider,
        "resource": resource[:300],
        "title": title[:200],
        "severity": severity if severity in SEVERITIES else "MEDIUM",
        "category": category[:80],
        "description": description[:1000],
        "recommendation": recommendation[:1000],
        "evidence": evidence[:1000],
    }


def _aws_access_denied(exc: Exception) -> bool:
    response = getattr(exc, "response", {})
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    return error.get("Code") in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AllAccessDisabled"}


def scan_aws() -> dict[str, Any]:
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise RuntimeError("AWS scans require boto3. Install the backend requirements and retry.") from exc

    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        raise RuntimeError("AWS credentials were not found. Configure an AWS profile, environment credentials, or an attached role for the backend.")
    client_config = Config(connect_timeout=5, read_timeout=20, retries={"max_attempts": 2, "mode": "standard"})
    sts = session.client("sts", config=client_config)
    identity = sts.get_caller_identity()
    account = identity.get("Account", "unknown")
    findings: list[dict[str, str]] = []
    warnings: list[str] = []
    coverage = ["Account and bucket S3 public-access controls, bucket policies/ACLs/encryption/logging, IAM users/groups/roles, regional security groups, and public EC2 addresses."]
    resources_scanned = 0

    s3 = session.client("s3", config=client_config)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as exc:
        if not _aws_access_denied(exc):
            raise
        buckets = []
        warnings.append("S3 bucket inventory could not be read; grant s3:ListAllMyBuckets.")
    resources_scanned += len(buckets)
    if len(buckets) > 500:
        warnings.append("Only the first 500 S3 buckets were inspected; split large estates into scoped account scans.")
    try:
        account_access = session.client("s3control", config=client_config).get_public_access_block(AccountId=account)["PublicAccessBlockConfiguration"]
        if not all(account_access.get(key, False) for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            findings.append(_finding("aws", f"account/{account}", "S3 account public access block is incomplete", "HIGH", "Storage",
                                     "One or more account-level S3 Block Public Access safeguards are disabled.",
                                     "Enable all four account-level S3 Block Public Access settings and review the impact on existing data.",
                                     ", ".join(key for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets") if not account_access.get(key, False))))
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
            findings.append(_finding("aws", f"account/{account}", "S3 account public access block is not configured", "HIGH", "Storage",
                                     "No account-level S3 Block Public Access configuration was found.",
                                     "Enable all four account-level S3 Block Public Access settings and review the impact on existing data."))
        elif _aws_access_denied(exc):
            warnings.append("S3 account-level public access settings could not be read; grant s3:GetAccountPublicAccessBlock.")
        else:
            warnings.append("Could not verify S3 account-level public access safeguards.")
    for bucket in buckets[:500]:
        name = bucket["Name"]
        for label, operation in (
            ("public access block", lambda: s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]),
            ("bucket policy status", lambda: s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]),
            ("bucket ACL", lambda: s3.get_bucket_acl(Bucket=name)),
        ):
            try:
                value = operation()
            except Exception as exc:
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchBucketPolicy"}:
                    value = None
                elif _aws_access_denied(exc):
                    warnings.append(f"Could not read {label} for S3 bucket {name}; check read permissions.")
                    value = _UNREADABLE  # unknown state: warn, but never report it as a finding
                else:
                    logger.warning("AWS %s check failed for bucket %s: %s", label, name, exc)
                    warnings.append(f"Could not read {label} for S3 bucket {name}.")
                    value = _UNREADABLE
            if label == "public access block" and value is None:
                findings.append(_finding("aws", name, "S3 public access block is not configured", "HIGH", "Storage",
                                         "No bucket-level S3 Block Public Access configuration was found.",
                                         "Enable all four S3 Block Public Access settings and confirm account-level safeguards are also active.",
                                         "No bucket public-access block configuration"))
            elif label == "public access block" and isinstance(value, dict) and not all(value.get(key, False) for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
                findings.append(_finding("aws", name, "S3 public access block is incomplete", "HIGH", "Storage",
                                         "One or more account-independent bucket public-access safeguards are disabled.",
                                         "Enable all four S3 Block Public Access settings and confirm access policies are intentional.",
                                         ", ".join(key for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets") if not value.get(key, False))))
            elif label == "bucket policy status" and isinstance(value, dict) and value.get("IsPublic"):
                findings.append(_finding("aws", name, "S3 bucket policy permits public access", "CRITICAL", "Storage",
                                         "AWS reports that this bucket policy allows public access.",
                                         "Remove public principals and validate access through an approved identity and network path.",
                                         "PolicyStatus.IsPublic=true"))
            elif label == "bucket ACL" and isinstance(value, dict):
                public_grants = [
                    grant for grant in value.get("Grants", [])
                    if grant.get("Grantee", {}).get("URI", "").endswith(("/AllUsers", "/AuthenticatedUsers"))
                    and grant.get("Permission") in {"READ", "FULL_CONTROL", "WRITE", "WRITE_ACP"}
                ]
                if public_grants:
                    findings.append(_finding("aws", name, "S3 bucket ACL grants public access", "CRITICAL", "Storage",
                                             "The bucket ACL grants access to all users or all authenticated users.",
                                             "Remove public ACL grants and use least-privilege IAM or bucket policies.",
                                             ", ".join(grant.get("Permission", "") for grant in public_grants)))
        try:
            encryption = s3.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not encryption:
                findings.append(_finding("aws", name, "S3 default encryption is not configured", "MEDIUM", "Storage",
                                         "The bucket does not report default server-side encryption configuration.",
                                         "Configure default S3 server-side encryption and confirm existing objects meet data policy."))
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") not in {"ServerSideEncryptionConfigurationNotFoundError"}:
                warnings.append(f"Could not verify encryption for S3 bucket {name}.")
        try:
            logging_status = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
            if not logging_status:
                findings.append(_finding("aws", name, "S3 access logging is not enabled", "LOW", "Logging",
                                         "No server access logging destination is configured for this bucket.",
                                         "Enable access logging with an approved destination and retention policy."))
        except Exception:
            warnings.append(f"Could not verify access logging for S3 bucket {name}.")

    try:
        iam = session.client("iam", config=client_config)
        details: dict[str, list[dict[str, Any]]] = {
            "UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": [],
        }
        for page in iam.get_paginator("get_account_authorization_details").paginate(Filter=["User", "Group", "Role", "LocalManagedPolicy"]):
            for key in details:
                details[key].extend(page.get(key, []))
        resources_scanned += len(details.get("Policies", []))
        resources_scanned += len(details.get("UserDetailList", [])) + len(details.get("GroupDetailList", [])) + len(details.get("RoleDetailList", []))
        local_policies = {
            policy.get("Arn"): policy
            for policy in details.get("Policies", [])
        }
        for principal_type, key in (("IAM user", "UserDetailList"), ("IAM group", "GroupDetailList"), ("IAM role", "RoleDetailList")):
            for principal in details.get(key, []):
                policies = principal.get("AttachedManagedPolicies", [])
                for policy in policies:
                    if policy.get("PolicyName") == "AdministratorAccess":
                        findings.append(_finding("aws", principal.get("Arn", principal.get("UserName", principal.get("RoleName", principal_type))),
                                                 f"{principal_type} has AdministratorAccess", "HIGH", "Identity",
                                                 "This identity is attached to the broad AWS AdministratorAccess managed policy.",
                                                 "Replace administrator access with task-specific least-privilege permissions and review usage."))
                    local_policy = local_policies.get(policy.get("PolicyArn"))
                    if local_policy:
                        statements = local_policy.get("PolicyVersionList", [{}])
                        default_version = next((version for version in statements if version.get("IsDefaultVersion")), {})
                        policy_statements = default_version.get("Document", {}).get("Statement", [])
                        policy_statements = policy_statements if isinstance(policy_statements, list) else [policy_statements]
                        if any(statement.get("Effect") == "Allow"
                               and "*" in (statement.get("Action", []) if isinstance(statement.get("Action", []), list) else [statement.get("Action")])
                               and "*" in (statement.get("Resource", []) if isinstance(statement.get("Resource", []), list) else [statement.get("Resource")])
                               for statement in policy_statements):
                            findings.append(_finding("aws", principal.get("Arn", principal_type),
                                                     f"{principal_type} has a wildcard managed policy", "HIGH", "Identity",
                                                     "An attached customer-managed IAM policy grants all actions on all resources.",
                                                     "Scope the managed policy to required actions and resources.",
                                                     policy.get("PolicyName", "")))
                inline = principal.get("UserPolicyList", []) + principal.get("RolePolicyList", [])
                for policy in inline:
                    statements = policy.get("PolicyDocument", {}).get("Statement", [])
                    for statement in statements if isinstance(statements, list) else [statements]:
                        actions = statement.get("Action", [])
                        resources = statement.get("Resource", [])
                        actions = actions if isinstance(actions, list) else [actions]
                        resources = resources if isinstance(resources, list) else [resources]
                        if statement.get("Effect") == "Allow" and "*" in actions and "*" in resources:
                            findings.append(_finding("aws", principal.get("Arn", principal_type),
                                                     f"{principal_type} has wildcard administrative permissions", "HIGH", "Identity",
                                                     "An inline policy grants all actions on all resources.",
                                                     "Scope actions and resources to the minimum required for this identity.",
                                                     policy.get("PolicyName", "")))
                            break
        for user in details.get("UserDetailList", []):
            try:
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                for key in keys:
                    if key.get("Status") == "Active":
                        created = key["CreateDate"]
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=timezone.utc)
                        age = (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days
                        if age > 90:
                            findings.append(_finding("aws", user.get("Arn", user["UserName"]), "IAM access key is older than 90 days", "MEDIUM", "Identity",
                                                     "An active long-lived IAM access key was created more than 90 days ago.",
                                                     "Rotate or retire the access key; prefer temporary role credentials.",
                                                     f"Key age: {age} days"))
            except Exception:
                warnings.append(f"Could not inspect access keys for IAM user {user.get('UserName', 'unknown')}.")
    except Exception as exc:
        if _aws_access_denied(exc):
            warnings.append("IAM policy inventory could not be read; grant iam:GetAccountAuthorizationDetails and iam:ListAccessKeys.")
        else:
            logger.warning("AWS IAM inventory failed: %s", exc)
            warnings.append("AWS IAM policy inventory failed; check backend logs and IAM read permissions.")

    try:
        regions = session.client("ec2", region_name="us-east-1", config=client_config).describe_regions(AllRegions=False).get("Regions", [])
    except Exception as exc:
        if _aws_access_denied(exc):
            warnings.append("AWS region inventory could not be read; grant ec2:DescribeRegions.")
            regions = []
        else:
            raise
    for region in regions:
        region_name = region["RegionName"]
        ec2 = session.client("ec2", region_name=region_name, config=client_config)
        try:
            for page in ec2.get_paginator("describe_security_groups").paginate():
                for group in page.get("SecurityGroups", []):
                    resources_scanned += 1
                    for permission in group.get("IpPermissions", []):
                        ranges = permission.get("IpRanges", []) + permission.get("Ipv6Ranges", [])
                        public_ranges = [entry.get("CidrIp", entry.get("CidrIpv6", "")) for entry in ranges if entry.get("CidrIp", entry.get("CidrIpv6", "")) in {"0.0.0.0/0", "::/0"}]
                        if public_ranges:
                            protocol = permission.get("IpProtocol", "all")
                            ports = "all protocols" if protocol == "-1" else f"{permission.get('FromPort', '?')}-{permission.get('ToPort', '?')}/{protocol}"
                            covers_admin = any(
                                permission.get("FromPort", 0) <= port <= permission.get("ToPort", 65535)
                                for port in ADMIN_PORTS
                            )
                            severity = "CRITICAL" if protocol == "-1" or covers_admin else "HIGH"
                            findings.append(_finding("aws", f"{region_name}/{group.get('GroupId', '')}",
                                                     "Security group allows inbound traffic from the internet", severity, "Network",
                                                     "An inbound security-group rule accepts traffic from a public IPv4 or IPv6 range.",
                                                     "Restrict ingress to approved source ranges and only required ports.",
                                                     f"{ports} from {', '.join(public_ranges)}"))
            for page in ec2.get_paginator("describe_instances").paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        resources_scanned += 1
                        if instance.get("PublicIpAddress"):
                            findings.append(_finding("aws", f"{region_name}/{instance.get('InstanceId', '')}",
                                                     "Compute instance has a public IP address", "LOW", "Network",
                                                     "A running EC2 instance is directly addressable through a public IP.",
                                                     "Confirm public exposure is required; prefer a private subnet and managed ingress.",
                                                     instance["PublicIpAddress"]))
        except Exception as exc:
            if _aws_access_denied(exc):
                warnings.append(f"EC2 network inventory is incomplete in {region_name}; grant ec2:DescribeSecurityGroups and ec2:DescribeInstances.")
            else:
                logger.warning("AWS EC2 inventory failed in %s: %s", region_name, exc)
                warnings.append(f"EC2 network inventory failed in {region_name}.")
    return {"account": account, "findings": findings, "resources_scanned": resources_scanned, "warnings": warnings, "coverage": coverage}


def scan_azure() -> dict[str, Any]:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.resource import SubscriptionClient
        from azure.mgmt.resource.resources import ResourceManagementClient
        from azure.mgmt.storage import StorageManagementClient
    except ImportError as exc:
        raise RuntimeError("Azure scans require azure-identity and azure-mgmt-resource, azure-mgmt-storage, azure-mgmt-authorization, and azure-mgmt-network. Install the backend requirements and retry.") from exc

    credential = DefaultAzureCredential()
    subscriptions = list(SubscriptionClient(credential).subscriptions.list())
    if not subscriptions:
        credential.close()
        raise RuntimeError("No Azure subscriptions were returned. Configure Azure credentials and grant access to at least one subscription.")
    findings: list[dict[str, str]] = []
    warnings: list[str] = []
    resources_scanned = 0
    subscription_names = [sub.display_name or sub.subscription_id for sub in subscriptions]
    for subscription in subscriptions:
        sub_id = subscription.subscription_id
        resource_client = ResourceManagementClient(credential, sub_id)
        try:
            storage_accounts = list(itertools.islice(resource_client.resources.list(
                filter="resourceType eq 'Microsoft.Storage/storageAccounts'",
                expand="createdTime,changedTime",
                top=501,
            ), 501))
        except Exception as exc:
            logger.warning("Azure storage resource inventory failed for %s: %s", sub_id, exc)
            warnings.append(f"Could not list storage accounts in Azure subscription {sub_id}; grant Reader access.")
            storage_accounts = []
        resources_scanned += len(storage_accounts)
        storage_client = StorageManagementClient(credential, sub_id)
        for account in storage_accounts[:500]:
            properties = account.properties or {}
            resource_id = account.id or account.name or "storage account"
            if str(_azure_value(properties, "public_network_access", "publicNetworkAccess") or "").lower() == "enabled":
                findings.append(_finding("azure", resource_id, "Storage account accepts public network access", "MEDIUM", "Storage",
                                         "The storage account's public network access setting is enabled.",
                                         "Disable public network access where possible or restrict the storage firewall to approved virtual networks and IP ranges."))
            if _azure_value(properties, "allow_blob_public_access", "allowBlobPublicAccess") is True:
                findings.append(_finding("azure", resource_id, "Anonymous blob access is allowed", "HIGH", "Storage",
                                         "The storage account permits anonymous public access at the account level.",
                                         "Disable blob public access unless explicitly required and approved."))
            network_rules = _azure_value(properties, "network_rule_set", "networkAcls")
            if network_rules and str(_azure_value(network_rules, "default_action", "defaultAction") or "").lower() == "allow":
                findings.append(_finding("azure", resource_id, "Storage firewall defaults to allow", "HIGH", "Storage",
                                         "The storage network rules allow access by default.",
                                         "Set the network default action to Deny and explicitly allow trusted networks."))
            parts = resource_id.split("/")
            try:
                resource_group = parts[parts.index("resourceGroups") + 1]
                containers = storage_client.blob_containers.list(resource_group, account.name)
                for container in containers:
                    resources_scanned += 1
                    access = str(getattr(container, "public_access", "") or "").lower()
                    if access in {"blob", "container"}:
                        findings.append(_finding("azure", f"{resource_id}/blobServices/default/containers/{container.name}",
                                                 "Blob container allows anonymous public access", "CRITICAL" if access == "container" else "HIGH",
                                                 "Storage", "The blob container is configured for anonymous public access.",
                                                 "Set the container public access level to Private and use authorized identities for access.",
                                                 f"Public access level: {access}"))
            except Exception as exc:
                logger.warning("Azure blob-container check failed for %s: %s", resource_id, exc)
                warnings.append(f"Could not inspect blob containers for storage account {account.name}; grant storage account data-plane read access.")
        if len(storage_accounts) > 500:
            warnings.append(f"Only the first 500 storage accounts were inspected in Azure subscription {sub_id}.")

        try:
            authorization = AuthorizationManagementClient(credential, sub_id)
            assignments = authorization.role_assignments.list_for_subscription()
            for assignment in assignments:
                resources_scanned += 1
                role_id = (assignment.role_definition_id or "").lower().rstrip("/").split("/")[-1]
                role_names = {
                    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
                    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
                    "18d7d372-fdd7-4c37-94b4-892bc61f8225": "User Access Administrator",
                }
                if role_id in role_names:
                    findings.append(_finding("azure", f"{sub_id}/{assignment.principal_id or 'principal'}",
                                             f"Broad Azure role assignment: {role_names[role_id]}", "HIGH", "Identity",
                                             "A principal has a broad built-in role assigned at subscription scope.",
                                             "Review the principal's need for subscription-wide access and use a narrower role or scope.",
                                             f"Role: {role_names[role_id]}; principal type: {assignment.principal_type or 'unknown'}"))
        except Exception as exc:
            logger.warning("Azure role assignment inventory failed for %s: %s", sub_id, exc)
            warnings.append(f"Could not inspect Azure role assignments in subscription {sub_id}; grant Microsoft.Authorization/roleAssignments/read.")

        try:
            network = NetworkManagementClient(credential, sub_id)
            for nsg in network.network_security_groups.list_all():
                resources_scanned += 1
                for rule in getattr(nsg, "security_rules", []) or []:
                    if str(getattr(rule, "direction", "")).lower() != "inbound" or str(getattr(rule, "access", "")).lower() != "allow":
                        continue
                    sources = [getattr(rule, "source_address_prefix", "")] + list(getattr(rule, "source_address_prefixes", []) or [])
                    public_sources = [source for source in sources if source in {"*", "Internet", "0.0.0.0/0", "::/0"}]
                    if public_sources:
                        ports = str(getattr(rule, "destination_port_range", "") or ",".join(getattr(rule, "destination_port_ranges", []) or []))
                        severity = "CRITICAL" if _port_spec_covers_admin(ports) or "*" in (getattr(rule, "protocol", "") or "") else "HIGH"
                        findings.append(_finding("azure", f"{nsg.id}/{rule.name}",
                                                 "Network security group exposes an inbound rule to the internet", severity, "Network",
                                                 "An inbound allow rule accepts traffic from an internet-wide source.",
                                                 "Limit the source to approved networks and restrict destination ports and protocols.",
                                                 f"Source: {', '.join(public_sources)}; destination ports: {ports or 'not specified'}"))
        except Exception as exc:
            logger.warning("Azure network inventory failed for %s: %s", sub_id, exc)
            warnings.append(f"Could not inspect network security groups in subscription {sub_id}; grant Reader access.")
    credential.close()
    return {"account": ", ".join(subscription_names[:5]), "findings": findings, "resources_scanned": resources_scanned, "warnings": warnings,
            "coverage": ["Subscription storage accounts and blob containers, subscription-scope broad role assignments, and network security group inbound rules."]}


def scan_gcp() -> dict[str, Any]:
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
        from google.cloud import storage
    except ImportError as exc:
        raise RuntimeError("Google Cloud scans require google-auth and google-cloud-storage. Install the backend requirements and retry.") from exc

    credentials, default_project = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"])
    session = AuthorizedSession(credentials)
    project_warnings: list[str] = []
    projects: list[dict[str, Any]] = []
    project_params: dict[str, Any] = {"pageSize": 100}
    next_project_page = ""
    while len(projects) < 100:
        project_response = session.get("https://cloudresourcemanager.googleapis.com/v3/projects", params=project_params, timeout=20)
        if project_response.status_code == 403 and default_project and not projects:
            projects = [{"projectId": default_project, "name": default_project}]
            project_warnings.append(f"Project discovery is restricted; scanning only the ADC default project {default_project}.")
            break
        project_response.raise_for_status()
        project_payload = project_response.json()
        projects.extend(project_payload.get("projects", []))
        next_project_page = project_payload.get("nextPageToken", "")
        if not next_project_page:
            break
        project_params["pageToken"] = next_project_page
    if next_project_page and len(projects) >= 100:
        project_warnings.append("Only the first 100 discovered Google Cloud projects were inspected.")
    if default_project and all(item.get("projectId") != default_project for item in projects):
        projects.append({"projectId": default_project, "name": default_project})
    if not projects:
        raise RuntimeError("No Google Cloud projects were discovered. Configure ADC and grant project inventory access, or set a default project.")
    findings: list[dict[str, str]] = []
    warnings = project_warnings
    resources_scanned = 0
    storage_client = storage.Client(project=default_project, credentials=credentials)
    project_names: list[str] = []
    for project in projects[:100]:
        project_id = project.get("projectId") or project.get("name", "").split("/")[-1]
        if not project_id:
            continue
        project_names.append(project.get("name", project_id))
        try:
            buckets = list(itertools.islice(storage_client.list_buckets(project=project_id, max_results=501), 501))
        except Exception as exc:
            logger.warning("GCP bucket inventory failed for %s: %s", project_id, exc)
            warnings.append(f"Could not list Cloud Storage buckets in project {project_id}; grant storage.buckets.list.")
            buckets = []
        if len(buckets) > 500:
            warnings.append(f"Only the first 500 Cloud Storage buckets were inspected in project {project_id}.")
        for bucket in buckets:
            resources_scanned += 1
            bucket_name = bucket.name
            try:
                bucket.reload()
                public_access_prevention = bucket.iam_configuration.public_access_prevention
                if public_access_prevention != "enforced":
                    iam_policy = bucket.get_iam_policy(requested_policy_version=3)
                    public_members = [
                        f"{binding.get('role', 'unknown')}:{member}"
                        for binding in iam_policy.bindings
                        for member in binding.get("members", [])
                        if member in {"allUsers", "allAuthenticatedUsers"}
                    ]
                    if public_members:
                        findings.append(_finding("gcp", bucket_name, "Cloud Storage bucket IAM grants public access", "CRITICAL", "Storage",
                                                 "The bucket IAM policy contains allUsers or allAuthenticatedUsers.",
                                                 "Remove public principals and grant access through least-privilege identities.",
                                                 "; ".join(public_members)))
                if public_access_prevention != "enforced":
                    findings.append(_finding("gcp", bucket_name, "Public access prevention is not enforced", "MEDIUM", "Storage",
                                             "Public access prevention is not enforced for this bucket.",
                                             "Enforce public access prevention at the organization, folder, project, or bucket level."))
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    bucket.acl.reload()
                    public_acl = [
                        entry for entry in bucket.acl.get_entities()
                        if getattr(entry, "entity", "") in {"allUsers", "allAuthenticatedUsers"}
                    ]
                    if public_acl:
                        findings.append(_finding("gcp", bucket_name, "Cloud Storage ACL grants public access", "CRITICAL", "Storage",
                                                 "A legacy bucket ACL grants access to all users or all authenticated users.",
                                                 "Remove public ACL entries and enable uniform bucket-level access.",
                                                 ", ".join(f"{entry.entity}:{entry.role}" for entry in public_acl)))
                if not getattr(bucket, "default_kms_key_name", None):
                    findings.append(_finding("gcp", bucket_name, "Cloud Storage is not configured with a customer-managed key", "LOW", "Storage",
                                             "No default customer-managed encryption key is configured. Google-managed encryption may still be enabled.",
                                             "Review data classification and configure customer-managed keys where required by policy."))
                if not getattr(bucket, "logging", None):
                    findings.append(_finding("gcp", bucket_name, "Cloud Storage access logging is not configured", "LOW", "Logging",
                                             "No access-log destination is configured on the bucket.",
                                             "Enable Cloud Storage access logging using a protected destination bucket and retention policy."))
            except Exception as exc:
                logger.warning("GCP bucket inspection failed for %s: %s", bucket_name, exc)
                warnings.append(f"Could not fully inspect Cloud Storage bucket {bucket_name}; grant storage.buckets.get and storage.buckets.getIamPolicy.")
        try:
            policy_response = session.post(
                f"https://cloudresourcemanager.googleapis.com/v3/projects/{project_id}:getIamPolicy",
                json={"options": {"requestedPolicyVersion": 3}},
                timeout=20,
            )
            policy_response.raise_for_status()
            policy = policy_response.json()
            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                if role not in {"roles/owner", "roles/editor", "roles/iam.serviceAccountTokenCreator"}:
                    continue
                for member in binding.get("members", []):
                    if member == "allUsers" or member == "allAuthenticatedUsers":
                        findings.append(_finding("gcp", project_id, f"Project IAM grants {role} to a public principal", "CRITICAL", "Identity",
                                                 "A publicly addressable principal has a broad project role.",
                                                 "Remove public principals and assign project roles to approved identities only.",
                                                 f"{role}: {member}"))
                    else:
                        role_severity = "HIGH" if role in {"roles/owner", "roles/iam.serviceAccountTokenCreator"} else "MEDIUM"
                        findings.append(_finding("gcp", f"{project_id}/{member}",
                                                 f"Broad project IAM role: {role}", role_severity, "Identity",
                                                 "A project member has broad project-wide administrative or service-account impersonation privileges.",
                                                 "Replace broad project-level permissions with task-specific, least-privilege roles and scope service-account impersonation narrowly.",
                                                 f"{role}: {member}"))
        except Exception as exc:
            logger.warning("GCP project IAM inspection failed for %s: %s", project_id, exc)
            warnings.append(f"Could not inspect project IAM policy for {project_id}; grant resourcemanager.projects.getIamPolicy.")
        try:
            compute_params: dict[str, Any] = {"maxResults": 500}
            next_compute_page = ""
            for _ in range(5):
                compute_response = session.get(
                    f"https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances",
                    params=compute_params,
                    timeout=20,
                )
                compute_response.raise_for_status()
                compute_payload = compute_response.json()
                for zone in compute_payload.get("items", {}).values():
                    for instance in zone.get("instances", []):
                        resources_scanned += 1
                        public_ips = [
                            access.get("natIP")
                            for interface in instance.get("networkInterfaces", [])
                            for access in interface.get("accessConfigs", [])
                            if access.get("natIP")
                        ]
                        if public_ips:
                            findings.append(_finding("gcp", instance.get("selfLink", instance.get("name", project_id)),
                                                     "Compute Engine instance has an external IP", "LOW", "Network",
                                                     "A virtual machine has an externally routable IP address.",
                                                     "Confirm public access is needed and use private networking and controlled ingress where possible.",
                                                     ", ".join(public_ips)))
                next_compute_page = compute_payload.get("nextPageToken", "")
                if not next_compute_page:
                    break
                compute_params["pageToken"] = next_compute_page
            if next_compute_page:
                warnings.append(f"Compute Engine instance inventory reached its 2,500-item scan limit in project {project_id}.")
        except Exception as exc:
            logger.warning("GCP compute inventory failed for %s: %s", project_id, exc)
            warnings.append(f"Could not inspect Compute Engine instances in {project_id}; grant compute.instances.list.")
    if len(projects) > 100:
        warnings.append("Only the first 100 discovered Google Cloud projects were inspected.")
    return {"account": ", ".join(project_names[:5]), "findings": findings, "resources_scanned": resources_scanned, "warnings": warnings,
            "coverage": ["Project IAM bindings, Cloud Storage bucket public access/encryption/logging settings, and Compute Engine external IPs."]}
