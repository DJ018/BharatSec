"""Cloud API tests use an isolated database and mocked read-only provider scans."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from engines import cloud_engine
from tests.auth_helpers import authenticated_client


class CloudApiTests(unittest.TestCase):
    def test_provider_directory_documents_credential_chains_without_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(cloud_engine, "DB_PATH", Path(folder) / "cloud.db"):
                with authenticated_client() as client:
                    response = client.get("/api/cloud/providers")
        self.assertEqual(response.status_code, 200)
        providers = response.json()
        self.assertEqual([provider["id"] for provider in providers], ["aws", "azure", "gcp"])
        self.assertTrue(all(provider["credential_chain"] and provider["setup"] for provider in providers))
        self.assertTrue(all("credentials" not in provider and "secret" not in provider for provider in providers))

    def test_scan_requires_authorization_and_persists_provider_results(self):
        result = {
            "account": "test-account",
            "resources_scanned": 2,
            "warnings": [],
            "coverage": ["storage and identity"],
            "findings": [{
                "id": "aws-public-bucket",
                "provider": "aws",
                "resource": "example-public",
                "title": "Bucket is public",
                "severity": "CRITICAL",
                "category": "Storage",
                "description": "Public object access is permitted.",
                "recommendation": "Remove public access.",
                "evidence": "IsPublic=true",
            }],
        }
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(cloud_engine, "DB_PATH", Path(folder) / "cloud.db"), \
                 patch.object(cloud_engine, "scan_aws", return_value=result):
                with authenticated_client() as client:
                    rejected = client.post("/api/cloud/scans", json={"provider": "aws"})
                    self.assertEqual(rejected.status_code, 400)

                    started = client.post("/api/cloud/scans", json={"provider": "aws", "authorized": True})
                    self.assertEqual(started.status_code, 202)
                    scan_id = started.json()["scan_id"]
                    ran = client.post(f"/api/cloud/scans/{scan_id}/run")
                    self.assertEqual(ran.json()["status"], "complete")
                    # A second /run never executes the scan again.
                    with patch.object(cloud_engine, "run_scan") as rerun:
                        client.post(f"/api/cloud/scans/{scan_id}/run")
                    rerun.assert_not_called()
                    scan = client.get(f"/api/cloud/scans/{scan_id}")
                    self.assertEqual(scan.status_code, 200)
                    self.assertEqual(scan.json()["status"], "complete")
                    self.assertEqual(scan.json()["account"], "test-account")
                    self.assertEqual(scan.json()["findings"][0]["severity"], "CRITICAL")
                    self.assertEqual(scan.json()["findings"][0]["evidence"], "IsPublic=true")
                    history = client.get("/api/cloud/scans").json()
                    self.assertEqual(history[0]["scan_id"], scan_id)
                    self.assertEqual(history[0]["finding_count"], 1)
                    self.assertNotIn("findings", history[0])

    def test_unknown_provider_and_scan_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(cloud_engine, "DB_PATH", Path(folder) / "cloud.db"):
                with authenticated_client() as client:
                    invalid = client.post("/api/cloud/scans", json={"provider": "digital-ocean", "authorized": True})
                    missing = client.get("/api/cloud/scans/not-a-scan")
        self.assertEqual(invalid.status_code, 422)
        self.assertEqual(missing.status_code, 404)

    def test_aws_scan_flags_public_storage_and_administrator_access(self):
        class FakePaginator:
            def paginate(self, **kwargs):
                return [{
                    "UserDetailList": [{
                        "UserName": "deployment-user",
                        "Arn": "arn:aws:iam::123456789012:user/deployment-user",
                        "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess"}],
                    }],
                    "RoleDetailList": [],
                    "Policies": [],
                }]

        class FakeClient:
            def __init__(self, name):
                self.name = name

            def get_caller_identity(self):
                return {"Account": "123456789012"}

            def list_buckets(self):
                return {"Buckets": [{"Name": "customer-data"}]}

            def get_public_access_block(self, **kwargs):
                return {"PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }}

            def get_bucket_policy_status(self, **kwargs):
                return {"PolicyStatus": {"IsPublic": True}}

            def get_bucket_acl(self, **kwargs):
                return {"Grants": [{
                    "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }]}

            def get_bucket_encryption(self, **kwargs):
                return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}

            def get_bucket_logging(self, **kwargs):
                return {"LoggingEnabled": {"TargetBucket": "security-logs"}}

            def get_paginator(self, operation):
                self.asserted_operation = operation
                return FakePaginator()

            def list_access_keys(self, **kwargs):
                return {"AccessKeyMetadata": []}

            def describe_regions(self, **kwargs):
                return {"Regions": []}

        class FakeSession:
            def get_credentials(self):
                return object()

            def client(self, name, **kwargs):
                return FakeClient(name)

        with patch("boto3.Session", return_value=FakeSession()):
            result = cloud_engine.scan_aws()

        titles = {finding["title"] for finding in result["findings"]}
        self.assertEqual(result["account"], "123456789012")
        self.assertIn("S3 bucket policy permits public access", titles)
        self.assertIn("S3 bucket ACL grants public access", titles)
        self.assertIn("IAM user has AdministratorAccess", titles)
        self.assertGreaterEqual(result["resources_scanned"], 2)

    def test_aws_scan_surfaces_missing_credentials(self):
        class FakeSession:
            def get_credentials(self):
                return None

        with patch("boto3.Session", return_value=FakeSession()):
            with self.assertRaisesRegex(RuntimeError, "AWS credentials were not found"):
                cloud_engine.scan_aws()

    def test_azure_scan_finds_public_storage_broad_roles_and_open_network_rules(self):
        subscription = SimpleNamespace(subscription_id="sub-123", display_name="Production")
        storage_account = SimpleNamespace(
            id="/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acmestorage",
            name="acmestorage",
            properties={"publicNetworkAccess": "Enabled", "allowBlobPublicAccess": True, "networkAcls": {"defaultAction": "Allow"}},
        )
        public_container = SimpleNamespace(name="public-data", public_access="container")
        owner_assignment = SimpleNamespace(
            role_definition_id="/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
            principal_id="principal-1",
            principal_type="User",
        )
        open_rule = SimpleNamespace(
            name="allow-all",
            direction="Inbound", access="Allow", source_address_prefix="Internet",
            source_address_prefixes=[], destination_port_range="*", destination_port_ranges=[],
            protocol="*",
        )
        nsg = SimpleNamespace(id="/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web", security_rules=[open_rule])

        class FakeCredential:
            def close(self):
                return None

        with patch("azure.identity.DefaultAzureCredential", return_value=FakeCredential()), \
             patch("azure.mgmt.resource.SubscriptionClient", return_value=SimpleNamespace(subscriptions=SimpleNamespace(list=lambda: [subscription]))), \
             patch("azure.mgmt.resource.resources.ResourceManagementClient", return_value=SimpleNamespace(resources=SimpleNamespace(list=lambda **kwargs: [storage_account]))), \
             patch("azure.mgmt.storage.StorageManagementClient", return_value=SimpleNamespace(blob_containers=SimpleNamespace(list=lambda *args: [public_container]))), \
             patch("azure.mgmt.authorization.AuthorizationManagementClient", return_value=SimpleNamespace(role_assignments=SimpleNamespace(list_for_subscription=lambda: [owner_assignment]))), \
             patch("azure.mgmt.network.NetworkManagementClient", return_value=SimpleNamespace(network_security_groups=SimpleNamespace(list_all=lambda: [nsg]))):
            result = cloud_engine.scan_azure()

        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Storage account accepts public network access", titles)
        self.assertIn("Anonymous blob access is allowed", titles)
        self.assertIn("Storage firewall defaults to allow", titles)
        self.assertIn("Blob container allows anonymous public access", titles)
        self.assertIn("Broad Azure role assignment: Owner", titles)
        self.assertIn("Network security group exposes an inbound rule to the internet", titles)
        self.assertEqual(result["account"], "Production")

    def test_gcp_scan_finds_public_storage_and_broad_iam(self):
        class FakeResponse:
            status_code = 200

            def __init__(self, payload):
                self.payload = payload

            def json(self):
                return self.payload

            def raise_for_status(self):
                return None

        class FakeSession:
            def get(self, url, **kwargs):
                if "cloudresourcemanager" in url:
                    return FakeResponse({"projects": [{"projectId": "project-123", "name": "Production"}]})
                return FakeResponse({"items": {}})

            def post(self, url, **kwargs):
                return FakeResponse({"bindings": [{"role": "roles/owner", "members": ["user:admin@example.com"]}]})

        class FakeBucket:
            name = "customer-data"
            default_kms_key_name = None
            logging = None

            def __init__(self):
                self.iam_configuration = SimpleNamespace(
                    public_access_prevention="inherited",
                    uniform_bucket_level_access_enabled=False,
                )
                self.acl = SimpleNamespace(
                    reload=lambda: None,
                    get_entities=lambda: [SimpleNamespace(entity="allUsers", role="READER")],
                )

            def reload(self):
                return None

            def get_iam_policy(self, **kwargs):
                return SimpleNamespace(bindings=[{"role": "roles/storage.objectViewer", "members": ["allUsers"]}])

        class FakeStorageClient:
            def __init__(self, **kwargs):
                return None

            def list_buckets(self, **kwargs):
                return [FakeBucket()]

        with patch("google.auth.default", return_value=(object(), "project-123")), \
             patch("google.auth.transport.requests.AuthorizedSession", return_value=FakeSession()), \
             patch("google.cloud.storage.Client", FakeStorageClient):
            result = cloud_engine.scan_gcp()

        titles = {finding["title"] for finding in result["findings"]}
        self.assertIn("Cloud Storage bucket IAM grants public access", titles)
        self.assertIn("Public access prevention is not enforced", titles)
        self.assertIn("Cloud Storage ACL grants public access", titles)
        self.assertIn("Cloud Storage is not configured with a customer-managed key", titles)
        self.assertIn("Cloud Storage access logging is not configured", titles)
        self.assertIn("Broad project IAM role: roles/owner", titles)
        self.assertEqual(result["account"], "Production")


if __name__ == "__main__":
    unittest.main()
