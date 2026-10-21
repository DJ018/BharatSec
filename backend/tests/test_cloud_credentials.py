"""Which AWS credentials the cloud scanner uses, especially on serverless hosts that run on AWS themselves."""
import os
import unittest
from unittest.mock import MagicMock, patch

import boto3

from engines import cloud_engine


class AwsCredentialSourceTests(unittest.TestCase):
    def test_serverless_without_bharatsec_keys_refuses_instead_of_using_platform_credentials(self):
        env = {"AWS_ACCESS_KEY_ID": "PLATFORM", "AWS_SECRET_ACCESS_KEY": "platform-secret"}
        with patch.dict(os.environ, env, clear=False), \
             patch.dict(os.environ, {"BHARATSEC_AWS_ACCESS_KEY_ID": "", "BHARATSEC_AWS_SECRET_ACCESS_KEY": ""}), \
             patch.object(cloud_engine, "IS_SERVERLESS", True), \
             patch.object(boto3, "Session") as session:
            with self.assertRaises(RuntimeError) as raised:
                cloud_engine.scan_aws()
        session.assert_not_called()
        self.assertIn("BHARATSEC_AWS_ACCESS_KEY_ID", str(raised.exception))

    def test_bharatsec_keys_are_used_explicitly_with_a_default_region(self):
        env = {"BHARATSEC_AWS_ACCESS_KEY_ID": "AKIATEST", "BHARATSEC_AWS_SECRET_ACCESS_KEY": "secret", "BHARATSEC_AWS_REGION": ""}
        fake = MagicMock()
        fake.get_credentials.return_value = None  # stop right after the session is built
        with patch.dict(os.environ, env), patch.object(cloud_engine, "IS_SERVERLESS", True), \
             patch.object(boto3, "Session", return_value=fake) as session:
            with self.assertRaises(RuntimeError):
                cloud_engine.scan_aws()
        session.assert_called_once_with(
            aws_access_key_id="AKIATEST", aws_secret_access_key="secret", region_name="ap-south-1"
        )


if __name__ == "__main__":
    unittest.main()
