"""AWS session management, identity verification, regional enumeration, and resilient API execution."""

import time
import random
import logging
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

from src.config import Settings, setup_logging

logger = setup_logging()

RETRYABLE_ERROR_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestThrottled",
    "RequestThrottledException",
    "PriorRequestNotComplete",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "BandwidthLimitExceeded",
    "SlowDown",
    "InternalError",
    "ServiceUnavailable",
}


class AWSSessionManager:
    """Manages authenticated Boto3 sessions, STS identity validation, and safe region enumeration."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._session: Optional[boto3.Session] = None
        self._account_id: Optional[str] = None
        self._caller_arn: Optional[str] = None

    def get_session(self) -> boto3.Session:
        """Create or return an active Boto3 Session."""
        if self._session is None:
            kwargs = {}
            if self.settings.aws_access_key_id and self.settings.aws_secret_access_key:
                kwargs["aws_access_key_id"] = self.settings.aws_access_key_id
                kwargs["aws_secret_access_key"] = self.settings.aws_secret_access_key
                if self.settings.aws_session_token:
                    kwargs["aws_session_token"] = self.settings.aws_session_token
            elif self.settings.aws_profile:
                kwargs["profile_name"] = self.settings.aws_profile

            if self.settings.aws_default_region:
                kwargs["region_name"] = self.settings.aws_default_region

            base_session = boto3.Session(**kwargs)

            # If an explicit role ARN is provided, assume that role
            if self.settings.aws_role_arn:
                logger.info(f"Assuming authorized discovery role: {self.settings.aws_role_arn}")
                sts_client = base_session.client("sts")
                assumed = sts_client.assume_role(
                    RoleArn=self.settings.aws_role_arn,
                    RoleSessionName=self.settings.aws_role_session_name
                )
                creds = assumed["Credentials"]
                self._session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self.settings.aws_default_region
                )
            else:
                self._session = base_session

        return self._session

    def validate_credentials(self) -> Dict[str, str]:
        """
        Verify that active credentials exist and return caller identity.
        CRITICAL: Never fall back to mock data on failure.
        """
        session = self.get_session()
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            self._account_id = identity.get("Account")
            self._caller_arn = identity.get("Arn")
            logger.info(f"Verified AWS caller identity: Account={self._account_id}, Arn={self._caller_arn}")
            return {
                "account_id": self._account_id,
                "arn": self._caller_arn,
                "user_id": identity.get("UserId", "")
            }
        except NoCredentialsError as e:
            raise RuntimeError(
                "No AWS credentials discovered in the environment or specified profile. "
                "AWS mode cannot proceed without valid credentials. (Fallback to mock is strictly disabled in AWS mode)."
            ) from e
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            msg = e.response.get("Error", {}).get("Message", str(e))
            raise RuntimeError(f"AWS authentication failed ({code}): {msg}") from e

    def get_account_id(self) -> str:
        """Return the validated account ID."""
        if not self._account_id:
            self.validate_credentials()
        return self._account_id

    def discover_regions(self, requested_regions: Optional[List[str]] = None) -> List[str]:
        """
        Determine target regions.
        If requested_regions is provided and non-empty, validates and uses that list.
        Otherwise queries EC2 describe_regions for enabled regions in the account.
        """
        if requested_regions and len(requested_regions) > 0:
            denylist = set(self.settings.denylisted_regions)
            return [r for r in requested_regions if r not in denylist]

        configured_target = self.settings.target_regions
        if configured_target and len(configured_target) > 0:
            return configured_target

        session = self.get_session()
        try:
            ec2 = session.client("ec2", region_name=self.settings.aws_default_region)
            resp = ec2.describe_regions(AllRegions=False)
            discovered = [r["RegionName"] for r in resp.get("Regions", [])]
            denylist = set(self.settings.denylisted_regions)
            valid = [r for r in discovered if r not in denylist]
            logger.info(f"Discovered {len(valid)} enabled AWS regions in account {self._account_id}")
            return valid
        except Exception as e:
            logger.warning(f"Failed to query ec2.describe_regions ({e}). Falling back to default region.")
            return [self.settings.aws_default_region]


def execute_with_backoff(operation_fn, max_retries: int = 3, initial_delay: float = 0.5):
    """
    Execute a boto3 operation with exponential backoff on retryable throttling errors.
    Does NOT retry permanent permission errors (AccessDenied) indefinitely.
    """
    delay = initial_delay
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return operation_fn()
        except ClientError as e:
            last_exception = e
            code = e.response.get("Error", {}).get("Code", "")
            if code in RETRYABLE_ERROR_CODES and attempt < max_retries:
                jitter = random.uniform(0.1, 0.3)
                sleep_time = delay + jitter
                logger.warning(f"Throttled ({code}). Retrying in {sleep_time:.2f}s (attempt {attempt + 1}/{max_retries})...")
                time.sleep(sleep_time)
                delay *= 2
            else:
                raise e
        except (EndpointConnectionError, TimeoutError) as e:
            last_exception = e
            if attempt < max_retries:
                sleep_time = delay
                logger.warning(f"Connection error ({e}). Retrying in {sleep_time:.2f}s...")
                time.sleep(sleep_time)
                delay *= 2
            else:
                raise e

    raise last_exception
