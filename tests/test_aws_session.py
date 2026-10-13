"""Tests verifying AWS authentication validation, error handling, and strict absence of silent mock fallbacks."""

import pytest
from unittest.mock import patch, MagicMock
from botocore.exceptions import NoCredentialsError, ClientError

from src.config import Settings, ScanMode
from src.discovery.aws_session import AWSSessionManager, execute_with_backoff


def test_aws_mode_never_falls_back_to_mock_on_missing_credentials():
    """
    CRITICAL SECURITY & RELIABILITY TEST:
    Verify that in real AWS mode, missing credentials raises an explicit RuntimeError
    and NEVER silently substitutes synthetic or mock data.
    """
    settings = Settings(discovery_mode=ScanMode.AWS, aws_profile=None)
    manager = AWSSessionManager(settings)

    with patch("boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.client.return_value = mock_sts
        mock_session_cls.return_value = mock_session

        with pytest.raises(RuntimeError) as exc_info:
            manager.validate_credentials()

        assert "No AWS credentials discovered" in str(exc_info.value)
        assert "Fallback to mock is strictly disabled" in str(exc_info.value)


def test_aws_mode_raises_on_access_denied():
    """Verify that ClientError (AccessDenied) raises a descriptive exception."""
    settings = Settings(discovery_mode=ScanMode.AWS)
    manager = AWSSessionManager(settings)

    with patch("boto3.Session") as mock_session_cls:
        mock_session = MagicMock()
        mock_sts = MagicMock()
        err_response = {"Error": {"Code": "AccessDenied", "Message": "User is not authorized to perform sts:GetCallerIdentity"}}
        mock_sts.get_caller_identity.side_effect = ClientError(err_response, "GetCallerIdentity")
        mock_session.client.return_value = mock_sts
        mock_session_cls.return_value = mock_session

        with pytest.raises(RuntimeError) as exc_info:
            manager.validate_credentials()

        assert "AWS authentication failed (AccessDenied)" in str(exc_info.value)


def test_region_discovery_honors_denylist():
    """Verify that region discovery strictly excludes regions on the denylist."""
    settings = Settings(
        scan_regions="us-east-1,us-west-2,ap-south-1",
        scan_denylist_regions="us-west-2"
    )
    manager = AWSSessionManager(settings)
    target_regions = manager.discover_regions()

    assert "us-east-1" in target_regions
    assert "ap-south-1" in target_regions
    assert "us-west-2" not in target_regions


def test_execute_with_backoff_retries_throttling():
    """Verify that retryable throttling triggers retries and succeeds if throttling resolves."""
    call_count = 0

    def throttled_operation():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise ClientError({"Error": {"Code": "Throttling", "Message": "Rate exceeded"}}, "TestOp")
        return {"Status": "SUCCESS"}

    result = execute_with_backoff(throttled_operation, max_retries=2, initial_delay=0.01)
    assert result == {"Status": "SUCCESS"}
    assert call_count == 2
