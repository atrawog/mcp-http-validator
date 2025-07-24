"""Tests for MCP HTTP Validator models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from mcp_http_validator.models import (
    ComplianceReport,
    MCPServerInfo,
    OAuthServerMetadata,
    ProtectedResourceMetadata,
    TestCase,
    TestResult,
    TestSeverity,
    TestStatus,
    ValidationResult,
)


def test_test_case_creation():
    """Test TestCase model creation."""
    test_case = TestCase(
        id="test-1",
        name="Test Case 1",
        description="A test case",
        category="oauth",
        severity=TestSeverity.HIGH,
        required=True,
    )
    
    assert test_case.id == "test-1"
    assert test_case.name == "Test Case 1"
    assert test_case.severity == TestSeverity.HIGH
    assert test_case.required is True


def test_test_result_creation():
    """Test TestResult model creation."""
    test_case = TestCase(
        id="test-1",
        name="Test Case 1",
        description="A test case",
        category="oauth",
    )
    
    result = TestResult(
        test_case=test_case,
        status=TestStatus.PASSED,
        duration_ms=123.45,
        error_message=None,
    )
    
    assert result.status == TestStatus.PASSED
    assert result.duration_ms == 123.45
    assert result.error_message is None
    assert isinstance(result.timestamp, datetime)


def test_validation_result_calculations():
    """Test ValidationResult calculations."""
    test_cases = [
        TestCase(id=f"test-{i}", name=f"Test {i}", description="Test", category="test")
        for i in range(5)
    ]
    
    test_results = [
        TestResult(
            test_case=test_cases[0],
            status=TestStatus.PASSED,
            duration_ms=100,
        ),
        TestResult(
            test_case=test_cases[1],
            status=TestStatus.PASSED,
            duration_ms=200,
        ),
        TestResult(
            test_case=test_cases[2],
            status=TestStatus.FAILED,
            duration_ms=150,
            error_message="Test failed",
        ),
        TestResult(
            test_case=test_cases[3],
            status=TestStatus.SKIPPED,
            duration_ms=0,
        ),
        TestResult(
            test_case=test_cases[4],
            status=TestStatus.ERROR,
            duration_ms=50,
            error_message="Test error",
        ),
    ]
    
    result = ValidationResult(
        server_url="https://mcp.example.com",
        started_at=datetime.now(),
        completed_at=datetime.now(),
        total_tests=5,
        passed_tests=2,
        failed_tests=1,
        skipped_tests=1,
        error_tests=1,
        test_results=test_results,
    )
    
    assert result.total_tests == 5
    assert result.passed_tests == 2
    assert result.failed_tests == 1
    assert result.success_rate == 40.0  # 2/5 * 100
    assert result.is_compliant is True  # All required tests that ran passed


def test_oauth_server_metadata():
    """Test OAuthServerMetadata model."""
    metadata = OAuthServerMetadata(
        issuer="https://auth.example.com",
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        jwks_uri="https://auth.example.com/jwks",
        response_types_supported=["code"],
        resource_indicators_supported=True,
        scopes_supported=["mcp:read", "mcp:write"],
    )
    
    assert metadata.issuer == "https://auth.example.com"
    assert metadata.resource_indicators_supported is True
    assert "mcp:read" in metadata.scopes_supported


def test_protected_resource_metadata():
    """Test ProtectedResourceMetadata model."""
    metadata = ProtectedResourceMetadata(
        resource="https://mcp.example.com",
        authorization_servers=["https://auth.example.com"],
        scopes_supported=["mcp:read", "mcp:write"],
        bearer_methods_supported=["header"],
    )
    
    assert str(metadata.resource) == "https://mcp.example.com/"
    assert len(metadata.authorization_servers) == 1
    assert "header" in metadata.bearer_methods_supported


def test_compliance_report_markdown():
    """Test ComplianceReport markdown generation."""
    server_info = MCPServerInfo(
        url="https://mcp.example.com",
        name="Test MCP Server",
        requires_auth=True,
    )
    
    test_case = TestCase(
        id="test-1",
        name="Critical Test",
        description="A critical test",
        category="oauth",
        severity=TestSeverity.CRITICAL,
    )
    
    failed_result = TestResult(
        test_case=test_case,
        status=TestStatus.FAILED,
        duration_ms=100,
        error_message="Authentication failed",
    )
    
    validation_result = ValidationResult(
        server_url="https://mcp.example.com",
        started_at=datetime.now(),
        completed_at=datetime.now(),
        total_tests=1,
        passed_tests=0,
        failed_tests=1,
        skipped_tests=0,
        error_tests=0,
        test_results=[failed_result],
    )
    
    report = ComplianceReport(
        server_info=server_info,
        validation_result=validation_result,
        compliance_level="NON_COMPLIANT",
        critical_failures=[failed_result],
        recommendations=["Fix authentication", "Implement OAuth"],
    )
    
    markdown = report.to_markdown()
    
    assert "# MCP Compliance Report" in markdown
    assert "https://mcp.example.com" in markdown
    assert "NON_COMPLIANT" in markdown
    assert "Critical Test" in markdown
    assert "Authentication failed" in markdown
    assert "Fix authentication" in markdown


def test_model_validation_errors():
    """Test that models validate input correctly."""
    # Missing required field
    with pytest.raises(ValidationError):
        TestCase(
            id="test-1",
            # name is missing
            description="Test",
            category="test",
        )
    
    # Invalid URL
    with pytest.raises(ValidationError):
        MCPServerInfo(
            url="not-a-url",
        )
    
    # Invalid enum value
    with pytest.raises(ValidationError):
        TestResult(
            test_case=TestCase(
                id="test-1",
                name="Test",
                description="Test",
                category="test",
            ),
            status="invalid-status",  # Not a valid TestStatus
            duration_ms=100,
        )