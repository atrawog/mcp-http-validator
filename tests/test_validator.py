"""Tests for MCP HTTP Validator core functionality."""

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from mcp_http_validator.models import TestStatus
from mcp_http_validator.validator import MCPValidator


@pytest.mark.asyncio
async def test_validator_initialization():
    """Test MCPValidator initialization."""
    validator = MCPValidator(
        server_url="https://mcp.example.com",
        access_token="test-token",
        timeout=60.0,
        verify_ssl=False,
    )
    
    assert validator.server_url == "https://mcp.example.com"
    assert validator.access_token == "test-token"
    assert validator.timeout == 60.0
    assert validator.verify_ssl is False
    
    await validator.close()


@pytest.mark.asyncio
async def test_validator_headers():
    """Test header generation."""
    validator = MCPValidator(
        server_url="https://mcp.example.com",
        access_token="test-token",
    )
    
    headers = validator._get_headers()
    assert headers["Authorization"] == "Bearer test-token"
    assert headers["MCP-Protocol-Version"] == "2025-06-18"
    assert headers["Accept"] == "application/json"
    
    # Test with additional headers
    headers = validator._get_headers({"X-Custom": "value"})
    assert headers["X-Custom"] == "value"
    
    await validator.close()


@pytest.mark.asyncio
async def test_protected_resource_metadata_success(monkeypatch):
    """Test successful protected resource metadata retrieval."""
    validator = MCPValidator("https://mcp.example.com")
    
    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "resource": "https://mcp.example.com",
        "authorization_servers": ["https://auth.example.com"],
        "scopes_supported": ["mcp:read", "mcp:write"],
    }
    
    # Mock the client.get method
    async def mock_get(url, **kwargs):
        return mock_response
    
    monkeypatch.setattr(validator.client, "get", mock_get)
    
    passed, error, details = await validator.test_protected_resource_metadata()
    
    assert passed is True
    assert error is None
    assert details["resource"] == "https://mcp.example.com"
    assert "https://auth.example.com" in details["authorization_servers"]
    
    await validator.close()


@pytest.mark.asyncio
async def test_protected_resource_metadata_not_found(monkeypatch):
    """Test 404 response for protected resource metadata."""
    validator = MCPValidator("https://mcp.example.com")
    
    # Mock 404 response
    mock_response = MagicMock()
    mock_response.status_code = 404
    
    async def mock_get(url, **kwargs):
        return mock_response
    
    monkeypatch.setattr(validator.client, "get", mock_get)
    
    passed, error, details = await validator.test_protected_resource_metadata()
    
    assert passed is False
    assert "not found" in error.lower()
    assert details["status_code"] == 404
    
    await validator.close()


@pytest.mark.asyncio
async def test_unauthenticated_request_proper_401(monkeypatch):
    """Test proper 401 response with WWW-Authenticate header."""
    validator = MCPValidator("https://mcp.example.com")
    
    # Mock 401 response with proper header
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.headers = {
        "WWW-Authenticate": 'Bearer realm="MCP", as_uri="https://auth.example.com/.well-known/oauth-authorization-server", resource_uri="https://mcp.example.com/.well-known/oauth-protected-resource"'
    }
    
    async def mock_get(url, **kwargs):
        return mock_response
    
    monkeypatch.setattr(validator.client, "get", mock_get)
    
    passed, error, details = await validator.test_unauthenticated_request()
    
    assert passed is True
    assert error is None
    assert "realm" in details["found_params"]
    assert "as_uri" in details["found_params"]
    assert "resource_uri" in details["found_params"]
    
    await validator.close()


@pytest.mark.asyncio
async def test_unauthenticated_request_missing_header(monkeypatch):
    """Test 401 response without WWW-Authenticate header."""
    validator = MCPValidator("https://mcp.example.com")
    
    # Mock 401 response without header
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.headers = {}
    
    async def mock_get(url, **kwargs):
        return mock_response
    
    monkeypatch.setattr(validator.client, "get", mock_get)
    
    passed, error, details = await validator.test_unauthenticated_request()
    
    assert passed is False
    assert "Missing WWW-Authenticate header" in error
    
    await validator.close()


@pytest.mark.asyncio
async def test_authenticated_request_success(monkeypatch):
    """Test successful authenticated request."""
    validator = MCPValidator("https://mcp.example.com", access_token="valid-token")
    
    # Mock successful response
    mock_response = MagicMock()
    mock_response.status_code = 200
    
    async def mock_get(url, **kwargs):
        # Verify auth header was sent
        assert kwargs["headers"]["Authorization"] == "Bearer valid-token"
        return mock_response
    
    monkeypatch.setattr(validator.client, "get", mock_get)
    
    passed, error, details = await validator.test_authenticated_request()
    
    assert passed is True
    assert error is None
    assert details["status_code"] == 200
    
    await validator.close()


@pytest.mark.asyncio
async def test_execute_test_success():
    """Test successful test execution."""
    from mcp_http_validator.models import TestCase, TestSeverity
    
    validator = MCPValidator("https://mcp.example.com")
    
    test_case = TestCase(
        id="test-1",
        name="Test 1",
        description="Test description",
        category="test",
        severity=TestSeverity.MEDIUM,
    )
    
    async def test_func():
        return True, None, {"detail": "success"}
    
    result = await validator._execute_test(test_case, test_func)
    
    assert result.test_case == test_case
    assert result.status == TestStatus.PASSED
    assert result.error_message is None
    assert result.details["detail"] == "success"
    assert result.duration_ms > 0
    
    await validator.close()


@pytest.mark.asyncio
async def test_execute_test_failure():
    """Test failed test execution."""
    from mcp_http_validator.models import TestCase, TestSeverity
    
    validator = MCPValidator("https://mcp.example.com")
    
    test_case = TestCase(
        id="test-1",
        name="Test 1",
        description="Test description",
        category="test",
        severity=TestSeverity.HIGH,
    )
    
    async def test_func():
        return False, "Test failed", {"reason": "invalid response"}
    
    result = await validator._execute_test(test_case, test_func)
    
    assert result.test_case == test_case
    assert result.status == TestStatus.FAILED
    assert result.error_message == "Test failed"
    assert result.details["reason"] == "invalid response"
    
    await validator.close()


@pytest.mark.asyncio
async def test_execute_test_exception():
    """Test test execution with exception."""
    from mcp_http_validator.models import TestCase, TestSeverity
    
    validator = MCPValidator("https://mcp.example.com")
    
    test_case = TestCase(
        id="test-1",
        name="Test 1",
        description="Test description",
        category="test",
        severity=TestSeverity.CRITICAL,
    )
    
    async def test_func():
        raise ValueError("Something went wrong")
    
    result = await validator._execute_test(test_case, test_func)
    
    assert result.test_case == test_case
    assert result.status == TestStatus.ERROR
    assert "Something went wrong" in result.error_message
    assert result.details["exception_type"] == "ValueError"
    
    await validator.close()