"""Core MCP HTTP Validator implementation."""

from datetime import datetime
from typing import List, Optional

from pydantic import HttpUrl

from .base_validator import BaseMCPValidator
from .oauth_tests import OAuthTestValidator
from .protocol_tests import ProtocolTests
from .tool_tests import MCPToolTests
from .oauth_helpers import OAuthHelpers
from .models import (
    MCPServerInfo,
    TestCase,
    TestResult,
    TestSeverity,
    TestStatus,
    ValidationResult,
)


class MCPValidator(OAuthTestValidator, ProtocolTests, MCPToolTests, OAuthHelpers):
    """Main MCP validator that orchestrates all test modules."""
    
    def __init__(
        self,
        server_url: str,
        access_token: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        env_file: Optional[str] = None,
        auto_register: bool = True,
        progress_callback: Optional[callable] = None,
    ):
        """Initialize the MCP validator."""
        # Call the base class __init__ explicitly to avoid multiple inheritance issues
        BaseMCPValidator.__init__(
            self,
            server_url=server_url,
            access_token=access_token,
            timeout=timeout,
            verify_ssl=verify_ssl,
            env_file=env_file,
            auto_register=auto_register,
            progress_callback=progress_callback
        )
    
    async def validate(self) -> ValidationResult:
        """Run all validation tests and return results."""
        start_time = datetime.utcnow()
        
        # First, check if the server requires authentication
        auth_required = await self._check_auth_required()
        
        # Build test cases dynamically based on auth requirements
        test_cases = []
        
        # OAuth tests - only if authentication is required
        if auth_required:
            test_cases.extend([
                (
                    TestCase(
                        id="oauth-metadata",
                        name="OAuth Discovery Endpoint",
                        description="Server must expose /.well-known/oauth-protected-resource (RFC 9728)",
                        spec_reference="MCP Auth Spec Section 2.1",
                        severity=TestSeverity.CRITICAL,
                        required=True,
                        category="oauth",
                    ),
                    self.test_protected_resource_metadata,
                ),
                (
                    TestCase(
                        id="oauth-server-discovery",
                        name="OAuth Server Discovery",
                        description="Discover OAuth authorization server",
                        spec_reference="RFC 8414",
                        severity=TestSeverity.HIGH,
                        required=False,
                        category="oauth",
                    ),
                    self.test_oauth_server_discovery,
                ),
                (
                    TestCase(
                        id="oauth-server-mcp-compliance",
                        name="OAuth Server MCP Compliance",
                        description="Validate OAuth server supports MCP requirements",
                        spec_reference="MCP Auth Spec, RFC 8414",
                        severity=TestSeverity.HIGH,
                        required=False,
                        category="oauth",
                    ),
                    self.test_oauth_server_mcp_compliance,
                ),
                (
                    TestCase(
                        id="oauth-dynamic-registration",
                        name="OAuth Dynamic Client Registration",
                        description="Test dynamic client registration support (RFC 7591)",
                        spec_reference="RFC 7591",
                        severity=TestSeverity.MEDIUM,
                        required=False,
                        category="oauth",
                    ),
                    self.test_oauth_dynamic_registration,
                ),
                (
                    TestCase(
                        id="auth-challenge",
                        name="401 Authentication Response",
                        description="Server must return 401 with proper WWW-Authenticate header",
                        spec_reference="MCP Auth Spec Section 2.2",
                        severity=TestSeverity.CRITICAL,
                        required=True,
                        category="oauth",
                    ),
                    self.test_unauthenticated_request,
                ),
                (
                    TestCase(
                        id="auth-success",
                        name="Bearer Token Authentication", 
                        description="Server must accept valid bearer tokens",
                        spec_reference="MCP Auth Spec Section 2.3",
                        severity=TestSeverity.CRITICAL,
                        required=True,
                        category="oauth",
                    ),
                    self.test_authenticated_request,
                ),
                (
                    TestCase(
                        id="token-audience",
                        name="Token Audience Restrictions",
                        description="Server should validate token audience claims",
                        spec_reference="RFC 9728 Section 3",
                        severity=TestSeverity.HIGH,
                        required=False,
                        category="oauth",
                    ),
                    self.test_token_audience_validation,
                ),
                (
                    TestCase(
                        id="resource-token-consistency",
                        name="Resource-Token Consistency",
                        description="Verify resource metadata matches token audience",
                        spec_reference="RFC 9728 Section 2.2, RFC 8707",
                        severity=TestSeverity.HIGH,
                        required=False,
                        category="oauth",
                    ),
                    self.test_resource_token_consistency,
                ),
                (
                    TestCase(
                        id="token-refresh",
                        name="OAuth Token Refresh",
                        description="Test OAuth token refresh functionality",
                        spec_reference="RFC 6749 Section 6",
                        severity=TestSeverity.MEDIUM,
                        required=False,
                        category="oauth",
                    ),
                    self.test_token_refresh,
                ),
                (
                    TestCase(
                        id="token-validation",
                        name="Invalid Token Handling",
                        description="Server must properly reject invalid/malformed tokens",
                        spec_reference="RFC 6750",
                        severity=TestSeverity.HIGH,
                        required=True,
                        category="oauth",
                    ),
                    self.test_token_expiration_handling,
                ),
                (
                    TestCase(
                        id="token-introspection",
                        name="Token Introspection",
                        description="Test OAuth token introspection endpoint",
                        spec_reference="RFC 7662",
                        severity=TestSeverity.LOW,
                        required=False,
                        category="oauth",
                    ),
                    self.test_token_introspection,
                ),
                (
                    TestCase(
                        id="token-revocation",
                        name="Token Revocation",
                        description="Test OAuth token revocation endpoint",
                        spec_reference="RFC 7009",
                        severity=TestSeverity.LOW,
                        required=False,
                        category="oauth",
                    ),
                    self.test_token_revocation,
                ),
            ])
        
        # Core protocol tests - always run these
        test_cases.extend([
            (
                TestCase(
                    id="http-transport",
                    name="MCP Protocol Transport",
                    description="Server must support HTTP transport with JSON or SSE responses",
                    spec_reference="MCP Transport Spec Section 3.1",
                    severity=TestSeverity.HIGH,
                    required=True,
                    category="protocol",
                ),
                self.test_http_transport,
            ),
            (
                TestCase(
                    id="protocol-version",
                    name="Protocol Version Header",
                    description="Server MUST handle MCP-Protocol-Version header per spec",
                    spec_reference="MCP Transport Spec Section 2.4",
                    severity=TestSeverity.CRITICAL,
                    required=True,
                    category="protocol",
                ),
                self.test_protocol_version,
            ),
            (
                TestCase(
                    id="streamable-http",
                    name="Streamable HTTP Transport",
                    description="Server MUST properly implement Streamable HTTP transport",
                    spec_reference="MCP Transport Spec - Streamable HTTP",
                    severity=TestSeverity.HIGH,
                    required=True,
                    category="protocol",
                ),
                self.test_streamable_http,
            ),
            (
                TestCase(
                    id="mcp-tools",
                    name="MCP Tools",
                    description="Test tool discovery and validation",
                    spec_reference="MCP Core Spec - Tools",
                    severity=TestSeverity.HIGH,
                    required=False,
                    category="protocol",
                ),
                self.test_mcp_tools,
            ),
        ])
        
        # Initialize server info
        self.server_info = MCPServerInfo(
            url=HttpUrl(self.mcp_endpoint),
            requires_auth=auth_required
        )
        
        # Execute all tests
        self.test_results = []
        for test_case, test_func in test_cases:
            result = await self._execute_test(test_case, test_func)
            self.test_results.append(result)
        
        # Calculate summary statistics
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.status == TestStatus.PASSED)
        failed_tests = sum(1 for r in self.test_results if r.status == TestStatus.FAILED)
        skipped_tests = sum(1 for r in self.test_results if r.status == TestStatus.SKIPPED)
        error_tests = sum(1 for r in self.test_results if r.status == TestStatus.ERROR)
        
        return ValidationResult(
            server_url=HttpUrl(self.mcp_endpoint),
            started_at=start_time,
            completed_at=datetime.utcnow(),
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            skipped_tests=skipped_tests,
            error_tests=error_tests,
            test_results=self.test_results,
        )