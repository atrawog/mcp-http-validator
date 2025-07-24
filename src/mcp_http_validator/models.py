"""Data models for MCP HTTP Validator."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field, HttpUrl


class TestStatus(str, Enum):
    """Test execution status."""
    
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class TestSeverity(str, Enum):
    """Test failure severity levels."""
    
    CRITICAL = "critical"  # Spec violation that breaks interoperability
    HIGH = "high"         # Important spec requirement not met
    MEDIUM = "medium"     # Optional feature missing or incorrect
    LOW = "low"          # Minor issue or recommendation


class TestCase(BaseModel):
    """Individual test case definition."""
    
    id: str = Field(..., description="Unique test identifier")
    name: str = Field(..., description="Human-readable test name")
    description: str = Field(..., description="What this test validates")
    spec_reference: Optional[str] = Field(None, description="MCP spec section reference")
    severity: TestSeverity = Field(TestSeverity.MEDIUM, description="Failure severity")
    required: bool = Field(True, description="Whether this test is required for compliance")
    category: str = Field(..., description="Test category (e.g., 'oauth', 'endpoints')")


class TestResult(BaseModel):
    """Result of a single test execution."""
    
    test_case: TestCase
    status: TestStatus
    duration_ms: float = Field(..., description="Test execution time in milliseconds")
    message: Optional[str] = Field(None, description="Test result message (for any status)")
    error_message: Optional[str] = Field(None, description="Error details for failed tests (deprecated - use message)")
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ValidationResult(BaseModel):
    """Complete validation run result."""
    
    server_url: HttpUrl
    mcp_version: str = "2025-06-18"
    started_at: datetime
    completed_at: datetime
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    error_tests: int
    test_results: List[TestResult]
    
    @property
    def success_rate(self) -> float:
        """Calculate the success rate as a percentage."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100
    
    @property
    def is_compliant(self) -> bool:
        """Check if all required tests passed."""
        return all(
            result.status == TestStatus.PASSED or not result.test_case.required
            for result in self.test_results
        )
    
    @property
    def duration(self) -> float:
        """Calculate the duration of the validation run in seconds."""
        return (self.completed_at - self.started_at).total_seconds()


class OAuthServerMetadata(BaseModel):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
    
    issuer: HttpUrl
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    jwks_uri: Optional[HttpUrl] = None
    registration_endpoint: Optional[HttpUrl] = None
    scopes_supported: Optional[List[str]] = None
    response_types_supported: List[str]
    grant_types_supported: Optional[List[str]] = None
    token_endpoint_auth_methods_supported: Optional[List[str]] = None
    resource_indicators_supported: Optional[bool] = None
    introspection_endpoint: Optional[HttpUrl] = None
    revocation_endpoint: Optional[HttpUrl] = None
    id_token_signing_alg_values_supported: Optional[List[str]] = None
    subject_types_supported: Optional[List[str]] = None


class ProtectedResourceMetadata(BaseModel):
    """OAuth 2.0 Protected Resource Metadata (RFC 9728)."""
    
    resource: HttpUrl
    authorization_servers: List[HttpUrl]
    jwks_uri: Optional[HttpUrl] = None
    scopes_supported: Optional[List[str]] = None
    bearer_methods_supported: Optional[List[str]] = None
    resource_documentation: Optional[HttpUrl] = None
    resource_policy: Optional[HttpUrl] = None


class MCPServerInfo(BaseModel):
    """MCP Server information and capabilities."""
    
    url: HttpUrl
    name: Optional[str] = None
    version: Optional[str] = None
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    oauth_metadata: Optional[ProtectedResourceMetadata] = None
    supported_methods: Set[str] = Field(default_factory=set)
    requires_auth: bool = True


class ComplianceReport(BaseModel):
    """MCP specification compliance report."""
    
    server_info: MCPServerInfo
    validation_result: ValidationResult
    oauth_server_metadata: Optional[OAuthServerMetadata] = None
    compliance_level: str = Field(..., description="Overall compliance level")
    critical_failures: List[TestResult] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    
    def to_markdown(self) -> str:
        """Generate a markdown report."""
        lines = [
            f"# MCP Compliance Report",
            f"",
            f"**Server**: {self.server_info.url}",
            f"**Generated**: {self.generated_at.isoformat()}",
            f"**MCP Version**: {self.validation_result.mcp_version}",
            f"",
            f"## Summary",
            f"",
            f"- **Compliance Level**: {self.compliance_level}",
            f"- **Success Rate**: {self.validation_result.success_rate:.1f}%",
            f"- **Total Tests**: {self.validation_result.total_tests}",
            f"- **Passed**: {self.validation_result.passed_tests}",
            f"- **Failed**: {self.validation_result.failed_tests}",
            f"",
        ]
        
        if self.critical_failures:
            lines.extend([
                f"## Critical Failures",
                f"",
            ])
            for result in self.critical_failures:
                lines.extend([
                    f"### {result.test_case.name}",
                    f"",
                    f"- **Status**: {result.status}",
                    f"- **Severity**: {result.test_case.severity}",
                    f"- **Error**: {result.message}",
                    f"",
                ])
        
        if self.recommendations:
            lines.extend([
                f"## Recommendations",
                f"",
            ])
            for rec in self.recommendations:
                lines.append(f"- {rec}")
        
        return "\n".join(lines)


class OAuthTokenResponse(BaseModel):
    """OAuth 2.0 Token Response."""
    
    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    # MCP-specific: resources should be in the token's aud claim
    aud: Optional[List[str]] = None