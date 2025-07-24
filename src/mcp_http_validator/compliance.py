"""MCP specification compliance checker."""

from typing import Dict, List, Optional, Set

from .models import (
    ComplianceReport,
    MCPServerInfo,
    TestResult,
    TestSeverity,
    TestStatus,
    ValidationResult,
)
from .oauth import OAuthTestClient
from .validator import MCPValidator


class ComplianceChecker:
    """Checks MCP server compliance with the specification."""
    
    # MCP 2025-06-18 required features
    REQUIRED_OAUTH_METADATA_FIELDS = {
        "resource",
        "authorization_servers",
    }
    
    REQUIRED_WWW_AUTHENTICATE_PARAMS = {
        "realm",
        "as_uri",
        "resource_uri",
    }
    
    REQUIRED_AUTH_SERVER_METADATA_FIELDS = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
    }
    
    RECOMMENDED_AUTH_SERVER_FEATURES = {
        "resource_indicators_supported": True,
        "introspection_endpoint": "present",
        "revocation_endpoint": "present",
        "registration_endpoint": "present",
    }
    
    MCP_REQUIRED_SCOPES = {
        "mcp:read",
        "mcp:write",
    }
    
    def __init__(self, validation_result: ValidationResult, server_info: MCPServerInfo):
        """Initialize compliance checker.
        
        Args:
            validation_result: Results from validation tests
            server_info: Information about the MCP server
        """
        self.validation_result = validation_result
        self.server_info = server_info
        self.critical_failures: List[TestResult] = []
        self.recommendations: List[str] = []
    
    def check_compliance(self) -> ComplianceReport:
        """Check overall MCP compliance and generate report."""
        # Analyze test results
        self._analyze_test_results()
        
        # Determine compliance level
        compliance_level = self._determine_compliance_level()
        
        # Generate recommendations
        self._generate_recommendations()
        
        return ComplianceReport(
            server_info=self.server_info,
            validation_result=self.validation_result,
            compliance_level=compliance_level,
            critical_failures=self.critical_failures,
            recommendations=self.recommendations,
        )
    
    def _analyze_test_results(self):
        """Analyze test results to identify critical failures."""
        self.critical_failures = [
            result for result in self.validation_result.test_results
            if result.status == TestStatus.FAILED and result.test_case.severity == TestSeverity.CRITICAL
        ]
    
    def _determine_compliance_level(self) -> str:
        """Determine overall compliance level based on test results."""
        if not self.validation_result.test_results:
            return "UNKNOWN"
        
        # Check if all required tests passed
        required_failed = any(
            result.status != TestStatus.PASSED and result.test_case.required
            for result in self.validation_result.test_results
        )
        
        if required_failed:
            if self.critical_failures:
                return "NON_COMPLIANT"
            else:
                return "PARTIALLY_COMPLIANT"
        
        # All required tests passed
        success_rate = self.validation_result.success_rate
        
        if success_rate == 100:
            return "FULLY_COMPLIANT"
        elif success_rate >= 90:
            return "MOSTLY_COMPLIANT"
        elif success_rate >= 70:
            return "PARTIALLY_COMPLIANT"
        else:
            return "MINIMALLY_COMPLIANT"
    
    def _generate_recommendations(self):
        """Generate recommendations based on test failures."""
        self.recommendations = []
        
        # Check specific test failures
        test_results_by_id = {
            result.test_case.id: result
            for result in self.validation_result.test_results
        }
        
        # OAuth metadata recommendations
        if "oauth-metadata" in test_results_by_id:
            result = test_results_by_id["oauth-metadata"]
            if result.status != TestStatus.PASSED:
                details = result.details or {}
                url = details.get("url_tested", "/.well-known/oauth-protected-resource")
                if details.get("status_code") == 401:
                    self.recommendations.append(
                        f"**OAuth Discovery**: Remove auth requirement from `{url}` (currently returns 401)"
                    )
                elif details.get("status_code") == 404:
                    self.recommendations.append(
                        f"**OAuth Discovery**: Implement `{url}` endpoint (currently returns 404)"
                    )
                else:
                    self.recommendations.append(
                        f"**OAuth Discovery**: Fix `{url}` endpoint (currently returns {details.get('status_code', 'error')})"
                    )
        
        # Authentication challenge recommendations
        if "auth-challenge" in test_results_by_id:
            result = test_results_by_id["auth-challenge"]
            if result.status != TestStatus.PASSED:
                details = result.details or {}
                url = details.get("url_tested", "/mcp endpoint")
                if details.get("status_code") != 401:
                    self.recommendations.append(
                        f"**401 Response**: Return 401 Unauthorized for `{url}` (not {details.get('status_code')})"
                    )
                elif details.get("missing_params"):
                    params = details["missing_params"]
                    self.recommendations.append(
                        f"**WWW-Authenticate**: Add {', '.join(params)} to Bearer challenge on `{url}`"
                    )
                else:
                    self.recommendations.append(
                        f"**WWW-Authenticate**: Include proper Bearer challenge on `{url}` responses"
                    )
        
        # Token validation recommendations
        if "token-audience" in test_results_by_id:
            result = test_results_by_id["token-audience"]
            if result.status != TestStatus.PASSED and result.status != TestStatus.SKIPPED:
                self.recommendations.append(
                    "**Token Security**: Validate token audience contains your server URL"
                )
        
        # HTTP transport recommendations
        if "http-transport" in test_results_by_id:
            result = test_results_by_id["http-transport"]
            if result.status != TestStatus.PASSED:
                # Check what the specific issue was
                if result.details and "content_type" in result.details:
                    content_type = result.details.get("content_type", "")
                    if not content_type:
                        self.recommendations.append(
                            "Return proper Content-Type header (application/json or text/event-stream)"
                        )
                    elif "application/json" not in content_type and "text/event-stream" not in content_type:
                        self.recommendations.append(
                            f"Return valid Content-Type for MCP transport (got '{content_type}', expected application/json or text/event-stream)"
                        )
                else:
                    self.recommendations.append(
                        "Implement valid HTTP transport with either JSON or SSE responses"
                    )
                    self.recommendations.append(
                        "Support POST requests to /mcp endpoint with JSON-RPC messages"
                    )
        
        # Protocol version recommendations
        if "protocol-version" in test_results_by_id:
            result = test_results_by_id["protocol-version"]
            if result.status != TestStatus.PASSED:
                if result.details and "diagnosis" in result.details:
                    # Server bug - not reading header
                    self.recommendations.append(
                        "**Server Bug**: Fix MCP-Protocol-Version header parsing (case-insensitive lookup)"
                    )
                else:
                    self.recommendations.append(
                        "**Protocol Support**: Add MCP version 2025-06-18 to supported versions"
                    )
        
        # General OAuth recommendations
        if self.server_info.oauth_metadata:
            metadata = self.server_info.oauth_metadata
            
            if not metadata.scopes_supported:
                self.recommendations.append(
                    f"Document supported OAuth scopes (at minimum: {', '.join(self.MCP_REQUIRED_SCOPES)})"
                )
            elif not self.MCP_REQUIRED_SCOPES.issubset(set(metadata.scopes_supported)):
                missing_scopes = self.MCP_REQUIRED_SCOPES - set(metadata.scopes_supported)
                self.recommendations.append(
                    f"Add required MCP scopes: {', '.join(missing_scopes)}"
                )
            
            if not metadata.bearer_methods_supported:
                self.recommendations.append(
                    "Document supported bearer token methods (e.g., 'header')"
                )
            
            if not metadata.resource_documentation:
                self.recommendations.append(
                    "Provide resource_documentation URL for API documentation"
                )
        
        # MCP tools recommendations
        if "mcp-tools" in test_results_by_id:
            result = test_results_by_id["mcp-tools"]
            if result.status != TestStatus.PASSED and result.details:
                details = result.details
                
                # Check for session initialization failures
                if not details.get("session_initialized"):
                    self.recommendations.append(
                        "Ensure MCP server properly handles 'initialize' method calls"
                    )
                    self.recommendations.append(
                        "Return valid JSON-RPC responses with 'result' field for successful operations"
                    )
                
                # Check for tool discovery issues
                elif details.get("tools_failed", 0) > 0:
                    self.recommendations.append(
                        "Ensure all exposed tools handle test calls gracefully"
                    )
                    self.recommendations.append(
                        "Implement proper error handling for invalid tool parameters"
                    )
                    
                    # Specific tool recommendations
                    tool_results = details.get("tool_results", [])
                    for tool_result in tool_results:
                        if tool_result["status"] not in ["success", "skipped"]:
                            tool_name = tool_result["tool_name"]
                            error = tool_result.get("error", "Unknown error")
                            self.recommendations.append(
                                f"Fix tool '{tool_name}': {error}"
                            )
    
    @classmethod
    async def check_oauth_server_compliance(
        cls,
        oauth_client: OAuthTestClient,
    ) -> Dict[str, any]:
        """Check OAuth authorization server compliance.
        
        Args:
            oauth_client: Configured OAuth test client
        
        Returns:
            Dictionary of compliance checks and results
        """
        results = {}
        
        try:
            # Discover server metadata
            metadata = await oauth_client.discover_metadata()
            results["metadata_endpoint"] = "PASS"
            
            # Check required fields
            missing_required = []
            for field in cls.REQUIRED_AUTH_SERVER_METADATA_FIELDS:
                if not getattr(metadata, field, None):
                    missing_required.append(field)
            
            if missing_required:
                results["required_fields"] = f"FAIL: Missing {missing_required}"
            else:
                results["required_fields"] = "PASS"
            
            # Check resource indicators support (RFC 8707)
            if metadata.resource_indicators_supported:
                results["resource_indicators"] = "PASS"
            else:
                results["resource_indicators"] = "FAIL: RFC 8707 support not indicated"
            
            # Check recommended features
            for feature, expected in cls.RECOMMENDED_AUTH_SERVER_FEATURES.items():
                value = getattr(metadata, feature, None)
                if expected == "present":
                    results[feature] = "PASS" if value else "WARN: Not supported"
                else:
                    results[feature] = "PASS" if value == expected else f"WARN: Expected {expected}"
            
            # Check supported scopes
            if metadata.scopes_supported:
                supported_scopes = set(metadata.scopes_supported)
                if cls.MCP_REQUIRED_SCOPES.issubset(supported_scopes):
                    results["mcp_scopes"] = "PASS"
                else:
                    missing = cls.MCP_REQUIRED_SCOPES - supported_scopes
                    results["mcp_scopes"] = f"FAIL: Missing scopes {missing}"
            else:
                results["mcp_scopes"] = "WARN: No scopes documented"
            
        except Exception as e:
            results["metadata_endpoint"] = f"FAIL: {str(e)}"
        
        return results
    
    @classmethod
    def generate_compliance_summary(
        cls,
        reports: List[ComplianceReport],
    ) -> str:
        """Generate a summary of multiple compliance reports.
        
        Args:
            reports: List of compliance reports to summarize
        
        Returns:
            Markdown formatted summary
        """
        lines = [
            "# MCP Compliance Summary",
            "",
            f"**Total Servers Tested**: {len(reports)}",
            "",
            "## Results by Server",
            "",
        ]
        
        # Group by compliance level
        by_level = {}
        for report in reports:
            level = report.compliance_level
            if level not in by_level:
                by_level[level] = []
            by_level[level].append(report)
        
        # Show results by compliance level
        for level in ["FULLY_COMPLIANT", "MOSTLY_COMPLIANT", "PARTIALLY_COMPLIANT", 
                      "MINIMALLY_COMPLIANT", "NON_COMPLIANT"]:
            if level in by_level:
                lines.extend([
                    f"### {level.replace('_', ' ').title()} ({len(by_level[level])})",
                    "",
                ])
                for report in by_level[level]:
                    lines.append(
                        f"- **{report.server_info.url}**: "
                        f"{report.validation_result.success_rate:.1f}% tests passed"
                    )
                lines.append("")
        
        # Common issues
        all_failures = []
        for report in reports:
            all_failures.extend([
                result.test_case.name
                for result in report.validation_result.test_results
                if result.status == TestStatus.FAILED
            ])
        
        if all_failures:
            from collections import Counter
            failure_counts = Counter(all_failures)
            
            lines.extend([
                "## Common Issues",
                "",
            ])
            for test_name, count in failure_counts.most_common(5):
                lines.append(f"- {test_name}: Failed on {count} server(s)")
        
        return "\n".join(lines)