"""RFC 8414 OAuth 2.0 Authorization Server Metadata validation."""

from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from pydantic import HttpUrl, ValidationError

from .models import OAuthServerMetadata


class RFC8414Validator:
    """Validates OAuth 2.0 Authorization Server Metadata against RFC 8414."""
    
    # Required fields per RFC 8414 Section 2
    REQUIRED_FIELDS = {
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    }
    
    # Recommended fields that should be present
    RECOMMENDED_FIELDS = {
        "registration_endpoint",
        "scopes_supported",
        "token_endpoint_auth_methods_supported",
        "claims_supported",
        "code_challenge_methods_supported",
        "grant_types_supported",
        "revocation_endpoint",
        "introspection_endpoint",
    }
    
    # MCP-specific requirements
    MCP_REQUIRED_SCOPES = {"mcp:read", "mcp:write"}
    MCP_RECOMMENDED_FIELDS = {
        "resource_indicators_supported",  # RFC 8707
    }
    
    def __init__(self, metadata: Dict[str, any]):
        """Initialize validator with server metadata.
        
        Args:
            metadata: Raw metadata dictionary from server
        """
        self.metadata = metadata
        self.issues: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
    
    def validate(self) -> Tuple[bool, OAuthServerMetadata, Dict[str, List[str]]]:
        """Validate metadata against RFC 8414.
        
        Returns:
            Tuple of (is_valid, parsed_metadata, issues_dict)
        """
        self.issues = []
        self.warnings = []
        self.info = []
        
        # Check required fields
        self._check_required_fields()
        
        # Check recommended fields
        self._check_recommended_fields()
        
        # Validate field values
        self._validate_issuer()
        self._validate_endpoints()
        self._validate_supported_values()
        
        # MCP-specific checks
        self._check_mcp_compliance()
        
        # Try to parse into model
        parsed_metadata = None
        try:
            parsed_metadata = OAuthServerMetadata(**self.metadata)
        except ValidationError as e:
            self.issues.append(f"Failed to parse metadata: {str(e)}")
        
        is_valid = len(self.issues) == 0
        
        return is_valid, parsed_metadata, {
            "errors": self.issues,
            "warnings": self.warnings,
            "info": self.info,
        }
    
    def _check_required_fields(self):
        """Check for presence of required fields."""
        missing = self.REQUIRED_FIELDS - set(self.metadata.keys())
        for field in missing:
            self.issues.append(f"Missing required field: {field}")
    
    def _check_recommended_fields(self):
        """Check for presence of recommended fields."""
        missing = self.RECOMMENDED_FIELDS - set(self.metadata.keys())
        for field in missing:
            self.warnings.append(f"Missing recommended field: {field}")
    
    def _validate_issuer(self):
        """Validate issuer field per RFC 8414 Section 2."""
        issuer = self.metadata.get("issuer")
        if not issuer:
            return
        
        # Must be a valid HTTPS URL with no query or fragment
        try:
            parsed = urlparse(issuer)
            if parsed.scheme != "https":
                self.issues.append("Issuer must use HTTPS scheme")
            if parsed.query:
                self.issues.append("Issuer must not contain query string")
            if parsed.fragment:
                self.issues.append("Issuer must not contain fragment")
        except Exception as e:
            self.issues.append(f"Invalid issuer URL: {str(e)}")
    
    def _validate_endpoints(self):
        """Validate endpoint URLs."""
        endpoint_fields = [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "registration_endpoint",
            "revocation_endpoint",
            "introspection_endpoint",
        ]
        
        for field in endpoint_fields:
            url = self.metadata.get(field)
            if url:
                try:
                    parsed = urlparse(url)
                    if parsed.scheme not in ["https", "http"]:
                        self.issues.append(f"{field} must use HTTP or HTTPS scheme")
                    # RFC 8414 allows HTTP for development
                    if parsed.scheme == "http" and field in self.REQUIRED_FIELDS:
                        self.warnings.append(f"{field} should use HTTPS in production")
                except Exception as e:
                    self.issues.append(f"Invalid {field} URL: {str(e)}")
    
    def _validate_supported_values(self):
        """Validate various *_supported fields."""
        # response_types_supported must contain at least one value
        response_types = self.metadata.get("response_types_supported", [])
        if not response_types:
            self.issues.append("response_types_supported must not be empty")
        elif "code" not in response_types:
            self.warnings.append("response_types_supported should include 'code' for OAuth 2.0")
        
        # grant_types_supported defaults
        grant_types = self.metadata.get("grant_types_supported", [])
        if grant_types and "authorization_code" not in grant_types:
            self.warnings.append("grant_types_supported should include 'authorization_code'")
        
        # token_endpoint_auth_methods_supported defaults
        auth_methods = self.metadata.get("token_endpoint_auth_methods_supported", [])
        if not auth_methods:
            self.info.append("token_endpoint_auth_methods_supported defaults to ['client_secret_basic']")
        
        # code_challenge_methods_supported for PKCE
        pkce_methods = self.metadata.get("code_challenge_methods_supported", [])
        if not pkce_methods:
            self.warnings.append("code_challenge_methods_supported not specified (PKCE support unclear)")
        elif "S256" not in pkce_methods:
            self.warnings.append("code_challenge_methods_supported should include 'S256' for security")
    
    def _check_mcp_compliance(self):
        """Check MCP-specific requirements."""
        # Check for MCP scopes
        scopes = set(self.metadata.get("scopes_supported", []))
        missing_scopes = self.MCP_REQUIRED_SCOPES - scopes
        if missing_scopes:
            self.warnings.append(f"Missing MCP scopes: {', '.join(missing_scopes)}")
        
        # Check for resource indicators support (RFC 8707)
        if "resource_indicators_supported" not in self.metadata:
            self.warnings.append("resource_indicators_supported not specified (RFC 8707)")
        elif not self.metadata.get("resource_indicators_supported"):
            self.warnings.append("resource_indicators_supported is false (MCP requires RFC 8707)")
        
        # Check for additional endpoints
        for field in self.MCP_RECOMMENDED_FIELDS:
            if field not in self.metadata:
                self.info.append(f"MCP recommendation: Include {field}")
    
    def get_summary(self) -> str:
        """Get a summary of validation results."""
        lines = []
        
        if self.issues:
            lines.append("ERRORS:")
            for issue in self.issues:
                lines.append(f"  ✗ {issue}")
        
        if self.warnings:
            lines.append("\nWARNINGS:")
            for warning in self.warnings:
                lines.append(f"  ⚠ {warning}")
        
        if self.info:
            lines.append("\nINFO:")
            for info in self.info:
                lines.append(f"  ℹ {info}")
        
        if not self.issues and not self.warnings:
            lines.append("✓ Fully compliant with RFC 8414")
        
        return "\n".join(lines)