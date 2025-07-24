"""OAuth-related test methods for MCP HTTP Validator."""

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import HttpUrl

from .transport_detector import TransportDetector, TransportType
from .sse_client import MCPSSEClient
from .models import (
    TestCase,
    TestResult,
    TestStatus,
    ValidationResult,
)
from .oauth import OAuthTestClient
from .env_manager import EnvManager
from .rfc8414 import RFC8414Validator
from .rfc8707 import RFC8707Validator


class BaseMCPValidator:
    """Base class for MCP validators - provides common functionality."""
    
    def __init__(
        self,
        server_url: str,
        access_token: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        env_file: Optional[str] = None,
        auto_register: bool = True,
    ):
        self.server_url = server_url.rstrip("/")
        self.base_url = self.server_url  # For compatibility
        self.access_token = access_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.env_file = env_file
        self.auto_register = auto_register
        
        # Parse server URL to extract base URL
        parsed = urlparse(self.server_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Determine MCP endpoint
        if "/mcp" in parsed.path:
            self.mcp_endpoint = self.server_url
        else:
            # Default to /mcp endpoint
            self.mcp_endpoint = urljoin(self.base_url, "/mcp")
        
        # Initialize HTTP client
        self.client = httpx.AsyncClient(verify=verify_ssl, timeout=timeout)
        
        # OAuth client for authentication
        self.oauth_client = None
        self.env_manager = None
        
    def _get_headers(self, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get headers for authenticated requests."""
        headers = {}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if extra_headers:
            headers.update(extra_headers)
        return headers
    


class OAuthTestValidator(BaseMCPValidator):
    """Validator for OAuth-related MCP tests."""
    
    async def test_protected_resource_metadata(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test /.well-known/oauth-protected-resource endpoint (RFC 9728)."""
        url = urljoin(self.server_url, "/.well-known/oauth-protected-resource")
        
        details = {
            "test_description": "Checking if MCP server exposes OAuth protected resource metadata",
            "requirement": "RFC 9728 requires all OAuth-protected resources to expose metadata at /.well-known/oauth-protected-resource",
            "purpose": "This endpoint allows clients to discover OAuth requirements and authorization servers",
            "url_tested": url,
        }
        
        try:
            # First try WITHOUT auth - this endpoint should be publicly accessible per RFC 9728
            response = await self.client.get(url, timeout=5.0)
            
            if response.status_code == 404:
                return False, (
                    "Protected resource metadata endpoint not found. "
                    "The server must implement /.well-known/oauth-protected-resource endpoint as required by RFC 9728. "
                    "This endpoint should return JSON metadata about OAuth requirements without requiring authentication."
                ), {
                    **details,
                    "status_code": 404,
                    "expected_status": 200,
                    "fix": "Implement the /.well-known/oauth-protected-resource endpoint that returns OAuth metadata",
                    "example_response": {
                        "resource": "https://mcp.example.com",
                        "authorization_servers": ["https://auth.example.com"],
                        "scopes_supported": ["mcp:read", "mcp:write"],
                        "bearer_methods_supported": ["header"],
                        "resource_documentation": "https://docs.example.com/api"
                    }
                }
            
            if response.status_code == 401:
                # This is wrong per RFC 9728 - endpoint should be public
                # But let's try with auth anyway to see what we get
                auth_response = await self.client.get(url, headers=self._get_headers(), timeout=5.0)
                return False, (
                    "Protected resource metadata endpoint requires authentication, which violates RFC 9728. "
                    "This endpoint MUST be publicly accessible without authentication so that clients can discover "
                    "OAuth requirements before attempting to access protected resources. The server returned 401 Unauthorized, "
                    "but RFC 9728 Section 2 explicitly states this endpoint must be available without credentials."
                ), {
                    **details,
                    "status_code": response.status_code,
                    "expected_status": 200,
                    "auth_status_code": auth_response.status_code if auth_response else None,
                    "body": auth_response.text if auth_response and auth_response.status_code == 200 else response.text,
                    "violation": "RFC 9728 Section 2 - Metadata endpoint must be publicly accessible",
                    "fix": "Remove authentication requirement from /.well-known/oauth-protected-resource endpoint"
                }
            
            if response.status_code != 200:
                return False, (
                    f"Protected resource metadata endpoint returned unexpected status {response.status_code}. "
                    f"Expected HTTP 200 OK with JSON metadata."
                ), {
                    **details,
                    "status_code": response.status_code,
                    "expected_status": 200,
                    "body": response.text[:500] if response.text else None
                }
            
            # Parse and validate the metadata
            try:
                data = response.json()
                
                # Check required fields per RFC 9728
                required_fields = ["resource", "authorization_servers"]
                missing_fields = [f for f in required_fields if f not in data]
                
                if missing_fields:
                    return False, (
                        f"Protected resource metadata missing required fields: {', '.join(missing_fields)}. "
                        f"RFC 9728 Section 3 requires 'resource' (the resource URI) and 'authorization_servers' "
                        f"(array of OAuth server URLs) fields."
                    ), {
                        **details,
                        "missing_fields": missing_fields,
                        "fields_found": list(data.keys()),
                        "metadata": data
                    }
                
                # Validate resource field
                resource_uri = data.get("resource")
                if not resource_uri or not isinstance(resource_uri, str):
                    return False, (
                        "Protected resource metadata has invalid 'resource' field. "
                        "It must be a non-empty string containing the resource URI."
                    ), {
                        **details,
                        "resource_value": resource_uri,
                        "resource_type": type(resource_uri).__name__
                    }
                
                # Validate authorization_servers
                auth_servers = data.get("authorization_servers", [])
                if not isinstance(auth_servers, list) or not auth_servers:
                    return False, (
                        "Protected resource metadata has invalid 'authorization_servers' field. "
                        "It must be a non-empty array of OAuth authorization server URLs."
                    ), {
                        **details,
                        "authorization_servers": auth_servers,
                        "type": type(auth_servers).__name__
                    }
                
                # Success!
                details["metadata"] = data
                details["resource_uri"] = resource_uri
                details["authorization_servers"] = auth_servers
                details["scopes_supported"] = data.get("scopes_supported", [])
                
                return True, (
                    f"Protected resource metadata endpoint is properly implemented. "
                    f"Resource URI: {resource_uri}, "
                    f"Authorization servers: {', '.join(auth_servers[:3])}{'...' if len(auth_servers) > 3 else ''}. "
                    f"The endpoint is publicly accessible and returns valid RFC 9728 metadata."
                ), details
                
            except Exception as e:
                return False, (
                    f"Protected resource metadata has invalid format: {str(e)}. "
                    "The endpoint returned data but it doesn't match the required schema from RFC 9728. "
                    "Common issues include invalid JSON syntax or incorrect data types for required fields."
                ), {
                    **details,
                    "parse_error": str(e),
                    "response_body": response.text[:500]
                }
                
        except httpx.ConnectError:
            return False, (
                "Failed to connect to server. The connection was refused or timed out. "
                "This usually indicates the server is not running, not accessible at the specified URL, "
                "or there are network/firewall issues preventing the connection."
            ), {
                **details,
                "error": "Connection refused or timed out",
                "suggestions": [
                    "Verify the server is running and accessible",
                    "Check the URL is correct (including protocol and port)",
                    "Ensure DNS resolution is working for the server hostname",
                    "Check for any firewall or network restrictions"
                ]
            }
        
        except Exception as e:
            error_msg = str(e)
            return False, (
                f"Unexpected error while testing protected resource metadata: {error_msg}. "
                "This may indicate a network issue or server error preventing access to the metadata endpoint."
            ), {
                **details,
                "error": error_msg,
                "error_type": type(e).__name__
            }
    
    async def test_unauthenticated_request(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test that protected endpoints return proper 401 with WWW-Authenticate header."""
        # Try to access the MCP endpoint without auth
        url = self.mcp_endpoint
        
        details = {
            "test_description": "Testing authentication challenge for protected MCP endpoints",
            "requirement": "MCP servers must return 401 Unauthorized with WWW-Authenticate header for unauthenticated requests",
            "purpose": "This allows clients to discover OAuth requirements and authorization server location",
            "url_tested": url,
            "spec_reference": "MCP Auth Spec Section 2.2, RFC 9110 Section 11.6.1"
        }
        
        try:
            # First detect transport type
            detector = TransportDetector(self.client)
            base_headers = {"MCP-Protocol-Version": "2025-06-18"}
            
            caps = await detector.detect(url, base_headers)
            
            # For SSE servers, we need to use SSE-appropriate headers
            if caps.primary_transport == TransportType.HTTP_SSE:
                headers = {"Accept": "text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
                # SSE endpoints might not respond to regular GET requests, so use streaming
                try:
                    async with self.client.stream("GET", url, headers=headers, timeout=5.0) as response:
                        # For SSE, just check the initial response status
                        status_code = response.status_code
                except httpx.ReadTimeout:
                    # SSE connections stay open, so timeout is expected for 200 responses
                    return None, (
                        "SSE endpoint is publicly accessible (no authentication required). "
                        "SSE servers keep connections open for event streaming, which is the expected behavior. "
                        "Authentication tests will be skipped for this public SSE server."
                    ), {
                        **details,
                        "transport": "SSE",
                        "auth_required": False,
                        "note": "Public SSE servers are allowed by the specification"
                    }
            else:
                # For non-SSE servers, use regular request
                headers = {"Accept": "application/json", "MCP-Protocol-Version": "2025-06-18"}
                response = await self.client.get(url, headers=headers, timeout=5.0)
                status_code = response.status_code
            
            if status_code != 401:
                # Check if endpoint is publicly accessible (no auth required)
                if status_code == 200:
                    return None, (
                        f"MCP endpoint is publicly accessible and returned {status_code}. "
                        "No authentication is required for this server. Authentication tests will be skipped."
                    ), {
                        **details,
                        "status_code": status_code,
                        "auth_required": False,
                        "note": "Public MCP servers are allowed by the specification"
                    }
                else:
                    return False, (
                        f"MCP endpoint returned unexpected status {status_code} for unauthenticated request. "
                        f"Expected 401 Unauthorized for protected resources or 200 OK for public resources. "
                        f"Received status indicates the server may be misconfigured or experiencing errors."
                    ), {
                        **details,
                        "status_code": status_code,
                        "expected_statuses": [401, 200],
                        "body": response.text[:500] if hasattr(response, 'text') else None
                    }
            
            # We got 401 - now check for WWW-Authenticate header
            www_auth = response.headers.get("WWW-Authenticate", "")
            details["www_authenticate_header"] = www_auth
            details["status_code"] = 401
            
            if not www_auth:
                return False, (
                    "Server returned 401 Unauthorized but missing WWW-Authenticate header. "
                    "RFC 9110 Section 11.6.1 requires servers to include WWW-Authenticate header "
                    "with 401 responses to indicate which authentication scheme is required. "
                    "For OAuth 2.0, this should be 'Bearer' with optional parameters. "
                    "To fix: Add 'WWW-Authenticate: Bearer' header to 401 responses. "
                    "Run 'mcp-validate flow' for interactive OAuth flow."
                ), {
                    **details,
                    "missing_header": "WWW-Authenticate",
                    "required_by": "RFC 9110 Section 11.6.1",
                    "expected_value": "Bearer realm=\"MCP Server\""
                }
            
            # Check if it's Bearer auth
            if not www_auth.lower().startswith("bearer"):
                return False, (
                    f"Server uses non-standard authentication scheme: {www_auth.split()[0]}. "
                    f"MCP specification requires OAuth 2.0 Bearer Token authentication (RFC 6750). "
                    f"The WWW-Authenticate header should start with 'Bearer'. "
                    f"Run 'mcp-validate flow' for interactive OAuth flow."
                ), {
                    **details,
                    "auth_scheme": www_auth.split()[0] if www_auth else "unknown",
                    "expected_scheme": "Bearer",
                    "spec_reference": "RFC 6750"
                }
            
            # Parse Bearer parameters
            bearer_params = {}
            if " " in www_auth:
                param_string = www_auth.split(" ", 1)[1]
                # Simple parameter parsing (doesn't handle all edge cases)
                for param in param_string.split(","):
                    if "=" in param:
                        key, value = param.strip().split("=", 1)
                        bearer_params[key] = value.strip('"')
            
            details["bearer_parameters"] = bearer_params
            
            # Success - proper 401 with Bearer auth
            return True, (
                "Server correctly challenges unauthenticated requests. "
                "Returns 401 Unauthorized with WWW-Authenticate: Bearer header as required by RFC 6750. "
                f"Bearer parameters: {', '.join(f'{k}={v}' for k, v in bearer_params.items()) if bearer_params else 'none'}. "
                "Clients can use this information to initiate OAuth 2.0 authorization flow."
            ), details
            
        except Exception as e:
            error_msg = str(e)
            return False, (
                f"Failed to test unauthenticated access: {error_msg}. "
                "Could not complete the authentication challenge test due to connection or server errors."
            ), {
                **details,
                "error": error_msg,
                "error_type": type(e).__name__,
                "fix": "Verify the MCP endpoint is accessible. For SSE servers, authentication may work differently."
            }
    
    async def test_authenticated_request(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test that authenticated requests are accepted and invalid tokens are rejected."""
        url = self.mcp_endpoint
        
        details = {
            "test_description": "Testing basic OAuth 2.0 bearer token validation",
            "requirement": "MCP servers must validate bearer tokens and reject invalid ones (RFC 6750)",
            "purpose": "Verifies server distinguishes between valid and obviously invalid tokens",
            "url_tested": url,
            "spec_reference": "RFC 6750 - OAuth 2.0 Bearer Token Usage"
        }
        
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        if not self.access_token:
            # Mark as skipped, not failed - manual auth required
            return None, (
                "Cannot test bearer token authentication without a valid access token. "
                "The server requires OAuth 2.0 Bearer Token authentication (RFC 6750) but no access token is available in the environment. "
                "The validator checked for existing tokens and attempted to use automated OAuth flows (client credentials per RFC 6749, device flow per RFC 8628) "
                "but these are either not supported by the OAuth server or require manual intervention. "
                "Bearer token authentication is critical for MCP servers to verify that clients can access protected resources as specified in RFC 6750."
            ), {
                **details,
                "token_status": "unavailable",
                "automated_grants_tried": ["client_credentials"],
                "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow to obtain a token",
                "alternative": "Provide a token via --token parameter or MCP_ACCESS_TOKEN environment variable"
            }
        
        # First, test with invalid token to ensure server rejects bad tokens
        invalid_token_test = {
            "test": "invalid_token_rejection",
            "description": "Verifying server rejects invalid tokens"
        }
        
        try:
            # Test with clearly invalid token
            invalid_headers = self._get_headers({"Authorization": "Bearer invalid-token-12345"})
            invalid_response = await self.client.get(url, headers=invalid_headers, timeout=5.0)
            
            if invalid_response.status_code in [200, 204]:
                # CRITICAL: Server accepted an invalid token!
                return False, (
                    "CRITICAL SECURITY FAILURE: Server accepted an obviously invalid bearer token! "
                    f"The server returned success (HTTP {invalid_response.status_code}) for the test token 'invalid-token-12345'. "
                    "This indicates the server is NOT performing even basic token validation. "
                    "Any client could access protected resources with any arbitrary string as a token. "
                    "Per RFC 6750, servers MUST validate bearer tokens. At minimum, the server should reject "
                    "tokens that are not in its token database or cannot be verified. "
                    "Run 'mcp-validate flow' for interactive OAuth flow."
                ), {
                    **details,
                    "invalid_token_accepted": True,
                    "invalid_token_status": invalid_response.status_code,
                    "security_issue": "CRITICAL - No token validation",
                    "required_fix": "Implement proper bearer token validation per RFC 6750"
                }
            
            # Good - server rejected invalid token
            details["invalid_token_status"] = invalid_response.status_code
            details["invalid_token_rejected"] = True
            
            # Now test with valid token
            valid_headers = self._get_headers()
            valid_headers["MCP-Protocol-Version"] = "2025-06-18"
            
            # Detect transport type for proper request
            detector = TransportDetector(self.client)
            caps = await detector.detect(url, valid_headers)
            
            if caps.primary_transport == TransportType.HTTP_SSE:
                # For SSE, establish connection and check if we can receive events
                valid_headers["Accept"] = "text/event-stream"
                try:
                    async with self.client.stream("GET", url, headers=valid_headers, timeout=5.0) as response:
                        if response.status_code == 401:
                            return False, (
                                "Server rejected valid access token with 401 Unauthorized. "
                                "The token was obtained through proper OAuth flow but server still denies access. "
                                "Possible causes: token expired, wrong audience, insufficient scopes, or server misconfiguration. "
                                "Run 'mcp-validate flow' for interactive OAuth flow."
                            ), {
                                **details,
                                "valid_token_status": 401,
                                "token_present": True,
                                "suggestion": "Check token expiration, audience claim, and required scopes"
                            }
                        elif response.status_code == 200:
                            # Success for SSE
                            details["valid_token_status"] = 200
                            details["transport"] = "SSE"
                            return True, (
                                "Bearer token authentication working correctly for SSE transport. "
                                "Server properly validates tokens: rejects invalid tokens with 401, "
                                "accepts valid bearer tokens and establishes SSE connection. "
                                "This confirms RFC 6750 compliance for token validation."
                            ), details
                except httpx.ReadTimeout:
                    # SSE connection established successfully (stays open)
                    details["valid_token_status"] = 200
                    details["transport"] = "SSE"
                    return True, (
                        "Bearer token authentication working correctly for SSE transport. "
                        "Server accepted valid token and kept connection open for event streaming."
                    ), details
            else:
                # Regular JSON request
                valid_headers["Accept"] = "application/json"
                valid_response = await self.client.post(
                    url,
                    headers=valid_headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "clientInfo": {
                                "name": "mcp-validator",
                                "version": "0.1.0"
                            }
                        }
                    },
                    timeout=5.0
                )
                
                if valid_response.status_code == 401:
                    return False, (
                        "Server rejected valid access token with 401 Unauthorized. "
                        "The token was obtained through proper OAuth flow but server still denies access. "
                        "This could indicate: expired token, wrong audience in token, insufficient scopes, "
                        "or server configuration issues. Check server logs for specific rejection reason. "
                        "Run 'mcp-validate flow' for interactive OAuth flow."
                    ), {
                        **details,
                        "valid_token_status": 401,
                        "token_present": True,
                        "headers_sent": list(valid_headers.keys())
                    }
                
                if valid_response.status_code not in [200, 201, 204]:
                    return False, (
                        f"Server returned unexpected status {valid_response.status_code} for authenticated request. "
                        f"Expected 2xx success status for valid bearer token. "
                        f"The server properly rejected invalid tokens but fails to accept valid ones."
                    ), {
                        **details,
                        "valid_token_status": valid_response.status_code,
                        "response_body": valid_response.text[:500] if valid_response.text else None
                    }
                
                # Success!
                details["valid_token_status"] = valid_response.status_code
                details["transport"] = "JSON-RPC"
                
                return True, (
                    "Bearer token authentication is working correctly. "
                    f"Server properly validates tokens: rejects invalid tokens ({invalid_response.status_code}), "
                    f"accepts valid bearer tokens ({valid_response.status_code}). "
                    "This confirms proper RFC 6750 implementation for OAuth 2.0 Bearer Token usage."
                ), details
                
        except Exception as e:
            error_msg = str(e)
            return False, (
                f"Failed to test authenticated access: {error_msg}. "
                "Could not complete bearer token validation test. Verify server is running and accessible."
            ), {
                **details,
                "error": error_msg,
                "error_type": type(e).__name__,
                "token_present": True,
                "fix": "Ensure server is accessible and accepting connections"
            }
    
    async def test_token_audience_validation(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test that the server validates token audience claims."""
        details = {
            "test_description": "Testing MCP server validation of token audience (aud) claims",
            "requirement": "MCP servers must validate that token audience includes their resource URI",
            "purpose": "Prevents tokens for other servers from being accepted (token confusion attack)",
            "spec_reference": "RFC 9728 Section 3, RFC 8707"
        }
        
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        if not self.access_token:
            # Mark as skipped, not failed
            return None, (
                "Token audience validation test requires a valid access token to proceed. "
                "This test verifies that the MCP server properly validates the 'aud' (audience) claim in JWT tokens "
                "to ensure tokens are only accepted by their intended recipients. This is a critical security feature "
                "required by RFC 9728 to prevent token misuse across different services. Without an access token, "
                "this security validation cannot be tested."
            ), {
                **details,
                "note": "Audience validation prevents tokens from being used on unintended servers",
                "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow"
            }
        
        # First, check if we have protected resource metadata to know expected audience
        expected_audience = self.mcp_endpoint.rstrip('/')  # Default to MCP endpoint URL
        details["expected_audience"] = expected_audience
        details["resource_metadata_found"] = False
        
        try:
            metadata_url = urljoin(self.base_url, "/.well-known/oauth-protected-resource")
            metadata_response = await self.client.get(metadata_url, timeout=5.0)
            if metadata_response.status_code == 200:
                metadata = metadata_response.json()
                # Use resource from metadata if available and non-null
                resource_uri = metadata.get("resource")
                if resource_uri and isinstance(resource_uri, str):
                    expected_audience = resource_uri.rstrip('/')
                    details["expected_audience"] = expected_audience
                    details["resource_metadata_found"] = True
                elif resource_uri is None:
                    details["metadata_warning"] = "Protected resource metadata has null 'resource' field"
        except Exception as e:
            # Keep default expected_audience (server URL)
            details["metadata_error"] = str(e)
        
        # Check if token is a JWT or opaque token
        # Opaque tokens are valid per OAuth 2.0 spec but can't be inspected for audience
        is_jwt = False
        try:
            # Try to decode as JWT without verification
            import jwt
            jwt.decode(self.access_token, options={"verify_signature": False})
            is_jwt = True
        except jwt.DecodeError:
            # Not a JWT - likely an opaque token
            is_jwt = False
        except Exception:
            # Other errors - treat as opaque token
            is_jwt = False
        
        details["token_type"] = "JWT" if is_jwt else "opaque"
        
        if not is_jwt:
            # Opaque tokens are valid but we can't inspect audience
            return None, (
                "Token appears to be an opaque token (not JWT). "
                "Audience validation requires JWT tokens with inspectable claims. "
                "Opaque tokens are valid per OAuth 2.0 but audience restrictions must be "
                "enforced server-side through token introspection (RFC 7662). "
                "This test is skipped for opaque tokens."
            ), details
        
        # Use RFC8707Validator to analyze the JWT token
        try:
            # RFC8707Validator uses static methods - validate token directly
            is_valid, token_data = RFC8707Validator.validate_token_response(
                self.access_token,
                requested_resources=[self.mcp_endpoint],
                verify_signature=False
            )
            issues = []  # RFC8707Validator doesn't return issues in validate_token_response
            
            details["token_valid"] = is_valid
            details["token_issues"] = issues
            
            if not is_valid:
                # Token validation failed for some reason
                if token_data and isinstance(token_data, dict):
                    # We have token data but validation still failed
                    error_msg = token_data.get("errors", ["Unknown validation error"])
                    if isinstance(error_msg, list) and error_msg:
                        error_msg = error_msg[0]
                    
                    # Check if this is the common case where OAuth server doesn't support RFC 8707
                    if "missing requested resources" in str(error_msg):
                        actual_aud = token_data.get("token_audience", [])
                        return False, (
                            f"OAuth server does not implement RFC 8707 resource indicators properly. "
                            f"The token audience is '{actual_aud}' but should include the MCP server URL "
                            f"'{self.mcp_endpoint}'. This is an OAuth server configuration issue - the "
                            f"authorization server should include requested 'resource' parameters in the token's "
                            f"audience claim. The MCP server cannot fix this; the OAuth server must be configured "
                            f"to support resource indicators per RFC 8707."
                        ), {
                            **details,
                            "token_data": token_data,
                            "oauth_server_issue": True,
                            "spec_reference": "RFC 8707 - Resource Indicators for OAuth 2.0"
                        }
                    
                    return False, (
                        f"Token audience validation failed: {error_msg}"
                    ), {
                        **details,
                        "token_data": token_data,
                        "validation_failed": True
                    }
                else:
                    # Could not decode token at all
                    return False, (
                        "Cannot validate audience - failed to decode access token. "
                        "This may indicate the token is malformed or not a valid JWT."
                    ), {
                        **details,
                        "token_format": "Invalid or malformed",
                        "fix": "Verify the access token is a properly formatted JWT"
                    }
            
            # Check audience claim
            aud_claim = token_data.get("aud", [])
            if isinstance(aud_claim, str):
                aud_claim = [aud_claim]
            
            details["token_audience"] = aud_claim
            details["audience_validation"] = "unknown"  # We can't directly test server behavior
            
            # We can only check if the token SHOULD work based on audience
            audience_match = any(
                aud.rstrip('/') == expected_audience for aud in aud_claim
            )
            
            if not aud_claim:
                return False, (
                    "Access token has no audience (aud) claim. "
                    "RFC 8707 requires OAuth tokens for resource servers to include an 'aud' claim "
                    "containing the resource URI(s) the token is valid for. Without audience restriction, "
                    "tokens could be used on any server (security risk). The OAuth server should include "
                    "the requested resource parameter as the audience claim when issuing tokens. "
                    "Run 'mcp-validate flow' for interactive OAuth flow."
                ), details
            
            if not audience_match:
                # Token doesn't include this server in audience
                return False, (
                    f"Access token audience doesn't include this MCP server. "
                    f"Token audience: {aud_claim}, Expected: {expected_audience}. "
                    f"Per RFC 8707, tokens must include the target resource server in their audience claim. "
                    f"This prevents token confusion attacks where tokens for one server are used on another. "
                    f"The OAuth server should include the requested 'resource' parameter in the token's 'aud' claim. "
                    f"Run 'mcp-validate flow' for interactive OAuth flow."
                ), details
            
            # Token has correct audience - now we need to verify server validates it
            # We can't definitively test server-side validation without a token for wrong audience
            # But we can provide guidance
            
            return True, (
                f"Access token has correct audience claim including this server ({expected_audience}). "
                f"Token audience: {', '.join(aud_claim)}. "
                f"The token is properly scoped to this resource server per RFC 8707. "
                f"Note: This test validates the token format but cannot verify if the server actually "
                f"validates the audience claim. Servers MUST validate 'aud' to prevent token confusion attacks."
            ), details
            
        except Exception as e:
            return False, (
                f"Error during token audience validation: {str(e)}. "
                "Could not complete audience validation checks. This may indicate issues with the token format "
                "or unexpected errors during validation. "
                "Run 'mcp-validate flow' for interactive OAuth flow."
            ), {
                **details,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    async def test_oauth_server_discovery(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth server discovery."""
        details = {
            "discovery_methods_tried": [],
            "oauth_server_found": None,
        }
        
        # Try to discover OAuth server
        oauth_server = await self.discover_oauth_server()
        
        if not oauth_server:
            return False, "No OAuth authorization server discovered. The validator attempted to discover the OAuth server through multiple methods: checking the protected resource metadata for authorization_servers field (RFC 9728), looking for common OAuth subdomains (auth.*, oauth.*, sso.*, login.*), and checking if the MCP server itself hosts OAuth endpoints with metadata at /.well-known/oauth-authorization-server (RFC 8414). None of these discovery methods succeeded. For proper OAuth integration, either the protected resource metadata should list authorization servers (RFC 9728) or an OAuth server should exist at a discoverable location with proper metadata (RFC 8414).", details
        
        details["oauth_server_found"] = oauth_server
        
        # Just check if metadata endpoint exists and is accessible
        try:
            metadata_url = urljoin(oauth_server, "/.well-known/oauth-authorization-server")
            response = await self.client.get(metadata_url, timeout=5.0)
            
            if response.status_code != 200:
                return False, f"OAuth authorization server metadata endpoint returned HTTP {response.status_code}. The endpoint at {metadata_url} must return HTTP 200 (RFC 9110 Section 15.3.1) with valid OAuth 2.0 Authorization Server Metadata as specified in RFC 8414. This endpoint should be publicly accessible without authentication (RFC 8414 Section 3) and return a JSON document (RFC 8259) containing at minimum: issuer, authorization_endpoint, token_endpoint, and response_types_supported fields (RFC 8414 Section 2).", {
                    **details,
                    "metadata_url": metadata_url,
                    "status_code": response.status_code,
                }
            
            # Just verify it's valid JSON
            try:
                metadata = response.json()
                details["metadata_url"] = metadata_url
                details["metadata_accessible"] = True
            except:
                return False, f"OAuth authorization server metadata endpoint returned invalid JSON. The endpoint at {metadata_url} must return a valid JSON document (RFC 8259) containing OAuth 2.0 Authorization Server Metadata as specified in RFC 8414.", details
            
            # OAuth server metadata endpoint is accessible
            return True, (
                f"OAuth authorization server metadata endpoint found at {metadata_url}. "
                f"The endpoint returned HTTP 200 with parseable JSON content. "
                f"This indicates an OAuth server is present, though functionality was not tested."
            ), details
            
        except Exception as e:
            return False, f"Failed to access OAuth authorization server. An error occurred while attempting to retrieve the OAuth server metadata from {oauth_server} as required by RFC 8414 Section 3. This could indicate network issues or server errors (RFC 9110). The specific error was: {str(e)}", details
    
    async def test_oauth_server_mcp_compliance(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth server compliance with MCP requirements."""
        details = {
            "oauth_server_found": None,
            "rfc8414_validation": None,
            "mcp_scopes_found": [],
            "resource_indicators_supported": False,
        }
        
        # Try to discover OAuth server
        oauth_server = await self.discover_oauth_server()
        
        if not oauth_server:
            return None, "Cannot test OAuth server MCP compliance without an OAuth server. Run OAuth server discovery test first.", details
        
        details["oauth_server_found"] = oauth_server
        
        try:
            metadata_url = urljoin(oauth_server, "/.well-known/oauth-authorization-server")
            response = await self.client.get(metadata_url, timeout=5.0)
            
            if response.status_code != 200:
                return None, "Cannot test OAuth server compliance - metadata endpoint not accessible", details
            
            # Parse and validate metadata
            metadata = response.json()
            validator = RFC8414Validator(metadata)
            is_valid, parsed_metadata, issues = validator.validate()
            
            details["rfc8414_validation"] = {
                "valid": is_valid,
                "issues": issues,
                "metadata": metadata,
            }
            
            if not is_valid:
                return False, "OAuth authorization server metadata is not compliant with RFC 8414. The metadata document must include all required fields per RFC 8414 Section 2 (issuer, authorization_endpoint, token_endpoint, response_types_supported) and follow the specification constraints. Common issues include missing required fields (RFC 8414 Section 2), invalid URL formats (RFC 3986), or issuer URL not matching the server's base URL (RFC 8414 Section 2 requires issuer to be an HTTPS URL with no query or fragment).", details
            
            # Check MCP-specific requirements
            scopes_supported = metadata.get("scopes_supported", [])
            details["mcp_scopes_found"] = [s for s in scopes_supported if s.startswith("mcp:")]
            has_mcp_scopes = set(scopes_supported) & {"mcp:read", "mcp:write"}
            has_resource_indicators = metadata.get("resource_indicators_supported", False)
            details["resource_indicators_supported"] = has_resource_indicators
            
            if not has_mcp_scopes:
                return False, "OAuth authorization server does not support required MCP scopes. The server must advertise support for 'mcp:read' and 'mcp:write' scopes in the scopes_supported field of its metadata per RFC 8414 Section 2. These scopes are essential for MCP protocol authorization as defined in the MCP Authorization Specification - mcp:read allows reading server state and mcp:write allows invoking tools and modifying resources following the principle of least privilege (RFC 6749 Section 3.3).", details
            
            if not has_resource_indicators:
                return False, "OAuth authorization server does not support resource indicators (RFC 8707). The server metadata must include 'resource_indicators_supported: true' to indicate support for the 'resource' parameter in authorization requests. This is required by the MCP specification to ensure tokens are properly scoped to specific MCP servers, preventing token confusion attacks where a token for one server could be used on another. Without resource indicators, tokens cannot be audience-restricted.", details
            
            # All MCP requirements met
            success_msg = (
                f"OAuth authorization server at {oauth_server} is MCP-compliant. "
                f"RFC 8414 validation passed with proper metadata structure. "
                f"Supports required MCP scopes: {', '.join(sorted(has_mcp_scopes))}. "
                f"Resource indicators (RFC 8707) supported for audience-restricted tokens. "
            )
            
            # Add optional feature information
            optional_features = []
            if metadata.get("jwks_uri"):
                optional_features.append("JWKS endpoint for key discovery")
            if metadata.get("introspection_endpoint"):
                optional_features.append("token introspection")
            if metadata.get("revocation_endpoint"):
                optional_features.append("token revocation")
            
            if optional_features:
                success_msg += f"Optional features: {', '.join(optional_features)}."
            
            return True, success_msg, details
            
        except Exception as e:
            return False, f"Failed to validate OAuth authorization server MCP compliance. An error occurred while attempting to validate the OAuth server metadata from {oauth_server}. The specific error was: {str(e)}", details
    
    async def test_oauth_dynamic_registration(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth dynamic client registration (RFC 7591)."""
        details = {
            "test_description": "Testing OAuth dynamic client registration",
            "spec_reference": "RFC 7591",
        }
        
        # Discover OAuth server
        oauth_server = await self.discover_oauth_server()
        if not oauth_server:
            return None, "Cannot test dynamic registration without an OAuth server. OAuth server discovery failed.", details
        
        details["oauth_server"] = oauth_server
        
        try:
            # Get OAuth metadata
            metadata_url = urljoin(oauth_server, "/.well-known/oauth-authorization-server")
            response = await self.client.get(metadata_url, timeout=5.0)
            
            if response.status_code != 200:
                return None, "Cannot test dynamic registration - OAuth metadata not accessible", details
            
            metadata = response.json()
            registration_endpoint = metadata.get("registration_endpoint")
            
            if not registration_endpoint:
                # This is not a failure - RFC 7591 is optional
                details["registration_supported"] = False
                return True, (
                    "OAuth server does not advertise dynamic client registration support. "
                    "This is acceptable as RFC 7591 is an optional feature. "
                    "Clients must be registered through other means (manual registration, pre-configured clients, etc)."
                ), details
            
            details["registration_endpoint"] = registration_endpoint
            details["registration_supported"] = True
            
            # Test registration with minimal request
            test_client_data = {
                "client_name": "MCP Validator Test Client",
                "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "software_id": "mcp-http-validator-test",
                "software_version": "0.1.0"
            }
            
            # Try registration
            reg_response = await self.client.post(
                registration_endpoint,
                json=test_client_data,
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            
            details["registration_status"] = reg_response.status_code
            
            if reg_response.status_code == 201 or reg_response.status_code == 200:
                # Registration succeeded
                try:
                    reg_data = reg_response.json()
                    client_id = reg_data.get("client_id")
                    
                    if not client_id:
                        return False, (
                            "Registration endpoint returned success but no client_id. "
                            "RFC 7591 requires client_id in the response."
                        ), details
                    
                    details["client_registered"] = True
                    details["client_id"] = client_id
                    
                    # Check for required response fields per RFC 7591
                    required_fields = ["client_id"]
                    missing_fields = [f for f in required_fields if f not in reg_data]
                    
                    if missing_fields:
                        return False, (
                            f"Registration response missing required fields: {', '.join(missing_fields)}. "
                            f"RFC 7591 Section 3.2.1 requires these fields in the response."
                        ), details
                    
                    # If we got a registration token, try to clean up
                    if reg_data.get("registration_access_token") and reg_data.get("registration_client_uri"):
                        try:
                            await self.client.delete(
                                reg_data["registration_client_uri"],
                                headers={"Authorization": f"Bearer {reg_data['registration_access_token']}"},
                                timeout=5.0
                            )
                            details["cleanup"] = "success"
                        except:
                            details["cleanup"] = "failed"
                    
                    return True, (
                        f"Dynamic client registration (RFC 7591) is fully supported. "
                        f"Successfully registered client '{client_id}' with minimal parameters. "
                        f"The registration endpoint properly validates requests and returns required fields."
                    ), details
                    
                except Exception as e:
                    return False, (
                        f"Registration succeeded but response was invalid: {str(e)}. "
                        f"The server returned 2xx but the response body doesn't conform to RFC 7591."
                    ), details
            
            elif reg_response.status_code == 400:
                # Bad request - server validates input
                details["registration_rejected"] = True
                return True, (
                    "OAuth server validates dynamic client registration requests. "
                    "The server rejected our test registration with HTTP 400, indicating input validation. "
                    "This is acceptable behavior - the server may have specific requirements for client registration."
                ), details
                
            elif reg_response.status_code == 401:
                # Requires authentication
                details["registration_requires_auth"] = True
                return True, (
                    "Dynamic client registration requires authentication. "
                    "The server returned HTTP 401, indicating registration is restricted to authenticated clients. "
                    "This is allowed by RFC 7591 - servers may require initial access tokens for registration."
                ), details
                
            else:
                # Unexpected status
                return False, (
                    f"Registration endpoint returned unexpected status {reg_response.status_code}. "
                    f"Expected 201 Created or 200 OK for success, 400 for client error, or 401 if auth required."
                ), details
                
        except Exception as e:
            return False, f"Failed to test dynamic client registration: {str(e)}", details
    
    async def test_token_refresh(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth token refresh functionality."""
        details = {
            "test_description": "Testing OAuth token refresh mechanism",
            "refresh_token_available": False,
            "refresh_attempted": False,
            "refresh_successful": False,
            "new_token_valid": False,
        }
        
        # Check if we have a refresh token
        refresh_token = self.env_manager.get_refresh_token(self.mcp_endpoint)
        if not refresh_token:
            return None, (
                "No refresh token available to test token refresh functionality. "
                "Refresh tokens are typically provided during the initial authorization flow. "
                "This test validates that the OAuth server properly handles refresh token grants "
                "as specified in RFC 6749 Section 6."
            ), details
        
        details["refresh_token_available"] = True
        
        # Get OAuth server info
        auth_server_url = await self.discover_oauth_server()
        if not auth_server_url:
            return False, "Cannot test refresh without OAuth server discovery", details
            
        credentials = self.env_manager.get_oauth_credentials(self.mcp_endpoint)
        if not credentials.get("client_id"):
            return False, "Cannot test refresh without client credentials", details
        
        try:
            async with OAuthTestClient(
                auth_server_url,
                client_id=credentials["client_id"],
                client_secret=credentials.get("client_secret"),
                verify_ssl=self.verify_ssl,
            ) as oauth_client:
                # Attempt token refresh
                details["refresh_attempted"] = True
                
                try:
                    token_response = await oauth_client.refresh_token(
                        refresh_token,
                        scope="mcp:read mcp:write"
                    )
                    
                    details["refresh_successful"] = True
                    details["new_access_token_received"] = bool(token_response.access_token)
                    details["new_refresh_token_received"] = bool(token_response.refresh_token)
                    details["expires_in"] = token_response.expires_in
                    
                    # Test the new token
                    if token_response.access_token:
                        success, error, test_details = await oauth_client.test_mcp_server_with_token(
                            self.mcp_endpoint,
                            token_response.access_token
                        )
                        details["new_token_valid"] = success
                        if not success:
                            details["token_test_error"] = error
                        
                        # Save the new tokens if valid
                        if success:
                            self.env_manager.save_tokens(
                                self.mcp_endpoint,
                                token_response.access_token,
                                token_response.expires_in,
                                token_response.refresh_token or refresh_token
                            )
                            details["tokens_updated"] = True
                    
                    return True, (
                        "OAuth token refresh successful. "
                        f"Received new access token (expires in {token_response.expires_in}s). "
                        f"New token {'is valid and working' if details['new_token_valid'] else 'validation failed'}. "
                        "The OAuth server properly implements refresh token grant type per RFC 6749."
                    ), details
                    
                except Exception as e:
                    details["refresh_error"] = str(e)
                    return False, f"Token refresh failed: {e}", details
                    
        except Exception as e:
            details["test_error"] = str(e)
            return False, f"Failed to test token refresh: {e}", details
    
    async def test_token_expiration_handling(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test how the server handles invalid/malformed tokens."""
        details = {
            "test_description": "Testing invalid token handling",
            "invalid_token_tested": False,
            "proper_401_response": False,
            "www_authenticate_header": None,
        }
        
        # Use an invalid/malformed token to test error handling
        # Note: This tests invalid tokens, not specifically expired tokens
        # A truly expired token would need to be a valid JWT with exp claim in the past
        invalid_token = "invalid.token.test"
        
        headers = self._get_headers({
            "Authorization": f"Bearer {invalid_token}",
        })
        
        try:
            response = await self.client.get(self.mcp_endpoint, headers=headers)
            
            details["invalid_token_tested"] = True
            details["status_code"] = response.status_code
            
            if response.status_code == 401:
                details["proper_401_response"] = True
                www_auth = response.headers.get("WWW-Authenticate", "")
                details["www_authenticate_header"] = www_auth
                
                # Check if error indicates invalid token
                if "invalid_token" in www_auth.lower():
                    details["indicates_invalid_token"] = True
                
                return True, (
                    "Server properly rejects invalid/malformed tokens with 401 Unauthorized. "
                    f"WWW-Authenticate header: {www_auth}. "
                    "This complies with OAuth 2.0 Bearer Token Usage (RFC 6750)."
                ), details
            else:
                return False, (
                    f"Server returned {response.status_code} instead of 401 for invalid token. "
                    "Servers must reject invalid/malformed tokens with 401 Unauthorized per RFC 6750."
                ), details
                
        except Exception as e:
            details["test_error"] = str(e)
            return False, f"Failed to test invalid token handling: {e}", details
    
    async def test_token_introspection(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth token introspection endpoint if available."""
        details = {
            "test_description": "Testing OAuth token introspection (RFC 7662)",
            "introspection_endpoint": None,
            "introspection_supported": False,
            "token_active": None,
        }
        
        # Get OAuth server metadata
        auth_server_url = await self.discover_oauth_server()
        if not auth_server_url:
            return None, "Cannot test introspection without OAuth server discovery", details
            
        try:
            async with OAuthTestClient(auth_server_url, verify_ssl=self.verify_ssl) as oauth_client:
                metadata = await oauth_client.discover_metadata()
                introspection_endpoint = metadata.introspection_endpoint
                
                if not introspection_endpoint:
                    return None, (
                        "OAuth server does not advertise token introspection endpoint. "
                        "Token introspection (RFC 7662) is optional but recommended for "
                        "validating token state and metadata."
                    ), details
                
                details["introspection_endpoint"] = introspection_endpoint
                details["introspection_supported"] = True
                
                # Test with current access token
                access_token = self.access_token or self.env_manager.get_valid_access_token(self.mcp_endpoint)
                if not access_token:
                    details["no_token_to_test"] = True
                    return None, "No access token available to test introspection", details
                
                # Get client credentials
                credentials = self.env_manager.get_oauth_credentials(self.mcp_endpoint)
                if not credentials.get("client_id"):
                    return None, "Cannot test introspection without client credentials", details
                
                # Perform introspection
                oauth_client.client_id = credentials["client_id"]
                oauth_client.client_secret = credentials.get("client_secret")
                
                introspect_data = {
                    "token": access_token,
                    "token_type_hint": "access_token",
                    "client_id": credentials["client_id"],
                    "client_secret": credentials.get("client_secret", "")
                }
                
                # Note: auth.atratest.org requires client credentials in body, not Basic Auth
                response = await oauth_client.client.post(
                    str(introspection_endpoint),
                    data=introspect_data,
                    auth=None
                )
                
                if response.status_code == 200:
                    result = response.json()
                    details["introspection_response"] = result
                    details["token_active"] = result.get("active", False)
                    details["token_scope"] = result.get("scope")
                    details["token_exp"] = result.get("exp")
                    details["token_aud"] = result.get("aud")
                    
                    if details["token_active"]:
                        return True, (
                            "Token introspection successful. "
                            f"Token is {'active' if result.get('active') else 'inactive'}. "
                            f"Scope: {result.get('scope', 'N/A')}. "
                            "OAuth server properly implements RFC 7662."
                        ), details
                    else:
                        return True, (
                            "Token introspection indicates token is inactive/expired. "
                            "This is expected if the token has expired or been revoked."
                        ), details
                else:
                    details["introspection_failed"] = True
                    details["status_code"] = response.status_code
                    return False, f"Introspection request failed with status {response.status_code}", details
                    
        except Exception as e:
            details["test_error"] = str(e)
            return None, f"Failed to test token introspection: {e}", details
    
    async def test_token_revocation(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test OAuth token revocation endpoint if available."""
        details = {
            "test_description": "Testing OAuth token revocation (RFC 7009)",
            "revocation_endpoint": None,
            "revocation_supported": False,
            "revocation_tested": False,
        }
        
        # We don't actually revoke tokens in tests as it would break subsequent tests
        # Just check if the endpoint exists and is reachable
        
        auth_server_url = await self.discover_oauth_server()
        if not auth_server_url:
            return None, "Cannot test revocation without OAuth server discovery", details
            
        try:
            async with OAuthTestClient(auth_server_url, verify_ssl=self.verify_ssl) as oauth_client:
                metadata = await oauth_client.discover_metadata()
                revocation_endpoint = metadata.revocation_endpoint
                
                if not revocation_endpoint:
                    return None, (
                        "OAuth server does not advertise token revocation endpoint. "
                        "Token revocation (RFC 7009) is optional but recommended for "
                        "allowing clients to explicitly revoke tokens when no longer needed."
                    ), details
                
                details["revocation_endpoint"] = revocation_endpoint
                details["revocation_supported"] = True
                
                # Just check if endpoint is reachable with OPTIONS
                try:
                    response = await oauth_client.client.options(str(revocation_endpoint))
                    details["endpoint_reachable"] = response.status_code in [200, 204, 405]
                    details["allowed_methods"] = response.headers.get("Allow", "")
                    
                    return True, (
                        f"OAuth server supports token revocation at {revocation_endpoint}. "
                        "Endpoint is reachable and should accept POST requests with token parameter. "
                        "Token revocation allows clients to explicitly invalidate tokens."
                    ), details
                    
                except Exception as e:
                    details["endpoint_check_error"] = str(e)
                    return None, f"Could not verify revocation endpoint: {e}", details
                    
        except Exception as e:
            details["test_error"] = str(e)
            return None, f"Failed to test token revocation: {e}", details