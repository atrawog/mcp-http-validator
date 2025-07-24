"""OAuth Grant Types Validator - validates all grant types supported by an OAuth server."""

from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import httpx
import json
import base64
import time
import asyncio
from urllib.parse import urlencode


class GrantType(str, Enum):
    """OAuth 2.0 Grant Types."""
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"  # Deprecated in OAuth 2.1
    PASSWORD = "password"  # Resource Owner Password Credentials - Deprecated
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


@dataclass
class GrantValidationResult:
    """Result of grant type validation."""
    grant_type: str
    supported: bool
    tested: bool
    success: bool
    error: Optional[str] = None
    details: Dict[str, Any] = None
    recommendation: Optional[str] = None


class OAuthGrantValidator:
    """Validates OAuth grant types supported by a server."""
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    async def validate_all_grants(
        self,
        server_metadata: Dict[str, Any],
        client_id: str,
        client_secret: Optional[str] = None,
        test_grants: bool = True
    ) -> Dict[str, GrantValidationResult]:
        """Validate all grant types advertised by the OAuth server.
        
        Args:
            server_metadata: OAuth server metadata from .well-known
            client_id: OAuth client ID
            client_secret: OAuth client secret (optional)
            test_grants: Whether to actually test the grants (vs just check metadata)
            
        Returns:
            Dictionary mapping grant type to validation result
        """
        results = {}
        supported_grants = server_metadata.get("grant_types_supported", [])
        
        # Check authorization code grant
        auth_code_result = GrantValidationResult(
            grant_type=GrantType.AUTHORIZATION_CODE,
            supported=GrantType.AUTHORIZATION_CODE in supported_grants,
            tested=False,
            success=False
        )
        
        if auth_code_result.supported:
            auth_code_result.details = {
                "authorization_endpoint": server_metadata.get("authorization_endpoint"),
                "token_endpoint": server_metadata.get("token_endpoint"),
                "code_challenge_methods": server_metadata.get("code_challenge_methods_supported", [])
            }
            if not server_metadata.get("authorization_endpoint"):
                auth_code_result.error = "No authorization endpoint specified"
            else:
                auth_code_result.recommendation = "Use for interactive user authentication"
        
        results[GrantType.AUTHORIZATION_CODE] = auth_code_result
        
        # Check client credentials grant
        client_creds_result = GrantValidationResult(
            grant_type=GrantType.CLIENT_CREDENTIALS,
            supported=GrantType.CLIENT_CREDENTIALS in supported_grants,
            tested=False,
            success=False
        )
        
        if client_creds_result.supported and test_grants and client_secret:
            # Test client credentials grant
            tested, success, error = await self._test_client_credentials(
                server_metadata.get("token_endpoint"),
                client_id,
                client_secret
            )
            client_creds_result.tested = tested
            client_creds_result.success = success
            client_creds_result.error = error
            if success:
                client_creds_result.recommendation = "Best for server-to-server authentication (no user interaction)"
        elif client_creds_result.supported:
            client_creds_result.recommendation = "Server-to-server authentication available"
            
        results[GrantType.CLIENT_CREDENTIALS] = client_creds_result
        
        # Check refresh token grant
        refresh_result = GrantValidationResult(
            grant_type=GrantType.REFRESH_TOKEN,
            supported=GrantType.REFRESH_TOKEN in supported_grants,
            tested=False,
            success=False
        )
        
        if refresh_result.supported:
            refresh_result.recommendation = "Use to refresh expired access tokens"
            
        results[GrantType.REFRESH_TOKEN] = refresh_result
        
        # Check device code grant (RFC 8628)
        device_result = GrantValidationResult(
            grant_type=GrantType.DEVICE_CODE,
            supported=GrantType.DEVICE_CODE in supported_grants,
            tested=False,
            success=False
        )
        
        if device_result.supported:
            device_result.details = {
                "device_authorization_endpoint": server_metadata.get("device_authorization_endpoint")
            }
            if not server_metadata.get("device_authorization_endpoint"):
                device_result.error = "No device authorization endpoint specified"
            else:
                device_result.recommendation = "Best for CLI tools and devices without browsers"
                
        results[GrantType.DEVICE_CODE] = device_result
        
        # Check deprecated grants
        if GrantType.IMPLICIT in supported_grants:
            results[GrantType.IMPLICIT] = GrantValidationResult(
                grant_type=GrantType.IMPLICIT,
                supported=True,
                tested=False,
                success=False,
                error="Implicit grant is deprecated in OAuth 2.1",
                recommendation="Migrate to authorization code with PKCE"
            )
            
        if GrantType.PASSWORD in supported_grants:
            results[GrantType.PASSWORD] = GrantValidationResult(
                grant_type=GrantType.PASSWORD,
                supported=True,
                tested=False,
                success=False,
                error="Password grant is deprecated in OAuth 2.1",
                recommendation="Migrate to authorization code or client credentials"
            )
        
        return results
    
    async def _test_client_credentials(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str
    ) -> Tuple[bool, bool, Optional[str]]:
        """Test client credentials grant.
        
        Returns:
            Tuple of (tested, success, error_message)
        """
        if not token_endpoint:
            return False, False, "No token endpoint"
            
        try:
            # Prepare request
            data = {
                "grant_type": "client_credentials",
                "scope": "mcp:read mcp:write"
            }
            
            # Use HTTP Basic auth
            auth_string = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = await self.client.post(
                token_endpoint,
                data=data,
                headers=headers,
                timeout=10.0
            )
            
            if response.status_code == 200:
                token_data = response.json()
                if "access_token" in token_data:
                    return True, True, None
                else:
                    return True, False, "No access token in response"
            else:
                error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                error = error_data.get("error", f"HTTP {response.status_code}")
                error_desc = error_data.get("error_description", "")
                return True, False, f"{error}: {error_desc}" if error_desc else error
                
        except Exception as e:
            return True, False, f"Exception: {str(e)}"
    
    @staticmethod
    def recommend_best_grant(
        results: Dict[str, GrantValidationResult],
        is_cli: bool = True,
        has_browser: bool = False,
        is_automated: bool = False
    ) -> Optional[str]:
        """Recommend the best grant type based on context and availability.
        
        Args:
            results: Grant validation results
            is_cli: Whether this is a CLI application
            has_browser: Whether browser is available
            is_automated: Whether this needs to run without user interaction
            
        Returns:
            Recommended grant type or None
        """
        # For automated/server-to-server
        if is_automated:
            if results.get(GrantType.CLIENT_CREDENTIALS, GrantValidationResult(grant_type="", supported=False, tested=False, success=False)).supported:
                return GrantType.CLIENT_CREDENTIALS
                
        # For CLI without browser
        if is_cli and not has_browser:
            # Device flow is best for CLI
            if results.get(GrantType.DEVICE_CODE, GrantValidationResult(grant_type="", supported=False, tested=False, success=False)).supported:
                return GrantType.DEVICE_CODE
            # Authorization code with OOB is second best
            if results.get(GrantType.AUTHORIZATION_CODE, GrantValidationResult(grant_type="", supported=False, tested=False, success=False)).supported:
                return GrantType.AUTHORIZATION_CODE
                
        # For interactive with browser
        if has_browser:
            if results.get(GrantType.AUTHORIZATION_CODE, GrantValidationResult(grant_type="", supported=False, tested=False, success=False)).supported:
                return GrantType.AUTHORIZATION_CODE
                
        return None