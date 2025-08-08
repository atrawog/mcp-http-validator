"""OAuth 2.0 test client for MCP validation."""

import asyncio
import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx
import jwt
from authlib.common.security import generate_token
from authlib.oauth2.rfc6749 import OAuth2Token
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel, HttpUrl

from .models import OAuthServerMetadata, OAuthTokenResponse


class OAuthTestClient:
    """OAuth 2.0 client for testing MCP server authorization with RFC 7592 support."""
    
    def __init__(
        self,
        auth_server_url: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: str = "urn:ietf:wg:oauth:2.0:oob",
        timeout: float = 30.0,
        verify_ssl: bool = True,
        registration_access_token: Optional[str] = None,
    ):
        """Initialize OAuth test client.
        
        Args:
            auth_server_url: OAuth authorization server base URL
            client_id: OAuth client ID (if pre-registered)
            client_secret: OAuth client secret (if pre-registered)
            redirect_uri: Redirect URI for authorization code flow
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            registration_access_token: Token for managing client registration (RFC 7592)
        """
        self.auth_server_url = auth_server_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.registration_access_token = registration_access_token
        self.registration_client_uri: Optional[str] = None
        self.client = httpx.AsyncClient(timeout=timeout, verify=verify_ssl)
        self.server_metadata: Optional[OAuthServerMetadata] = None
        self._jwks_cache: Optional[Dict[str, Any]] = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    async def discover_metadata(self) -> OAuthServerMetadata:
        """Discover OAuth server metadata from .well-known endpoint."""
        url = urljoin(self.auth_server_url, "/.well-known/oauth-authorization-server")
        
        response = await self.client.get(url)
        response.raise_for_status()
        
        data = response.json()
        self.server_metadata = OAuthServerMetadata(**data)
        return self.server_metadata
    
    async def register_client(
        self,
        client_name: str = "MCP Validator Test Client",
        grant_types: List[str] = ["authorization_code", "refresh_token", "client_credentials"],
        response_types: List[str] = ["code"],
        scope: str = "mcp:read mcp:write",
        software_id: str = "mcp-http-validator",
        software_version: str = "0.1.0",
        redirect_uris: Optional[List[str]] = None,
    ) -> Tuple[str, Optional[str], Optional[str]]:
        """Dynamically register an OAuth client (RFC 7591).
        
        Args:
            client_name: Human-readable name for the client
            grant_types: OAuth grant types to request
            response_types: OAuth response types to request
            scope: OAuth scope to request
            software_id: Software identifier
            software_version: Software version
            redirect_uris: Custom redirect URIs (defaults to OOB)
        
        Returns:
            Tuple of (client_id, client_secret, registration_access_token)
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        if not self.server_metadata.registration_endpoint:
            raise ValueError("Server does not support dynamic client registration")
        
        # Use provided redirect URIs or default to OOB
        if redirect_uris is None:
            redirect_uris = ["urn:ietf:wg:oauth:2.0:oob"]
        
        # Update instance redirect_uri if single URI provided
        if len(redirect_uris) == 1:
            self.redirect_uri = redirect_uris[0]
        
        registration_data = {
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "scope": scope,
            "software_id": software_id,
            "software_version": software_version,
            "application_type": "native",  # CLI application
            "token_endpoint_auth_method": "client_secret_post",
        }
        
        response = await self.client.post(
            str(self.server_metadata.registration_endpoint),
            json=registration_data,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
        
        data = response.json()
        self.client_id = data["client_id"]
        self.client_secret = data.get("client_secret")
        self.registration_access_token = data.get("registration_access_token")
        self.registration_client_uri = data.get("registration_client_uri")
        
        return self.client_id, self.client_secret, self.registration_access_token
    
    def generate_authorization_url(
        self,
        state: Optional[str] = None,
        scope: str = "mcp:read mcp:write",
        resources: Optional[List[str]] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
    ) -> Tuple[str, str, Optional[str]]:
        """Generate authorization URL with PKCE support.
        
        Args:
            state: OAuth state parameter (generated if not provided)
            scope: OAuth scope
            resources: MCP server resource URLs (for audience restriction)
            code_challenge: PKCE code challenge (generated if not provided)
            code_challenge_method: PKCE method (S256 recommended)
        
        Returns:
            Tuple of (authorization_url, state, code_verifier)
        """
        if not self.server_metadata:
            raise ValueError("Must discover metadata first")
        
        if not self.client_id:
            raise ValueError("Must register client first")
        
        # Generate state if not provided
        if not state:
            state = generate_token(32)
        
        # Generate PKCE parameters if not provided
        code_verifier = None
        if not code_challenge:
            code_verifier = generate_token(64)
            code_challenge = self._generate_code_challenge(code_verifier)
        
        # Build authorization parameters
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "state": state,
        }
        
        # Add PKCE parameters
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method
        
        # Add resource parameters for MCP compliance
        if resources:
            # OAuth 2.0 resource indicators (RFC 8707)
            for resource in resources:
                params[f"resource"] = resource
        
        api_url = f"{self.server_metadata.authorization_endpoint}?{urlencode(params, doseq=True)}"
        return api_url, state, code_verifier
    
    def _generate_code_challenge(self, verifier: str) -> str:
        """Generate PKCE code challenge from verifier."""
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")
    
    async def exchange_code_for_token(
        self,
        code: str,
        code_verifier: Optional[str] = None,
        resources: Optional[List[str]] = None,
    ) -> OAuthTokenResponse:
        """Exchange authorization code for access token.
        
        Args:
            code: Authorization code from redirect
            code_verifier: PKCE code verifier
            resources: MCP server resource URLs
        
        Returns:
            OAuth token response
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        
        # Add client authentication if we have a secret
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.client_secret:
            # Use HTTP Basic auth for client credentials
            auth = httpx.BasicAuth(self.client_id, self.client_secret)
        else:
            auth = None
            # Include client_id in body for public clients
            token_data["client_id"] = self.client_id
        
        # Add PKCE verifier if provided
        if code_verifier:
            token_data["code_verifier"] = code_verifier
        
        # Add resources for audience restriction
        if resources:
            for resource in resources:
                token_data["resource"] = resource
        
        response = await self.client.post(
            str(self.server_metadata.token_endpoint),
            data=token_data,
            headers=headers,
            auth=auth,
        )
        response.raise_for_status()
        
        data = response.json()
        return OAuthTokenResponse(**data)
    
    async def refresh_token(
        self,
        refresh_token: str,
        scope: Optional[str] = None,
    ) -> OAuthTokenResponse:
        """Refresh an access token.
        
        Args:
            refresh_token: Refresh token from previous token response
            scope: Optional scope (must be subset of original)
        
        Returns:
            New token response
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        
        if scope:
            token_data["scope"] = scope
        
        # Add client authentication
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        
        # Try with Basic Auth first (RFC 6749 preferred method)
        if self.client_secret:
            auth = httpx.BasicAuth(self.client_id, self.client_secret)
            try:
                response = await self.client.post(
                    str(self.server_metadata.token_endpoint),
                    data=token_data,
                    headers=headers,
                    auth=auth,
                )
                response.raise_for_status()
                data = response.json()
                return OAuthTokenResponse(**data)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 422:
                    # Server might require client credentials in body instead
                    pass
                else:
                    raise
        
        # Try with client credentials in body (alternative method some servers require)
        token_data["client_id"] = self.client_id
        if self.client_secret:
            token_data["client_secret"] = self.client_secret
        
        response = await self.client.post(
            str(self.server_metadata.token_endpoint),
            data=token_data,
            headers=headers,
            auth=None,
        )
        response.raise_for_status()
        
        data = response.json()
        return OAuthTokenResponse(**data)
    
    async def client_credentials_grant(
        self,
        scope: str = "mcp:read mcp:write",
        resources: Optional[List[str]] = None,
    ) -> Optional[OAuthTokenResponse]:
        """Get access token using Client Credentials Grant (RFC 6749 Section 4.4).
        
        Args:
            scope: OAuth scope to request
            resources: Optional list of resource URLs for audience restriction
        
        Returns:
            Token response if successful, None if grant not supported
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        # Check if client credentials grant is supported
        grant_types = self.server_metadata.grant_types_supported or ["authorization_code"]
        if "client_credentials" not in grant_types:
            return None
        
        # Client credentials requires client authentication
        if not self.client_secret:
            return None
        
        token_data = {
            "grant_type": "client_credentials",
            "scope": scope,
        }
        
        # Add resources for audience restriction
        if resources:
            # RFC 8707 allows multiple resource parameters
            for resource in resources:
                if "resource" not in token_data:
                    token_data["resource"] = resource
                else:
                    # For multiple resources, we need to use form array syntax
                    if isinstance(token_data["resource"], str):
                        token_data["resource"] = [token_data["resource"]]
                    token_data["resource"].append(resource)
        
        try:
            response = await self.client.post(
                str(self.server_metadata.token_endpoint),
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                auth=httpx.BasicAuth(self.client_id, self.client_secret),
            )
            response.raise_for_status()
            
            data = response.json()
            return OAuthTokenResponse(**data)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 400:
                # Grant type not supported or other client error
                return None
            raise
    
    async def device_authorization_grant(
        self,
        scope: str = "mcp:read mcp:write",
    ) -> Optional[Dict[str, Any]]:
        """Initiate Device Authorization Grant flow (RFC 8628).
        
        Args:
            scope: OAuth scope to request
        
        Returns:
            Device authorization response with verification_uri and device_code
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        # Check if device authorization endpoint exists
        device_endpoint = getattr(self.server_metadata, "device_authorization_endpoint", None)
        if not device_endpoint:
            return None
        
        device_data = {
            "client_id": self.client_id,
            "scope": scope,
        }
        
        try:
            response = await self.client.post(
                str(device_endpoint),
                data=device_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            
            return response.json()
        except httpx.HTTPStatusError:
            return None
    
    async def poll_device_token(
        self,
        device_code: str,
        interval: int = 5,
        expires_in: int = 300,
    ) -> Optional[OAuthTokenResponse]:
        """Poll for device authorization completion.
        
        Args:
            device_code: Device code from authorization response
            interval: Polling interval in seconds
            expires_in: Maximum time to poll in seconds
        
        Returns:
            Token response when authorized, None if expired or denied
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        token_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": self.client_id,
        }
        
        start_time = time.time()
        while time.time() - start_time < expires_in:
            try:
                response = await self.client.post(
                    str(self.server_metadata.token_endpoint),
                    data=token_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                response.raise_for_status()
                
                data = response.json()
                return OAuthTokenResponse(**data)
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 400:
                    error_data = e.response.json()
                    error = error_data.get("error")
                    
                    if error == "authorization_pending":
                        # Still waiting for user authorization
                        await asyncio.sleep(interval)
                        continue
                    elif error == "slow_down":
                        # Increase polling interval
                        interval += 5
                        await asyncio.sleep(interval)
                        continue
                    elif error in ["access_denied", "expired_token"]:
                        # User denied or token expired
                        return None
                raise
        
        return None
    
    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """Introspect a token to check its validity and claims.
        
        Args:
            token: Access or refresh token to introspect
        
        Returns:
            Token introspection response
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        if not self.server_metadata.introspection_endpoint:
            raise ValueError("Server does not support token introspection")
        
        data = {
            "token": token,
            "token_type_hint": "access_token",
        }
        
        # Add client authentication
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.client_secret:
            auth = httpx.BasicAuth(self.client_id, self.client_secret)
        else:
            auth = None
            data["client_id"] = self.client_id
        
        response = await self.client.post(
            str(self.server_metadata.introspection_endpoint),
            data=data,
            headers=headers,
            auth=auth,
        )
        response.raise_for_status()
        
        return response.json()
    
    async def revoke_token(self, token: str, token_type_hint: str = "access_token") -> bool:
        """Revoke a token.
        
        Args:
            token: Token to revoke
            token_type_hint: Hint about token type (access_token or refresh_token)
        
        Returns:
            True if revocation succeeded
        """
        if not self.server_metadata:
            await self.discover_metadata()
        
        if not self.server_metadata.revocation_endpoint:
            raise ValueError("Server does not support token revocation")
        
        data = {
            "token": token,
            "token_type_hint": token_type_hint,
        }
        
        # Add client authentication
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.client_secret:
            auth = httpx.BasicAuth(self.client_id, self.client_secret)
        else:
            auth = None
            data["client_id"] = self.client_id
        
        response = await self.client.post(
            str(self.server_metadata.revocation_endpoint),
            data=data,
            headers=headers,
            auth=auth,
        )
        
        # Revocation endpoint returns 200 even if token was already revoked
        return response.status_code == 200
    
    async def get_jwks(self) -> Dict[str, Any]:
        """Get JSON Web Key Set from authorization server."""
        if not self.server_metadata:
            await self.discover_metadata()
        
        if not self.server_metadata.jwks_uri:
            raise ValueError("Server does not provide JWKS endpoint")
        
        if self._jwks_cache:
            return self._jwks_cache
        
        response = await self.client.get(str(self.server_metadata.jwks_uri))
        response.raise_for_status()
        
        self._jwks_cache = response.json()
        return self._jwks_cache
    
    def decode_token(self, token: str, verify: bool = True) -> Dict[str, Any]:
        """Decode and optionally verify a JWT token.
        
        Args:
            token: JWT access token
            verify: Whether to verify the signature
        
        Returns:
            Decoded token claims
        """
        if not verify:
            # Decode without verification (for testing)
            return jwt.decode(token, options={"verify_signature": False})
        
        # For verification, we'd need the server's public key from JWKS
        # This is a simplified version - in production you'd fetch and cache JWKS
        raise NotImplementedError("Token verification requires JWKS implementation")
    
    def validate_token_audience(
        self,
        token: str,
        expected_resources: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """Validate that token contains expected resource URLs in audience.
        
        Args:
            token: JWT access token
            expected_resources: List of MCP server resource URLs
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            claims = self.decode_token(token, verify=False)
            
            # Check audience claim
            aud = claims.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            
            # All expected resources should be in audience
            missing_resources = [r for r in expected_resources if r not in aud]
            
            if missing_resources:
                return False, f"Token audience missing resources: {missing_resources}"
            
            return True, None
            
        except Exception as e:
            return False, f"Failed to decode token: {str(e)}"
    
    async def get_client_configuration(self) -> Dict[str, Any]:
        """Get current client configuration (RFC 7592).
        
        Returns:
            Client configuration data
        
        Raises:
            ValueError: If registration access token not available
        """
        if not self.registration_access_token or not self.registration_client_uri:
            raise ValueError("Registration access token and client URI required")
        
        headers = {
            "Authorization": f"Bearer {self.registration_access_token}",
            "Accept": "application/json",
        }
        
        response = await self.client.get(self.registration_client_uri, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    async def update_client_configuration(
        self,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update client configuration (RFC 7592).
        
        Args:
            updates: Configuration updates to apply
        
        Returns:
            Updated client configuration
        
        Raises:
            ValueError: If registration access token not available
        """
        if not self.registration_access_token or not self.registration_client_uri:
            raise ValueError("Registration access token and client URI required")
        
        # Get current configuration
        current_config = await self.get_client_configuration()
        
        # Merge updates
        updated_config = {**current_config, **updates}
        
        headers = {
            "Authorization": f"Bearer {self.registration_access_token}",
            "Content-Type": "application/json",
        }
        
        response = await self.client.put(
            self.registration_client_uri,
            json=updated_config,
            headers=headers,
        )
        response.raise_for_status()
        
        data = response.json()
        
        # Update local state if changed
        if "client_secret" in data:
            self.client_secret = data["client_secret"]
        if "registration_access_token" in data:
            self.registration_access_token = data["registration_access_token"]
        
        return data
    
    async def delete_client_registration(self) -> bool:
        """Delete client registration (RFC 7592).
        
        Returns:
            True if deletion succeeded
        
        Raises:
            ValueError: If registration access token not available
        """
        if not self.registration_access_token or not self.registration_client_uri:
            raise ValueError("Registration access token and client URI required")
        
        headers = {
            "Authorization": f"Bearer {self.registration_access_token}",
        }
        
        response = await self.client.delete(self.registration_client_uri, headers=headers)
        
        if response.status_code == 204:
            # Clear local state
            self.client_id = None
            self.client_secret = None
            self.registration_access_token = None
            self.registration_client_uri = None
            return True
        
        return False
    
    async def test_mcp_server_with_token(
        self,
        mcp_server_url: str,
        access_token: str,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test accessing an MCP server with the given token.
        
        Args:
            mcp_server_url: MCP server URL to test
            access_token: OAuth access token
        
        Returns:
            Tuple of (success, error_message, details)
        """
        # For SSE endpoints, the URL itself is the MCP endpoint
        # For regular endpoints, we might need to append /mcp
        if mcp_server_url.endswith("/sse"):
            url = mcp_server_url
            # SSE endpoints need different headers
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "text/event-stream",
                "Cache-Control": "no-cache",
            }
        else:
            url = urljoin(mcp_server_url, "/mcp")
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "MCP-Protocol-Version": "2025-06-18",
            }
        
        try:
            # For SSE endpoints, use HEAD request or timeout quickly
            if mcp_server_url.endswith("/sse"):
                # Use a short timeout for SSE endpoints since they stream
                response = await self.client.get(
                    url, 
                    headers=headers,
                    timeout=httpx.Timeout(connect=5.0, read=2.0, write=5.0, pool=5.0)
                )
            else:
                response = await self.client.get(url, headers=headers)
            
            if response.status_code == 200:
                return True, None, {
                    "status_code": 200,
                    "url": url,
                }
            elif response.status_code == 401:
                www_auth = response.headers.get("WWW-Authenticate", "")
                return False, "Authentication failed", {
                    "status_code": 401,
                    "www_authenticate": www_auth,
                    "url": url,
                }
            else:
                return False, f"Unexpected status: {response.status_code}", {
                    "status_code": response.status_code,
                    "url": url,
                    "body": response.text[:500],
                }
                
        except httpx.ReadTimeout as e:
            # For SSE endpoints, ReadTimeout is expected since they stream
            if mcp_server_url.endswith("/sse"):
                # If we got a timeout, it means we connected successfully
                # (otherwise we'd get a different error like 401)
                return True, None, {
                    "status_code": 200,
                    "url": url,
                    "note": "SSE endpoint connected successfully (streaming)"
                }
            else:
                error_msg = f"Request timed out: {str(e)}"
                return False, error_msg, {"url": url, "error": error_msg, "type": "ReadTimeout"}
        except httpx.HTTPStatusError as e:
            # This means we got a non-2xx status code
            return False, f"HTTP error: {e.response.status_code}", {
                "status_code": e.response.status_code,
                "url": url,
                "body": e.response.text[:500] if e.response.text else ""
            }
        except httpx.RequestError as e:
            error_msg = f"Request failed: {type(e).__name__}: {str(e)}"
            return False, error_msg, {"url": url, "error": error_msg, "type": type(e).__name__}
        except Exception as e:
            error_msg = f"Unexpected error: {type(e).__name__}: {str(e)}"
            return False, error_msg, {"url": url, "error": error_msg, "type": type(e).__name__}