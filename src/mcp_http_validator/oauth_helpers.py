"""OAuth helper methods for MCP validation."""

from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from .base_validator import BaseMCPValidator
from .oauth import OAuthTestClient
from .transport_detector import TransportDetector, TransportType


class OAuthHelpers(BaseMCPValidator):
    """Helper methods for OAuth authentication and discovery."""
    
    async def discover_oauth_server(self) -> Optional[str]:
        """Discover OAuth server using multiple methods.
        
        Returns:
            OAuth server URL if discovered, None otherwise
        """
        discovered_servers = []
        
        # Method 1: Try to get from protected resource metadata
        try:
            # Import here to avoid circular dependency
            from .oauth_tests import OAuthTestValidator
            oauth_validator = OAuthTestValidator(
                self.server_url, 
                self.access_token, 
                self.timeout, 
                self.verify_ssl,
                self.env_manager.env_file,
                self.auto_register
            )
            oauth_validator.client = self.client
            passed, error, details = await oauth_validator.test_protected_resource_metadata()
            if passed and oauth_validator.server_info and oauth_validator.server_info.oauth_metadata:
                auth_servers = oauth_validator.server_info.oauth_metadata.authorization_servers
                if auth_servers:
                    discovered_servers.extend([str(s) for s in auth_servers])
        except Exception:
            pass  # Continue with other methods
        
        # Method 2: Try common subdomain patterns
        parsed_url = urlparse(self.api_url)
        base_domain = parsed_url.hostname
        if base_domain:
            # Extract base domain (e.g., atratest.org from echo-stateless.atratest.org)
            parts = base_domain.split('.')
            if len(parts) > 2:
                base_domain = '.'.join(parts[-2:])
            
            common_api_urls = [
                f"https://auth.{base_domain}",
                f"https://oauth.{base_domain}",
                f"https://sso.{base_domain}",
                f"https://login.{base_domain}",
            ]
            
            for api_url in common_api_urls:
                try:
                    # Check if OAuth metadata endpoint exists
                    test_url = urljoin(api_url, "/.well-known/oauth-authorization-server")
                    response = await self.client.get(test_url, follow_redirects=True, timeout=3.0)
                    if response.status_code == 200:
                        discovered_servers.append(api_url)
                        break  # Found one
                except Exception:
                    continue
        
        # Method 3: Check if the MCP server itself is also an OAuth server
        try:
            test_url = urljoin(self.api_url, "/.well-known/oauth-authorization-server")
            response = await self.client.get(test_url, follow_redirects=True, timeout=3.0)
            if response.status_code == 200:
                discovered_servers.append(self.api_url)
        except Exception as e:
            pass
        
        # Return the first discovered server
        return discovered_servers[0] if discovered_servers else None
    
    async def setup_oauth_client(self, force_new: bool = False) -> Optional[OAuthTestClient]:
        """Setup OAuth client with automatic discovery and registration.
        
        Args:
            force_new: Force new client registration even if credentials exist
        
        Returns:
            Configured OAuth client or None if setup failed
        """
        # Discover OAuth server
        auth_server_url = await self.discover_oauth_server()
        if not auth_server_url:
            return None
        
        # Check for existing credentials
        credentials = self.env_manager.get_oauth_credentials(self.mcp_endpoint)
        
        # Create OAuth client
        self.oauth_client = OAuthTestClient(
            auth_server_url=auth_server_url,
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
            registration_access_token=credentials["registration_token"],
        )
        
        # If we have credentials and not forcing new, we're done
        if credentials["client_id"] and not force_new:
            return self.oauth_client
        
        # Otherwise, register new client if auto_register is enabled
        if self.auto_register:
            try:
                # Discover OAuth server metadata
                await self.oauth_client.discover_metadata()
                
                # Register new client
                client_id, client_secret, reg_token = await self.oauth_client.register_client(
                    client_name=f"MCP Validator for {self.mcp_endpoint}",
                    software_id="mcp-http-validator",
                    software_version="0.1.0",
                )
                
                # Save credentials to .env
                # Auto-registration uses OOB by default
                self.env_manager.save_oauth_credentials(
                    server_url=self.mcp_endpoint,
                    client_id=client_id,
                    client_secret=client_secret,
                    registration_token=reg_token,
                    redirect_uri="urn:ietf:wg:oauth:2.0:oob",  # Default used by register_client
                )
                
                return self.oauth_client
                
            except Exception as e:
                # Registration failed
                print(f"OAuth client registration failed: {e}")
                return None
        
        return None
    
    async def get_access_token(self, interactive: bool = False) -> Optional[str]:
        """Get an access token, either from parameter or by OAuth flow.
        
        Args:
            interactive: Whether to allow interactive flows (device auth)
        
        Returns:
            Access token or None if unavailable
        """
        # If we already have a token from parameter, use it
        if self.access_token:
            return self.access_token
        
        # Check .env for valid access token
        stored_token = self.env_manager.get_valid_access_token(self.mcp_endpoint)
        if stored_token:
            self.access_token = stored_token
            return self.access_token
        
        # Check if we have a refresh token
        refresh_token = self.env_manager.get_refresh_token(self.mcp_endpoint)
        if refresh_token:
            # Try to setup OAuth client if needed
            if not self.oauth_client:
                await self.setup_oauth_client()
            
            if self.oauth_client:
                try:
                    # Attempt to refresh the token
                    token_response = await self.oauth_client.refresh_token(refresh_token)
                    if token_response:
                        self.access_token = token_response.access_token
                        # Save new tokens
                        self.env_manager.save_tokens(
                            self.mcp_endpoint,
                            token_response.access_token,
                            token_response.expires_in,
                            token_response.refresh_token or refresh_token
                        )
                        return self.access_token
                except Exception as e:
                    print(f"Token refresh failed: {e}")
        
        # Try to setup OAuth client if not already done
        if not self.oauth_client:
            await self.setup_oauth_client()
        
        if not self.oauth_client:
            return None
        
        # Try automated grant types
        
        # 1. Try Client Credentials Grant (best for server-to-server)
        try:
            token_response = await self.oauth_client.client_credentials_grant(
                scope="mcp:read mcp:write",
                resources=[self.mcp_endpoint]
            )
            if token_response:
                self.access_token = token_response.access_token
                return self.access_token
        except Exception as e:
            print(f"Client credentials grant failed: {e}")
        
        # 2. Try Device Authorization Grant if interactive mode
        if interactive:
            try:
                device_response = await self.oauth_client.device_authorization_grant(
                    scope="mcp:read mcp:write"
                )
                if device_response:
                    print(f"\nTo authorize, visit: {device_response['verification_uri']}")
                    print(f"Enter code: {device_response['user_code']}")
                    print("Waiting for authorization...")
                    
                    token_response = await self.oauth_client.poll_device_token(
                        device_response['device_code'],
                        device_response.get('interval', 5),
                        device_response.get('expires_in', 300)
                    )
                    
                    if token_response:
                        self.access_token = token_response.access_token
                        return self.access_token
            except Exception as e:
                print(f"Device authorization grant failed: {e}")
        
        # No automated grant available
        return None
    
    async def _check_auth_required(self) -> bool:
        """Check if the server requires authentication.
        
        Returns:
            True if auth is required (401), False if public (200)
        """
        try:
            # Detect transport type first
            detector = TransportDetector(self.client)
            base_headers = {"MCP-Protocol-Version": "2025-06-18"}
            caps = await detector.detect(self.mcp_endpoint, base_headers)
            
            # For SSE servers, check with appropriate headers
            if caps.primary_transport == TransportType.HTTP_SSE:
                headers = {"Accept": "text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
                # SSE endpoints stay open, so we need special handling
                try:
                    async with self.client.stream("GET", self.mcp_endpoint, headers=headers, timeout=5.0) as response:
                        return response.status_code == 401
                except httpx.ReadTimeout:
                    # Timeout means it's a 200 that stays open
                    return False
            else:
                # For non-SSE servers
                headers = {"Accept": "application/json", "MCP-Protocol-Version": "2025-06-18"}
                response = await self.client.get(self.mcp_endpoint, headers=headers, timeout=5.0)
                return response.status_code == 401
                
        except Exception:
            # If we can't determine, assume auth might be required
            return True