"""Generic OAuth flow handler that works in any environment."""

import asyncio
import webbrowser
import socket
import os
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlparse, urljoin
import json

from rich.console import Console
from rich.prompt import Prompt

from .oauth import OAuthTestClient, OAuthTokenResponse
from .grant_validator import OAuthGrantValidator, GrantType
from .network_utils import NetworkInfo, OAuthCallbackServer
from .oauth_flow_config import (
    OAuthFlowConfig, 
    RedirectStrategy, 
    EnvironmentDetector,
    determine_redirect_strategy
)
from .env_manager import EnvManager


console = Console()


class GenericOAuthFlow:
    """Generic OAuth flow handler for any environment."""
    
    def __init__(
        self,
        mcp_server_url: str,
        auth_server_url: str,
        config: Optional[OAuthFlowConfig] = None,
    ):
        """Initialize generic OAuth flow.
        
        Args:
            mcp_server_url: MCP server URL (used as resource)
            auth_server_url: OAuth authorization server URL
            config: OAuth flow configuration (auto-detected if None)
        """
        self.mcp_server_url = mcp_server_url
        self.auth_server_url = auth_server_url
        self.config = config or OAuthFlowConfig.from_environment()
        self.env_manager = EnvManager()
        self.callback_server: Optional[OAuthCallbackServer] = None
    
    async def authenticate(
        self,
        scope: str = "mcp:read mcp:write",
        verify_ssl: bool = True,
    ) -> Optional[str]:
        """Run OAuth authentication flow.
        
        Args:
            scope: OAuth scope to request
            verify_ssl: Whether to verify SSL certificates
            
        Returns:
            Access token if successful, None otherwise
        """
        credentials = self.env_manager.get_oauth_credentials(self.mcp_server_url)
        
        # Create OAuth client
        async with OAuthTestClient(
            self.auth_server_url,
            client_id=credentials.get("client_id"),
            client_secret=credentials.get("client_secret"),
            redirect_uri=credentials.get("redirect_uri"),
            verify_ssl=verify_ssl,
        ) as client:
            # Ensure client is registered
            if not client.client_id:
                if not await self._register_client(client, scope):
                    return None
            
            # Get server metadata
            metadata = await client.discover_metadata()
            
            # Validate available grants
            validator = OAuthGrantValidator(client.client)
            grant_results = await validator.validate_all_grants(
                metadata.model_dump(),
                client.client_id,
                client.client_secret,
                test_grants=False  # Just check availability
            )
            
            # Try grants in order of preference
            grant_order = self.config.get_grant_order()
            
            for grant_type in grant_order:
                if grant_type not in [r.grant_type for r in grant_results.values() if r.supported]:
                    continue
                
                if not self.config.suppress_console:
                    console.print(f"\n[dim]Trying {grant_type} grant...[/dim]")
                
                try:
                    token = await self._try_grant(
                        client, grant_type, scope, grant_results
                    )
                    if token:
                        # Save token
                        self.env_manager.save_tokens(
                            self.mcp_server_url,
                            token.access_token,
                            token.expires_in,
                            token.refresh_token
                        )
                        
                        # If we successfully authenticated and don't have redirect URI saved, save it
                        credentials = self.env_manager.get_oauth_credentials(self.mcp_server_url)
                        if client.redirect_uri and not credentials.get("redirect_uri"):
                            self.env_manager.save_oauth_credentials(
                                self.mcp_server_url,
                                credentials["client_id"],
                                credentials.get("client_secret"),
                                credentials.get("registration_token"),
                                client.redirect_uri
                            )
                            if not self.config.suppress_console:
                                console.print(f"[dim]Saved successful redirect URI: {client.redirect_uri}[/dim]")
                        
                        return token.access_token
                except Exception as e:
                    if not self.config.suppress_console:
                        console.print(f"[yellow]Grant failed: {e}[/yellow]")
                    continue
            
            return None
    
    async def _register_client(
        self,
        client: OAuthTestClient,
        scope: str
    ) -> bool:
        """Register OAuth client with appropriate redirect URI."""
        # First try with preferred redirect strategy
        redirect_uri = await self._determine_redirect_uri()
        
        if not self.config.suppress_console:
            console.print(f"[dim]Registering OAuth client with redirect: {redirect_uri}[/dim]")
        
        try:
            client_id, client_secret, reg_token = await client.register_client(
                client_name=f"MCP Validator ({self.mcp_server_url})",
                redirect_uris=[redirect_uri],
                scope=scope,
            )
            
            # Save credentials including redirect URI
            self.env_manager.save_oauth_credentials(
                server_url=self.mcp_server_url,
                client_id=client_id,
                client_secret=client_secret,
                registration_token=reg_token,
                redirect_uri=redirect_uri,
            )
            
            # Update client
            client.client_id = client_id
            client.client_secret = client_secret
            client.redirect_uri = redirect_uri
            
            if not self.config.suppress_console:
                console.print(f"[green]✓[/green] Client registered with {redirect_uri}")
            
            return True
            
        except Exception as e:
            if not self.config.suppress_console:
                console.print(f"[yellow]Registration failed: {e}[/yellow]")
            
            # If we weren't already using OOB, try falling back to it
            if not redirect_uri.startswith("urn:"):
                if not self.config.suppress_console:
                    console.print("[dim]Falling back to out-of-band redirect...[/dim]")
                
                redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
                
                try:
                    client_id, client_secret, reg_token = await client.register_client(
                        client_name=f"MCP Validator ({self.mcp_server_url})",
                        redirect_uris=[redirect_uri],
                        scope=scope,
                    )
                    
                    # Save credentials including OOB redirect URI
                    self.env_manager.save_oauth_credentials(
                        server_url=self.mcp_server_url,
                        client_id=client_id,
                        client_secret=client_secret,
                        registration_token=reg_token,
                        redirect_uri=redirect_uri,
                    )
                    
                    # Update client
                    client.client_id = client_id
                    client.client_secret = client_secret
                    client.redirect_uri = redirect_uri
                    
                    if not self.config.suppress_console:
                        console.print(f"[green]✓[/green] Client registered with OOB fallback")
                    
                    return True
                    
                except Exception as e2:
                    if not self.config.suppress_console:
                        console.print(f"[red]OOB registration also failed: {e2}[/red]")
                    return False
            else:
                # Already was OOB, can't fall back further
                return False
    
    async def _determine_redirect_uri(self) -> str:
        """Determine the best redirect URI based on configuration."""
        strategy = determine_redirect_strategy(self.config)
        
        if strategy == RedirectStrategy.CUSTOM:
            return self.config.custom_redirect_uri or "urn:ietf:wg:oauth:2.0:oob"
        
        elif strategy == RedirectStrategy.ENV:
            return os.getenv("OAUTH_REDIRECT_URI", "urn:ietf:wg:oauth:2.0:oob")
        
        elif strategy == RedirectStrategy.PUBLIC_HOSTNAME:
            hostname = self.config.public_hostname or socket.getfqdn()
            port = self._find_available_port()
            return f"http://{hostname}:{port}/callback"
        
        elif strategy == RedirectStrategy.PUBLIC_IP:
            public_ip = await NetworkInfo.detect_public_ip()
            if public_ip:
                port = self._find_available_port()
                self.callback_server = OAuthCallbackServer(public_ip, port)
                return f"http://{public_ip}:{port}/callback"
            # Fall back to OOB
            return "urn:ietf:wg:oauth:2.0:oob"
        
        elif strategy == RedirectStrategy.LOCALHOST:
            port = self._find_available_port()
            self.callback_server = OAuthCallbackServer("localhost", port)
            return f"http://localhost:{port}/callback"
        
        elif strategy == RedirectStrategy.DOCKER_HOST:
            port = self._find_available_port()
            # Docker Desktop uses host.docker.internal
            return f"http://host.docker.internal:{port}/callback"
        
        elif strategy == RedirectStrategy.DEVICE:
            # Device flow doesn't use redirect
            return "urn:ietf:wg:oauth:2.0:oob"
        
        else:  # OOB or fallback
            return "urn:ietf:wg:oauth:2.0:oob"
    
    def _find_available_port(self) -> int:
        """Find available port in configured range."""
        start, end = self.config.redirect_port_range
        for port in range(start, end):
            if NetworkInfo.find_available_port(port) == port:
                return port
        raise RuntimeError(f"No available ports in range {start}-{end}")
    
    async def _try_grant(
        self,
        client: OAuthTestClient,
        grant_type: str,
        scope: str,
        grant_results: Dict[str, Any]
    ) -> Optional[OAuthTokenResponse]:
        """Try a specific grant type."""
        
        if grant_type == GrantType.CLIENT_CREDENTIALS:
            return await self._try_client_credentials(client, scope)
        
        elif grant_type == GrantType.DEVICE_CODE:
            return await self._try_device_flow(client, scope)
        
        elif grant_type == GrantType.AUTHORIZATION_CODE:
            return await self._try_authorization_code(client, scope)
        
        elif grant_type == GrantType.REFRESH_TOKEN:
            return await self._try_refresh_token(client, scope)
        
        return None
    
    async def _try_client_credentials(
        self,
        client: OAuthTestClient,
        scope: str
    ) -> Optional[OAuthTokenResponse]:
        """Try client credentials grant."""
        if not client.client_secret:
            return None
        
        try:
            return await client.client_credentials_grant(
                scope=scope,
                resources=[self.mcp_server_url]
            )
        except Exception:
            return None
    
    async def _try_device_flow(
        self,
        client: OAuthTestClient,
        scope: str
    ) -> Optional[OAuthTokenResponse]:
        """Try device authorization grant."""
        try:
            # Start device flow
            device_response = await client.device_authorization_grant(scope=scope)
            if not device_response:
                return None
            
            if not self.config.suppress_console:
                console.print("\n[bold]Device Authorization:[/bold]")
                console.print(f"1. Visit: [cyan]{device_response['verification_uri']}[/cyan]")
                console.print(f"2. Enter code: [bold]{device_response['user_code']}[/bold]\n")
            
            # Poll for token
            return await client.poll_device_token(
                device_response['device_code'],
                device_response.get('interval', 5),
                device_response.get('expires_in', 300)
            )
        except Exception:
            return None
    
    async def _try_authorization_code(
        self,
        client: OAuthTestClient,
        scope: str
    ) -> Optional[OAuthTokenResponse]:
        """Try authorization code grant."""
        # Use existing redirect URI from registration, or determine new one
        if client.redirect_uri:
            redirect_uri = client.redirect_uri
        else:
            # For existing clients without saved redirect URI, try OOB first
            # as it's the most common default
            credentials = self.env_manager.get_oauth_credentials(self.mcp_server_url)
            if credentials.get("client_id") and not credentials.get("redirect_uri"):
                if not self.config.suppress_console:
                    console.print("[dim]Existing client without saved redirect URI - trying OOB first[/dim]")
                redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
                client.redirect_uri = redirect_uri
            else:
                redirect_uri = await self._determine_redirect_uri()
                client.redirect_uri = redirect_uri
        
        # Start callback server if needed
        if redirect_uri and redirect_uri.startswith("http://") and "/callback" in redirect_uri:
            # Extract host and port from redirect URI
            from urllib.parse import urlparse
            parsed = urlparse(redirect_uri)
            if parsed.hostname and parsed.port:
                # Create callback server with the exact host/port from registration
                self.callback_server = OAuthCallbackServer(parsed.hostname, parsed.port)
                callback_url = self.callback_server.start()
                if not self.config.suppress_console:
                    console.print(f"[dim]Callback server: {callback_url}[/dim]")
            elif self.callback_server:
                callback_url = self.callback_server.start()
                if not self.config.suppress_console:
                    console.print(f"[dim]Callback server: {callback_url}[/dim]")
        elif self.callback_server:
            callback_url = self.callback_server.start()
            if not self.config.suppress_console:
                console.print(f"[dim]Callback server: {callback_url}[/dim]")
        
        try:
            # Generate auth URL
            auth_url, state, verifier = client.generate_authorization_url(
                scope=scope,
                resources=[self.mcp_server_url],
            )
            
            # Handle authorization
            if self.config.auto_open_browser and not EnvironmentDetector.is_ci():
                if self.config.browser_command:
                    import subprocess
                    subprocess.run([self.config.browser_command, auth_url])
                else:
                    webbrowser.open(auth_url)
            
            if not self.config.suppress_console:
                console.print("\n[bold]Authorization Required:[/bold]")
                console.print(f"Visit: [cyan]{auth_url}[/cyan]\n")
            
            # Get authorization code
            if self.callback_server:
                if not self.config.suppress_console:
                    console.print("[dim]Waiting for authorization callback...[/dim]")
                
                auth_code, error = await self.callback_server.wait_for_code(
                    timeout=self.config.callback_timeout
                )
                
                if error:
                    raise Exception(error)
                    
                if not self.config.suppress_console:
                    console.print(f"[green]✓[/green] Authorization code automatically captured!")
                    console.print(f"[dim]Code: {auth_code[:20]}...[/dim]")
            else:
                # OOB flow
                if not self.config.suppress_console:
                    console.print("After authorizing, find the code:")
                    console.print("- Check the page for displayed code")
                    console.print("- Or check URL for 'code=' parameter")
                    auth_code = Prompt.ask("\nAuthorization code")
                else:
                    return None  # Can't do OOB in suppressed mode
            
            # Exchange for token
            return await client.exchange_code_for_token(
                auth_code,
                code_verifier=verifier,
                resources=[self.mcp_server_url]
            )
            
        finally:
            if self.callback_server:
                self.callback_server.stop()
                self.callback_server = None
    
    async def _try_refresh_token(
        self,
        client: OAuthTestClient,
        scope: str
    ) -> Optional[OAuthTokenResponse]:
        """Try refresh token grant."""
        refresh_token = self.env_manager.get_refresh_token(self.mcp_server_url)
        if not refresh_token:
            return None
        
        try:
            return await client.refresh_token(
                refresh_token,
                scope=scope,
                resources=[self.mcp_server_url]
            )
        except Exception:
            return None


async def generic_oauth_flow(
    mcp_server_url: str,
    auth_server_url: str,
    scope: str = "mcp:read mcp:write",
    verify_ssl: bool = True,
    config: Optional[OAuthFlowConfig] = None,
) -> Optional[str]:
    """Convenience function for generic OAuth flow.
    
    Args:
        mcp_server_url: MCP server URL
        auth_server_url: OAuth server URL
        scope: OAuth scope
        verify_ssl: Whether to verify SSL
        config: Optional configuration
        
    Returns:
        Access token if successful
    """
    flow = GenericOAuthFlow(mcp_server_url, auth_server_url, config)
    return await flow.authenticate(scope, verify_ssl)