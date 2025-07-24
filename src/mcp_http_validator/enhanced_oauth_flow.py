"""Enhanced OAuth flow with dynamic redirect URI and grant type validation."""

import asyncio
from typing import Optional, Tuple, Dict, Any
from rich.console import Console
from rich.prompt import Prompt

from .oauth import OAuthTestClient
from .grant_validator import OAuthGrantValidator, GrantType
from .network_utils import get_best_redirect_uri, OAuthCallbackServer, NetworkInfo
from .env_manager import EnvManager


console = Console()


async def enhanced_oauth_flow(
    mcp_server_url: str,
    auth_server_url: str,
    scope: str = "mcp:read mcp:write",
    verify_ssl: bool = True,
    force_public_callback: bool = True,
) -> Optional[str]:
    """Enhanced OAuth flow with automatic redirect URI selection and grant validation.
    
    Args:
        mcp_server_url: The MCP server URL (used as resource)
        auth_server_url: OAuth authorization server URL
        scope: OAuth scope to request
        verify_ssl: Whether to verify SSL certificates
        force_public_callback: Whether to force using public IP for callback
        
    Returns:
        Access token if successful, None otherwise
    """
    env_manager = EnvManager()
    credentials = env_manager.get_oauth_credentials(mcp_server_url)
    
    # Check if client is registered
    if not credentials["client_id"]:
        console.print("[yellow]No OAuth client registered. Attempting registration...[/yellow]")
        
        # Determine redirect URI before registration
        redirect_uri, _ = await get_best_redirect_uri(prefer_public=force_public_callback)
        
        async with OAuthTestClient(auth_server_url, verify_ssl=verify_ssl) as reg_client:
            await reg_client.discover_metadata()
            
            # Register with dynamic redirect URI
            reg_client.redirect_uri = redirect_uri
            client_id, client_secret, reg_token = await reg_client.register_client(
                redirect_uris=[redirect_uri]  # Register with our chosen redirect URI
            )
            
            console.print(f"[green]✓[/green] Client registered with redirect URI: {redirect_uri}")
            
            # Save credentials
            env_manager.save_oauth_credentials(
                server_url=mcp_server_url,
                client_id=client_id,
                client_secret=client_secret,
                registration_token=reg_token,
            )
            
            credentials["client_id"] = client_id
            credentials["client_secret"] = client_secret
    
    # Create OAuth client
    async with OAuthTestClient(
        auth_server_url,
        client_id=credentials["client_id"],
        client_secret=credentials["client_secret"],
        verify_ssl=verify_ssl,
    ) as client:
        # Discover metadata
        metadata = await client.discover_metadata()
        
        # Validate grant types
        console.print("\n[bold]Validating OAuth Grant Types...[/bold]")
        validator = OAuthGrantValidator(client.client)
        grant_results = await validator.validate_all_grants(
            metadata.model_dump(),
            client.client_id,
            client.client_secret,
            test_grants=True
        )
        
        # Display grant validation results
        for grant_type, result in grant_results.items():
            if result.supported:
                icon = "✓" if result.success else "○"
                color = "green" if result.success else "yellow"
                console.print(f"[{color}]{icon}[/{color}] {grant_type}: {result.recommendation or 'Supported'}")
                if result.error:
                    console.print(f"  [red]Error: {result.error}[/red]")
        
        # Check if client credentials is available and working
        client_creds = grant_results.get(GrantType.CLIENT_CREDENTIALS)
        if client_creds and client_creds.supported and client_creds.success:
            console.print("\n[green]✓[/green] Client credentials grant available - no user interaction needed!")
            use_client_creds = Prompt.ask(
                "Use client credentials grant?",
                choices=["y", "n"],
                default="y"
            )
            
            if use_client_creds == "y":
                # Use client credentials flow
                token_response = await client.client_credentials_grant(
                    scope=scope,
                    resources=[mcp_server_url]
                )
                if token_response:
                    return token_response.access_token
        
        # Check if device flow is available
        device_flow = grant_results.get(GrantType.DEVICE_CODE)
        if device_flow and device_flow.supported:
            console.print("\n[yellow]Device flow is supported but not yet implemented[/yellow]")
        
        # Fall back to authorization code flow
        console.print("\n[bold]Starting Authorization Code Flow...[/bold]")
        
        # Determine best redirect URI
        console.print("[dim]Detecting network configuration...[/dim]")
        public_ip = await NetworkInfo.detect_public_ip()
        if public_ip:
            console.print(f"[green]✓[/green] Public IP detected: {public_ip}")
        else:
            console.print("[yellow]○[/yellow] No public IP detected - will use localhost or OOB")
        
        redirect_uri, callback_server = await get_best_redirect_uri(prefer_public=force_public_callback)
        
        # Update client redirect URI if different from registered
        if redirect_uri != client.redirect_uri:
            client.redirect_uri = redirect_uri
        
        # Start callback server if using one
        if callback_server:
            callback_url = callback_server.start()
            console.print(f"[green]✓[/green] Callback server started at: {callback_url}")
            console.print("[dim]Waiting for authorization callback...[/dim]")
        
        try:
            # Generate authorization URL
            auth_url, state, verifier = client.generate_authorization_url(
                scope=scope,
                resources=[mcp_server_url],
            )
            
            console.print("\n[bold]Authorization Required:[/bold]")
            console.print(f"1. Open this URL in your browser:\n   [cyan]{auth_url}[/cyan]\n")
            
            if callback_server:
                console.print("2. Authorize the application")
                console.print("3. You will be redirected back automatically\n")
                
                # Wait for callback
                auth_code, error = await callback_server.wait_for_code(timeout=300)
                
                if error:
                    console.print(f"[red]✗[/red] Authorization failed: {error}")
                    return None
                    
                console.print(f"[green]✓[/green] Authorization code received!")
                
            else:
                # OOB flow
                console.print("2. After authorizing, you'll see an authorization code")
                console.print("   (Check the URL bar for 'code=' parameter if not displayed)")
                console.print("3. Enter the code below\n")
                
                auth_code = Prompt.ask("Authorization code")
            
            # Exchange code for token
            console.print("\n[dim]Exchanging authorization code for access token...[/dim]")
            token_response = await client.exchange_code_for_token(
                auth_code,
                code_verifier=verifier,
                resources=[mcp_server_url]
            )
            
            console.print("[green]✓[/green] Access token obtained successfully!")
            
            # Save tokens
            env_manager.save_tokens(
                mcp_server_url,
                token_response.access_token,
                token_response.expires_in,
                token_response.refresh_token
            )
            
            return token_response.access_token
            
        finally:
            # Stop callback server if running
            if callback_server:
                callback_server.stop()
                console.print("[dim]Callback server stopped[/dim]")