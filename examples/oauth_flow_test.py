"""Example: Test OAuth flow with MCP server."""

import asyncio
import os
from typing import List, Optional

from mcp_http_validator import MCPValidator, OAuthTestClient, ComplianceChecker, EnvManager


async def test_oauth_flow(mcp_server_url: str):
    """Test OAuth authorization flow with automatic discovery."""
    print(f"Testing OAuth flow for MCP server: {mcp_server_url}")
    print("-" * 70)
    
    # Create validator to discover OAuth server
    async with MCPValidator(mcp_server_url) as validator:
        # Discover OAuth server from MCP metadata
        print("\n1. Discovering OAuth server from MCP metadata...")
        auth_server_url = await validator.discover_oauth_server()
        
        if not auth_server_url:
            print("✗ Failed to discover OAuth server")
            return
        
        print(f"✓ Found OAuth server: {auth_server_url}")
        
        # Check for existing credentials
        env_manager = EnvManager()
        credentials = env_manager.get_oauth_credentials(mcp_server_url)
        
        if not credentials["client_id"]:
            print("\n2. No OAuth client found, registering new client...")
            oauth_client = await validator.setup_oauth_client()
            if oauth_client:
                print(f"✓ Client registered: {oauth_client.client_id}")
                credentials = env_manager.get_oauth_credentials(mcp_server_url)
            else:
                print("✗ Failed to register client")
                return
        else:
            print(f"\n2. Using existing client: {credentials['client_id']}")
    
    # Now test OAuth flow with the client
    async with OAuthTestClient(
        auth_server_url=auth_server_url,
        client_id=credentials["client_id"],
        client_secret=credentials["client_secret"],
        registration_access_token=credentials["registration_token"],
    ) as client:
        # Discover metadata
        print("\n3. Checking OAuth server metadata...")
        metadata = await client.discover_metadata()
        
        print(f"   Issuer: {metadata.issuer}")
        print(f"   Resource indicators: {'✓' if metadata.resource_indicators_supported else '✗'}")
        print(f"   MCP scopes: {'✓' if 'mcp:read' in (metadata.scopes_supported or []) else '✗'}")
        
        # Generate authorization URL
        print("\n4. Generating authorization URL...")
        auth_url, state, verifier = client.generate_authorization_url(
            scope="mcp:read mcp:write",
            resources=[mcp_server_url],
        )
        
        print(f"\nPlease visit this URL to authorize:")
        print(f"{auth_url}")
        print(f"\nAfter authorization, you'll be redirected to a URL containing a 'code' parameter.")
        
        # Interactive flow
        code = input("\nEnter the authorization code from the redirect URL: ")
        
        if code:
            print("\nExchanging code for token...")
            try:
                token_response = await client.exchange_code_for_token(
                    code=code,
                    code_verifier=verifier,
                    resources=[mcp_server_url],
                )
                
                print(f"✓ Access token obtained!")
                print(f"  Token: {token_response.access_token[:20]}...")
                print(f"  Expires in: {token_response.expires_in} seconds")
                
                # Validate token audience
                is_valid, error = client.validate_token_audience(
                    token_response.access_token,
                    [mcp_server_url],
                )
                
                if is_valid:
                    print("✓ Token audience is valid")
                else:
                    print(f"✗ Token audience validation failed: {error}")
                
                # Test MCP server access
                print(f"\nTesting access to {mcp_server_url}...")
                success, error, details = await client.test_mcp_server_with_token(
                    mcp_server_url,
                    token_response.access_token,
                )
                
                if success:
                    print("✓ MCP server access successful!")
                else:
                    print(f"✗ MCP server access failed: {error}")
                    
            except Exception as e:
                print(f"✗ Token exchange failed: {e}")


async def test_client_management(mcp_server_url: str):
    """Test RFC 7592 client management features."""
    print(f"\nTesting OAuth client management for: {mcp_server_url}")
    print("-" * 70)
    
    env_manager = EnvManager()
    credentials = env_manager.get_oauth_credentials(mcp_server_url)
    
    if not credentials["registration_token"]:
        print("✗ No registration token available for client management")
        return
    
    # Discover OAuth server
    async with MCPValidator(mcp_server_url) as validator:
        auth_server_url = await validator.discover_oauth_server()
        
        if not auth_server_url:
            print("✗ Failed to discover OAuth server")
            return
    
    # Create OAuth client with management token
    async with OAuthTestClient(
        auth_server_url=auth_server_url,
        client_id=credentials["client_id"],
        client_secret=credentials["client_secret"],
        registration_access_token=credentials["registration_token"],
    ) as client:
        # Get current configuration
        print("\n1. Getting client configuration...")
        try:
            config = await client.get_client_configuration()
            print("✓ Current configuration:")
            print(f"  Client name: {config.get('client_name')}")
            print(f"  Redirect URIs: {config.get('redirect_uris')}")
            print(f"  Scopes: {config.get('scope')}")
        except Exception as e:
            print(f"✗ Failed to get configuration: {e}")
            return
        
        # Update configuration
        print("\n2. Updating client configuration...")
        try:
            updated = await client.update_client_configuration({
                "client_name": "Updated MCP Validator Client",
            })
            print("✓ Configuration updated")
            
            # Save new token if changed
            if updated.get("registration_access_token") != credentials["registration_token"]:
                env_manager.save_oauth_credentials(
                    mcp_server_url,
                    updated["client_id"],
                    updated.get("client_secret"),
                    updated.get("registration_access_token"),
                )
                print("✓ New credentials saved to .env")
                
        except Exception as e:
            print(f"✗ Failed to update configuration: {e}")


async def main():
    """Run OAuth flow tests."""
    # Get server from environment or use default
    server_url = os.getenv("MCP_SERVER_URL", "https://mcp.example.com")
    
    # Test basic OAuth flow
    await test_oauth_flow(server_url)
    
    # Optionally test client management
    choice = input("\nTest RFC 7592 client management? (y/n): ")
    if choice.lower() == 'y':
        await test_client_management(server_url)


if __name__ == "__main__":
    asyncio.run(main())