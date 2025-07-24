#!/usr/bin/env python3
"""Example: Token management with automatic refresh and validation."""

import asyncio
import sys
import time
from mcp_http_validator import MCPValidator, OAuthTestClient, EnvManager


async def check_and_manage_tokens(mcp_server_url: str):
    """Check token status and demonstrate various token management scenarios."""
    
    print(f"Token Management for: {mcp_server_url}")
    print("=" * 60)
    
    env_manager = EnvManager()
    
    # Discover OAuth server
    async with MCPValidator(mcp_server_url, auto_register=False) as validator:
        print("\n1. Discovering OAuth server...")
        auth_server_url = await validator.discover_oauth_server()
        
        if not auth_server_url:
            print("   ✗ Failed to discover OAuth server")
            return
        
        print(f"   ✓ Found: {auth_server_url}")
    
    # Get credentials
    credentials = env_manager.get_oauth_credentials(mcp_server_url)
    if not credentials["client_id"]:
        print("\n✗ No OAuth client found. Run 'mcp-validate client register' first.")
        return
    
    print(f"\n2. OAuth client: {credentials['client_id']}")
    
    # Check token status
    print("\n3. Token Status:")
    
    # Get token info
    server_key = mcp_server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").upper()
    access_token = env_manager.get(f"OAUTH_ACCESS_TOKEN_{server_key}")
    expires_at = env_manager.get(f"OAUTH_TOKEN_EXPIRES_AT_{server_key}")
    refresh_token = env_manager.get(f"OAUTH_REFRESH_TOKEN_{server_key}")
    
    if not access_token:
        print("   ✗ No access token found")
        print("   → Run 'mcp-validate flow' to get one")
        return
    
    print(f"   Access token: {access_token[:20]}...")
    
    # Check expiration
    if expires_at:
        try:
            exp_time = int(expires_at)
            remaining = exp_time - int(time.time())
            
            if remaining > 0:
                if remaining > 3600:
                    time_left = f"{int(remaining/3600)}h {int((remaining%3600)/60)}m"
                elif remaining > 60:
                    time_left = f"{int(remaining/60)}m"
                else:
                    time_left = f"{remaining}s"
                print(f"   Status: ✓ Valid (expires in {time_left})")
            else:
                print(f"   Status: ⚠ Expired {int(-remaining/60)} minutes ago")
        except ValueError:
            print("   Status: ? Invalid expiration time")
    else:
        print("   Status: ? No expiration info")
    
    print(f"   Refresh token: {'✓ Available' if refresh_token else '✗ Not available'}")
    
    # Test token with server
    print("\n4. Testing token with MCP server...")
    async with OAuthTestClient(
        auth_server_url,
        client_id=credentials["client_id"],
        client_secret=credentials["client_secret"],
    ) as client:
        success, error, details = await client.test_mcp_server_with_token(
            mcp_server_url,
            access_token,
        )
        
        if success:
            print("   ✓ Token accepted by server")
        else:
            print(f"   ✗ Token rejected: {error}")
            
            # If token rejected and we have refresh token, try refresh
            if refresh_token and remaining <= 0:
                print("\n5. Attempting automatic token refresh...")
                try:
                    await client.discover_metadata()
                    token_response = await client.refresh_token(refresh_token)
                    
                    print("   ✓ Token refreshed successfully")
                    print(f"   New token: {token_response.access_token[:20]}...")
                    print(f"   Expires in: {token_response.expires_in} seconds")
                    
                    # Save new tokens
                    env_manager.save_tokens(
                        mcp_server_url,
                        token_response.access_token,
                        token_response.expires_in,
                        token_response.refresh_token or refresh_token
                    )
                    print("   ✓ New tokens saved to .env")
                    
                    # Test new token
                    success, error, details = await client.test_mcp_server_with_token(
                        mcp_server_url,
                        token_response.access_token,
                    )
                    
                    if success:
                        print("   ✓ New token works!")
                    else:
                        print(f"   ✗ New token still rejected: {error}")
                        
                except Exception as e:
                    print(f"   ✗ Refresh failed: {e}")
                    print("   → Run 'mcp-validate flow' for new token")
    
    # Recommendations
    print("\n" + "=" * 60)
    print("Token Management Commands:")
    print("• mcp-validate flow <server>         - Get new token (checks existing first)")
    print("• mcp-validate flow <server> --force - Force new token")
    print("• mcp-validate tokens show <server>  - Show token details")
    print("• mcp-validate tokens refresh <server> - Manual refresh")
    print("• mcp-validate tokens clear <server>   - Remove tokens")


async def simulate_expired_token(mcp_server_url: str):
    """Simulate an expired token scenario for testing."""
    print("\n\nSimulating Expired Token Scenario")
    print("=" * 60)
    
    env_manager = EnvManager()
    
    # Temporarily set token to expired
    server_key = mcp_server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").upper()
    current_expires = env_manager.get(f"OAUTH_TOKEN_EXPIRES_AT_{server_key}")
    
    if current_expires:
        # Set to 1 hour ago
        expired_time = int(time.time()) - 3600
        env_manager.update({f"OAUTH_TOKEN_EXPIRES_AT_{server_key}": str(expired_time)})
        print("✓ Temporarily set token as expired")
        
        # Run check
        await check_and_manage_tokens(mcp_server_url)
        
        # Restore original
        env_manager.update({f"OAUTH_TOKEN_EXPIRES_AT_{server_key}": current_expires})
        print("\n✓ Restored original expiration time")


async def main():
    if len(sys.argv) < 2:
        print("Usage: python token_management.py <mcp-server-url> [--simulate-expired]")
        print("Example: python token_management.py https://mcp.example.com")
        return
    
    mcp_server_url = sys.argv[1]
    simulate_expired = "--simulate-expired" in sys.argv
    
    await check_and_manage_tokens(mcp_server_url)
    
    if simulate_expired:
        await simulate_expired_token(mcp_server_url)


if __name__ == "__main__":
    asyncio.run(main())