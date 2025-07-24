#!/usr/bin/env python3
"""Example: How to use access tokens with mcp-validate."""

import asyncio
import subprocess
import sys
import re
from pathlib import Path


def extract_token_from_oauth(output: str) -> str:
    """Extract access token from oauth command output."""
    # Look for "Access token: xxx..."
    match = re.search(r'Access token: ([^\s]+)', output)
    if match:
        # The output shows truncated token with "..."
        # In real usage, you'd copy the full token from the terminal
        return match.group(1).rstrip('.')
    return None


async def main():
    """Demonstrate how to use tokens with validate command."""
    
    if len(sys.argv) < 2:
        print("Usage: python validate_with_token.py <mcp-server-url>")
        print("Example: python validate_with_token.py https://echo-stateless.atratest.org/mcp")
        return
        
    mcp_server = sys.argv[1]
    
    print("MCP Validator - Access Token Usage Example")
    print("=" * 60)
    print()
    
    # Check current situation
    print("1. Checking current OAuth credentials...")
    env_file = Path(".env")
    if env_file.exists():
        content = env_file.read_text()
        if "OAUTH_CLIENT_ID" in content:
            print("   ✓ OAuth client credentials found in .env")
        else:
            print("   ✗ No OAuth client credentials - run validate first to register")
            return
    
    print("\n2. Understanding the token flow:")
    print("   • OAuth credentials (client_id/secret) identify your app")
    print("   • Access tokens authorize specific requests") 
    print("   • Tokens expire (usually 30-60 minutes)")
    print("   • Validator needs fresh tokens for auth tests")
    
    print("\n3. Getting an access token:")
    print("   Option A: Run oauth command interactively")
    print(f"   $ pixi run mcp-validate flow {mcp_server}")
    print("   [Complete OAuth flow in browser]")
    print("   [Copy the full access token from output]")
    
    print("\n   Option B: If server supports client_credentials grant")
    print("   [Automatic - but auth.atratest.org doesn't support this]")
    
    print("\n4. Using the token with validate:")
    print("   Method 1 - Command line:")
    print(f'   $ pixi run mcp-validate validate {mcp_server} --token "eyJhbG..."')
    
    print("\n   Method 2 - Environment variable:")
    print('   $ export MCP_ACCESS_TOKEN="eyJhbG..."')
    print(f'   $ pixi run mcp-validate validate {mcp_server}')
    
    print("\n5. Why auth tests show as SKIPPED without token:")
    print("   • No token provided via --token or MCP_ACCESS_TOKEN")
    print("   • Client credentials grant not supported by OAuth server")
    print("   • Validator correctly marks as SKIPPED (not FAILED)")
    print("   • This differentiates from real auth failures")
    
    print("\n6. Best practices:")
    print("   • DON'T save access tokens in .env (they expire)")
    print("   • DO save client credentials in .env (long-lived)")
    print("   • Get fresh tokens when needed")
    print("   • Use refresh tokens for long sessions")
    
    print("\n" + "=" * 60)
    print("TIP: For automated testing, ask OAuth server admin to enable")
    print("     client_credentials grant type. This allows the validator")
    print("     to get tokens automatically without user interaction.")


if __name__ == "__main__":
    asyncio.run(main())