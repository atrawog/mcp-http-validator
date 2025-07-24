#!/usr/bin/env python3
"""Example: Test RFC 8707 Resource Indicators compliance."""

import asyncio
import sys
from mcp_http_validator import MCPValidator, OAuthTestClient
from mcp_http_validator.rfc8707 import RFC8707Validator


async def test_rfc8707_compliance():
    """Test OAuth server and MCP server for RFC 8707 compliance."""
    
    # Get servers from command line
    if len(sys.argv) < 3:
        print("Usage: python test_rfc8707.py <oauth-server> <mcp-server>")
        print("Example: python test_rfc8707.py https://auth.example.com https://mcp.example.com")
        return
        
    oauth_server = sys.argv[1]
    mcp_server = sys.argv[2]
    
    print("RFC 8707 Resource Indicators Compliance Test")
    print("=" * 60)
    print(f"OAuth Server: {oauth_server}")
    print(f"MCP Server: {mcp_server}")
    print()
    
    async with OAuthTestClient(oauth_server) as client:
        # Check OAuth server metadata
        print("1. Checking OAuth server metadata...")
        try:
            metadata = await client.discover_metadata()
            
            # Check for resource indicators support
            resource_indicators = metadata.resource_indicators_supported
            print(f"   resource_indicators_supported: {resource_indicators}")
            
            if not resource_indicators:
                print("   ⚠️  WARNING: OAuth server does not advertise RFC 8707 support")
                print("      This means it may not properly handle resource parameters")
            else:
                print("   ✓ OAuth server claims RFC 8707 support")
                
        except Exception as e:
            print(f"   ✗ Failed to get metadata: {e}")
            return
    
    # Now test the actual flow
    print("\n2. Testing authorization flow with resource parameter...")
    print(f"   Requesting access to: {mcp_server}")
    
    # Simulate what would happen in a real OAuth flow
    print("\n3. Expected behavior per RFC 8707:")
    print("   a) Authorization request includes: resource=" + mcp_server)
    print("   b) Token response should have: \"aud\": [\"" + mcp_server + "\"]")
    print("   c) MCP server should validate token audience contains its URL")
    
    print("\n4. Security implications if NOT compliant:")
    print("   • Tokens can be used on ANY service (token confusion attack)")
    print("   • Attacker can obtain token for Service A and use on Service B")
    print("   • No cryptographic binding between token and intended service")
    
    print("\n5. How to test manually:")
    print("   a) Run: mcp-validate flow " + mcp_server)
    print("   b) Complete OAuth flow")
    print("   c) Check if token audience includes MCP server URL")
    print("   d) Check if MCP server validates audience")
    
    print("\n" + "=" * 60)
    print("RECOMMENDATION: Use 'mcp-validate flow' for full RFC 8707 validation")
    print("It will show exactly where the compliance failures occur.")


async def check_token_audience(token: str):
    """Demonstrate how to check token audience."""
    import jwt
    
    print("\nToken Audience Check Example:")
    print("-" * 30)
    
    try:
        # Decode without verification (for demonstration)
        claims = jwt.decode(token, options={"verify_signature": False})
        
        aud = claims.get("aud", [])
        if isinstance(aud, str):
            aud = [aud]
            
        print(f"Token audience claim: {aud}")
        
        if not aud:
            print("⚠️  WARNING: Token has NO audience restriction!")
            print("   This token can be used on ANY service!")
        else:
            print("✓ Token is restricted to: " + ", ".join(aud))
            
        return aud
        
    except Exception as e:
        print(f"Failed to decode token: {e}")
        return []


if __name__ == "__main__":
    asyncio.run(test_rfc8707_compliance())