"""Example: Test automated authentication with client credentials grant."""

import asyncio
import sys

from mcp_http_validator import MCPValidator, OAuthTestClient


async def test_grant_type_support():
    """Check which OAuth grant types are supported by a server."""
    
    # Get OAuth server URL from command line or use default
    auth_server = sys.argv[1] if len(sys.argv) > 1 else "https://auth.example.com"
    
    print(f"OAuth Grant Type Support Test")
    print("=" * 50)
    print(f"OAuth Server: {auth_server}")
    print()
    
    try:
        # Create OAuth client
        async with OAuthTestClient(auth_server) as client:
            # Discover metadata
            print("Discovering server metadata...")
            metadata = await client.discover_metadata()
            
            # Check supported grant types
            grant_types = metadata.grant_types_supported or ["authorization_code"]
            print(f"\nSupported grant types:")
            for grant in grant_types:
                print(f"  • {grant}")
            
            # Check if client credentials is supported
            if "client_credentials" in grant_types:
                print("\n✓ Client Credentials Grant is supported!")
                print("  → Validator can obtain tokens automatically")
            else:
                print("\n✗ Client Credentials Grant NOT supported")
                print("  → Manual authentication will be required")
            
            # Check other automated grant types
            if "urn:ietf:params:oauth:grant-type:device_code" in grant_types:
                print("\n✓ Device Authorization Grant is supported!")
                print("  → Interactive token acquisition available")
            
            # Check for device authorization endpoint
            device_endpoint = getattr(metadata, "device_authorization_endpoint", None)
            if device_endpoint:
                print(f"\nDevice authorization endpoint: {device_endpoint}")
            
            # Check MCP-specific configuration
            print(f"\nMCP Configuration:")
            scopes = set(metadata.scopes_supported or [])
            mcp_scopes = scopes & {"mcp:read", "mcp:write", "mcp:admin"}
            if mcp_scopes:
                print(f"  MCP Scopes: {', '.join(mcp_scopes)}")
            else:
                print("  MCP Scopes: None found")
            
            if metadata.resource_indicators_supported:
                print("  Resource Indicators: Supported (RFC 8707)")
            else:
                print("  Resource Indicators: Not supported")
                
    except Exception as e:
        print(f"\nError: {e}")
        print("\nThis might mean:")
        print("  • The server doesn't have OAuth metadata endpoint")
        print("  • The server is not reachable")
        print("  • The URL is incorrect")


async def test_automated_validation():
    """Demonstrate automated validation with token acquisition."""
    
    mcp_server = sys.argv[2] if len(sys.argv) > 2 else "https://mcp.example.com"
    
    print(f"\n\nAutomated MCP Validation Test")
    print("=" * 50)
    print(f"MCP Server: {mcp_server}")
    print()
    
    async with MCPValidator(
        server_url=mcp_server,
        auto_register=True,
        verify_ssl=True,
    ) as validator:
        # The validator will automatically:
        # 1. Discover OAuth server
        # 2. Register client if needed
        # 3. Attempt client credentials grant
        # 4. Run all tests
        
        print("Running validation with automated token acquisition...")
        result = await validator.validate()
        
        print(f"\nResults:")
        print(f"  Total Tests: {result.total_tests}")
        print(f"  Passed: {result.passed_tests}")
        print(f"  Failed: {result.failed_tests}")
        print(f"  Skipped: {result.skipped_tests}")
        
        # Show auth-related test results
        auth_tests = [
            r for r in result.test_results 
            if r.test_case.id in ["auth-success", "token-audience", "sse-support"]
        ]
        
        if auth_tests:
            print(f"\nAuthentication-Required Tests:")
            for test in auth_tests:
                status_map = {
                    "passed": "✓ PASSED",
                    "failed": "✗ FAILED", 
                    "skipped": "⊘ SKIPPED",
                    "error": "⚠ ERROR"
                }
                status = status_map.get(test.status, test.status)
                print(f"  {test.test_case.name}: {status}")
                
                if test.status == "skipped":
                    suggestion = test.details.get("suggestion", "")
                    if suggestion:
                        print(f"    → {suggestion}")


async def main():
    """Run both tests."""
    if len(sys.argv) < 2:
        print("Usage: python test_automated_auth.py <oauth-server-url> [mcp-server-url]")
        print("Example: python test_automated_auth.py https://auth.example.com https://mcp.example.com")
        return
    
    await test_grant_type_support()
    
    if len(sys.argv) > 2:
        await test_automated_validation()


if __name__ == "__main__":
    asyncio.run(main())