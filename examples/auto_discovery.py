"""Example: Automatic OAuth discovery and client registration."""

import asyncio
import sys
from pathlib import Path

from mcp_http_validator import MCPValidator, ComplianceChecker, EnvManager


async def main():
    """Demonstrate automatic OAuth discovery and registration."""
    
    # Get MCP server URL from command line or use default
    mcp_server = sys.argv[1] if len(sys.argv) > 1 else "https://mcp.example.com"
    
    print(f"MCP HTTP Validator - Automatic OAuth Discovery")
    print("=" * 50)
    print(f"Target server: {mcp_server}")
    print()
    
    # Show current credentials
    env_manager = EnvManager()
    existing_creds = env_manager.get_oauth_credentials(mcp_server)
    
    if existing_creds["client_id"]:
        print(f"Found existing OAuth client: {existing_creds['client_id']}")
        print()
    
    # Create validator with auto-registration enabled
    async with MCPValidator(
        server_url=mcp_server,
        auto_register=True,
        verify_ssl=True,
    ) as validator:
        
        # Step 1: Discover OAuth server
        print("1. Discovering OAuth server from MCP metadata...")
        auth_server = await validator.discover_oauth_server()
        
        if auth_server:
            print(f"   ✓ Found OAuth server: {auth_server}")
        else:
            print("   ✗ No OAuth server found in MCP metadata")
            print("   → Server may not require authentication")
            print()
        
        # Step 2: Setup OAuth client (registers if needed)
        if auth_server:
            print("\n2. Setting up OAuth client...")
            oauth_client = await validator.setup_oauth_client()
            
            if oauth_client and oauth_client.client_id:
                print(f"   ✓ OAuth client ready: {oauth_client.client_id}")
                
                # Check if new registration happened
                new_creds = env_manager.get_oauth_credentials(mcp_server)
                if new_creds["client_id"] != existing_creds["client_id"]:
                    print("   ✓ New client registered and saved to .env")
                    
                    if new_creds["registration_token"]:
                        print("   ✓ RFC 7592 client management enabled")
                else:
                    print("   → Using existing client credentials")
            else:
                print("   ⚠ OAuth client setup failed")
        
        # Step 3: Run validation
        print("\n3. Running MCP validation tests...")
        validation_result = await validator.validate()
        
        # Step 4: Generate compliance report
        checker = ComplianceChecker(validation_result, validator.server_info)
        report = checker.check_compliance()
        
        print(f"\n4. Results:")
        print(f"   Compliance Level: {report.compliance_level}")
        print(f"   Success Rate: {validation_result.success_rate:.1f}%")
        print(f"   Tests Passed: {validation_result.passed_tests}/{validation_result.total_tests}")
        
        # Show OAuth-specific results
        oauth_tests = [
            r for r in validation_result.test_results 
            if r.test_case.category == "oauth"
        ]
        
        if oauth_tests:
            print(f"\n   OAuth Tests:")
            for result in oauth_tests:
                status = "✓" if result.status == "passed" else "✗"
                print(f"   {status} {result.test_case.name}")
                if result.error_message:
                    print(f"      → {result.error_message}")
    
    # Show final credential status
    print("\n5. Credential Management:")
    final_creds = env_manager.get_oauth_credentials(mcp_server)
    
    if final_creds["client_id"]:
        print(f"   ✓ Client ID saved: {final_creds['client_id']}")
        print(f"   ✓ Has secret: {'Yes' if final_creds['client_secret'] else 'No'}")
        print(f"   ✓ RFC 7592 enabled: {'Yes' if final_creds['registration_token'] else 'No'}")
        print(f"\n   Credentials are stored in: {env_manager.env_file.absolute()}")
    else:
        print("   → No OAuth credentials stored")
    
    # List all stored credentials
    all_creds = env_manager.list_credentials()
    if len(all_creds) > 1 or (len(all_creds) == 1 and "DEFAULT" not in all_creds):
        print(f"\n6. All Stored Credentials:")
        for server_key, creds in all_creds.items():
            if server_key != "DEFAULT":
                print(f"   • {server_key}: {creds.get('client_id', 'N/A')}")


if __name__ == "__main__":
    asyncio.run(main())