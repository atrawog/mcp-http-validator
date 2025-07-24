#!/usr/bin/env python3
"""Example: Programmatic OAuth client registration with full RFC validation."""

import asyncio
import sys
from mcp_http_validator import MCPValidator, OAuthTestClient, EnvManager
from mcp_http_validator.rfc7591 import RFC7591Validator, RFC7592Validator


async def register_client_with_validation(mcp_server_url: str, validate_rfc7592: bool = False):
    """Register an OAuth client with full RFC 7591/7592 validation."""
    
    print(f"Registering OAuth client for: {mcp_server_url}")
    print("=" * 60)
    
    env_manager = EnvManager()
    
    # Step 1: Discover OAuth server
    async with MCPValidator(mcp_server_url, auto_register=False) as validator:
        print("\n1. Discovering OAuth server...")
        auth_server_url = await validator.discover_oauth_server()
        
        if not auth_server_url:
            print("   ✗ Failed to discover OAuth server")
            return None
        
        print(f"   ✓ Found: {auth_server_url}")
    
    # Step 2: Check OAuth server metadata
    async with OAuthTestClient(auth_server_url) as client:
        print("\n2. Checking OAuth server metadata...")
        try:
            metadata = await client.discover_metadata()
            print("   ✓ Metadata retrieved successfully")
            
            if not metadata.registration_endpoint:
                print("   ✗ No registration endpoint - server doesn't support RFC 7591")
                return None
            
            print(f"   ✓ Registration endpoint: {metadata.registration_endpoint}")
            
        except Exception as e:
            print(f"   ✗ Failed to get metadata: {e}")
            return None
        
        # Step 3: Prepare registration request
        print("\n3. Preparing registration request...")
        registration_data = {
            "client_name": f"MCP Validator for {mcp_server_url}",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"],
            "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
            "response_types": ["code"],
            "scope": "mcp:read mcp:write",
            "software_id": "mcp-http-validator",
            "software_version": "0.1.0",
            "application_type": "native",
            "token_endpoint_auth_method": "client_secret_post",
        }
        
        # Validate request
        request_validation = RFC7591Validator.validate_registration_request(registration_data)
        print(f"   Request validation: {'✓ Valid' if request_validation.valid else '✗ Invalid'}")
        
        if not request_validation.valid:
            print("\n   Request validation errors:")
            for error in request_validation.errors:
                print(f"   - {error}")
            return None
        
        # Step 4: Register client
        print("\n4. Registering client...")
        try:
            response = await client.client.post(
                str(metadata.registration_endpoint),
                json=registration_data,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            
            response_data = response.json()
            print("   ✓ Registration successful")
            
        except Exception as e:
            print(f"   ✗ Registration failed: {e}")
            return None
        
        # Step 5: Validate response
        print("\n5. Validating registration response...")
        response_validation = RFC7591Validator.validate_registration_response(
            response_data,
            registration_data
        )
        
        print(f"   Response validation: {'✓ Valid' if response_validation.valid else '✗ Invalid'}")
        
        if response_validation.errors:
            print("\n   Response validation errors:")
            for error in response_validation.errors:
                print(f"   - {error}")
        
        # Extract credentials
        client_id = response_data.get("client_id")
        client_secret = response_data.get("client_secret")
        reg_token = response_data.get("registration_access_token")
        reg_uri = response_data.get("registration_client_uri")
        
        print(f"\n   Client ID: {client_id}")
        print(f"   Has secret: {'Yes' if client_secret else 'No'}")
        print(f"   Has registration token: {'Yes' if reg_token else 'No'}")
        print(f"   Management URI: {reg_uri if reg_uri else 'None'}")
        
        # Step 6: Test RFC 7592 if requested
        if validate_rfc7592 and reg_token and reg_uri:
            print("\n6. Testing RFC 7592 management protocol...")
            
            rfc7592_result = await RFC7592Validator.validate_management_support(
                client.client,
                reg_uri,
                reg_token,
                client_id
            )
            
            print(f"   Read (GET): {'✓' if rfc7592_result.read_supported else '✗'}")
            print(f"   Update (PUT): {'✓' if rfc7592_result.update_supported else '✗'}")
            print(f"   RFC 7592 compliant: {'✓' if rfc7592_result.valid else '✗'}")
        
        # Step 7: Save credentials
        print("\n7. Saving credentials...")
        env_manager.save_oauth_credentials(
            mcp_server_url,
            client_id,
            client_secret,
            reg_token,
        )
        print("   ✓ Credentials saved to .env")
        
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "registration_token": reg_token,
            "registration_uri": reg_uri,
            "auth_server": auth_server_url
        }


async def main():
    if len(sys.argv) < 2:
        print("Usage: python programmatic_registration.py <mcp-server-url> [--validate-rfc7592]")
        print("Example: python programmatic_registration.py https://mcp.example.com")
        return
    
    mcp_server_url = sys.argv[1]
    validate_rfc7592 = "--validate-rfc7592" in sys.argv
    
    result = await register_client_with_validation(mcp_server_url, validate_rfc7592)
    
    if result:
        print("\n" + "=" * 60)
        print("Registration completed successfully!")
        print(f"OAuth server: {result['auth_server']}")
        print(f"Client ID: {result['client_id']}")
        print("\nNext steps:")
        print(f"1. Get token: mcp-validate flow {mcp_server_url}")
        print(f"2. Run tests: mcp-validate validate {mcp_server_url}")
    else:
        print("\n" + "=" * 60)
        print("Registration failed. Check the errors above.")


if __name__ == "__main__":
    asyncio.run(main())