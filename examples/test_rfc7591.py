#!/usr/bin/env python3
"""Example: Test RFC 7591/7592 Dynamic Client Registration compliance."""

import asyncio
import sys
import json
from mcp_http_validator import OAuthTestClient
from mcp_http_validator.rfc7591 import RFC7591Validator, RFC7592Validator


async def test_rfc7591_compliance():
    """Test OAuth server for RFC 7591 Dynamic Client Registration compliance."""
    
    # Get OAuth server from command line
    if len(sys.argv) < 2:
        print("Usage: python test_rfc7591.py <oauth-server>")
        print("Example: python test_rfc7591.py https://auth.example.com")
        return
        
    oauth_server = sys.argv[1]
    
    print("RFC 7591/7592 Dynamic Client Registration Compliance Test")
    print("=" * 60)
    print(f"OAuth Server: {oauth_server}")
    print()
    
    async with OAuthTestClient(oauth_server) as client:
        # Discover metadata
        print("1. Checking OAuth server metadata...")
        try:
            metadata = await client.discover_metadata()
            
            # Check for registration endpoint
            if metadata.registration_endpoint:
                print(f"   ✓ Registration endpoint: {metadata.registration_endpoint}")
            else:
                print("   ✗ No registration endpoint found")
                print("   Server does not support RFC 7591 Dynamic Client Registration")
                return
                
        except Exception as e:
            print(f"   ✗ Failed to get metadata: {e}")
            return
    
        # Test various registration scenarios
        print("\n2. Testing client registration scenarios...")
        
        # Scenario 1: Basic registration
        print("\n   a) Basic client registration:")
        basic_request = {
            "client_name": "RFC 7591 Test Client",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        }
        
        # Validate request
        request_validation = RFC7591Validator.validate_registration_request(basic_request)
        print(f"      Request validation: {'✓ Valid' if request_validation.valid else '✗ Invalid'}")
        if request_validation.errors:
            for error in request_validation.errors:
                print(f"        Error: {error}")
        
        # Scenario 2: Full featured registration
        print("\n   b) Full featured client registration:")
        full_request = {
            "client_name": "RFC 7591 Full Test Client",
            "redirect_uris": ["https://app.example.com/callback", "urn:ietf:wg:oauth:2.0:oob"],
            "grant_types": ["authorization_code", "client_credentials", "refresh_token"],
            "response_types": ["code"],
            "scope": "read write admin",
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": "web",
            "contacts": ["admin@example.com"],
            "client_uri": "https://app.example.com",
            "logo_uri": "https://app.example.com/logo.png",
            "tos_uri": "https://app.example.com/terms",
            "policy_uri": "https://app.example.com/privacy",
            "software_id": "example-app",
            "software_version": "1.0.0"
        }
        
        # Validate request
        request_validation = RFC7591Validator.validate_registration_request(full_request)
        print(f"      Request validation: {'✓ Valid' if request_validation.valid else '✗ Invalid'}")
        if request_validation.warnings:
            for warning in request_validation.warnings:
                print(f"        Warning: {warning}")
        
        # Scenario 3: Invalid registration
        print("\n   c) Invalid client registration (testing error handling):")
        invalid_request = {
            "client_name": "Invalid Test Client",
            "redirect_uris": [],  # Empty array - invalid
            "grant_types": ["invalid_grant"],  # Invalid grant type
            "token_endpoint_auth_method": "invalid_method",  # Invalid auth method
            "application_type": "invalid_type"  # Invalid app type
        }
        
        # Validate request
        request_validation = RFC7591Validator.validate_registration_request(invalid_request)
        print(f"      Request validation: {'✓ Valid' if request_validation.valid else '✗ Invalid'}")
        if request_validation.errors:
            for error in request_validation.errors:
                print(f"        Error: {error}")
        
        print("\n3. RFC 7591 Compliance Summary:")
        print("   Required features:")
        print("   • Registration endpoint: " + ("✓" if metadata.registration_endpoint else "✗"))
        print("   • Accept client metadata: Test with actual registration")
        print("   • Return client_id: Test with actual registration")
        print("   • Support standard parameters: Test with actual registration")
        
        print("\n4. RFC 7592 (Management Protocol) Support:")
        print("   • Requires registration_access_token in response")
        print("   • Requires registration_client_uri in response")
        print("   • Supports GET/PUT/DELETE on client configuration")
        print("   • Test with --validate-rfc7592 flag in 'client register' command")
        
        print("\n5. Common RFC 7591 Implementation Issues:")
        print("   • Not validating redirect_uris format")
        print("   • Not checking grant_types/response_types consistency")
        print("   • Missing required response parameters")
        print("   • Not echoing client metadata in response")
        print("   • Not supporting all standard auth methods")
        
        print("\n" + "=" * 60)
        print("To fully test compliance, run:")
        print(f"mcp-validate client register <mcp-server> --validate-rfc7592")
        print("This will perform actual registration and validate the response.")


async def test_response_validation():
    """Demonstrate response validation."""
    print("\n\nRFC 7591 Response Validation Examples")
    print("=" * 60)
    
    # Example 1: Valid response
    print("\n1. Valid registration response:")
    valid_response = {
        "client_id": "client_123456",
        "client_secret": "secret_abcdef123456789012345678901234567890",
        "client_id_issued_at": 1234567890,
        "client_secret_expires_at": 0,
        "registration_access_token": "reg_token_xyz",
        "registration_client_uri": "https://auth.example.com/register/client_123456",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "Test Client",
        "scope": "read write"
    }
    
    request_data = {
        "client_name": "Test Client",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "read write"
    }
    
    validation = RFC7591Validator.validate_registration_response(valid_response, request_data)
    print(f"   Validation: {'✓ Valid' if validation.valid else '✗ Invalid'}")
    if validation.info:
        for info in validation.info:
            print(f"   Info: {info}")
    
    # Example 2: Invalid response
    print("\n2. Invalid registration response:")
    invalid_response = {
        # Missing client_id (required)
        "client_secret": "secret_123",
        "registration_access_token": "token_without_uri",  # Missing URI
        "client_id_issued_at": -1,  # Invalid timestamp
        "grant_types": ["authorization_code"],
        "response_types": ["token"]  # Inconsistent with grant_types
    }
    
    validation = RFC7591Validator.validate_registration_response(invalid_response, request_data)
    print(f"   Validation: {'✓ Valid' if validation.valid else '✗ Invalid'}")
    if validation.errors:
        for error in validation.errors:
            print(f"   Error: {error}")


if __name__ == "__main__":
    asyncio.run(test_rfc7591_compliance())
    asyncio.run(test_response_validation())