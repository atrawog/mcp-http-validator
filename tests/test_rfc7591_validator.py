"""Tests for RFC 7591/7592 validators."""

import pytest
from mcp_http_validator.rfc7591 import RFC7591Validator, RFC7592Validator, RFC7591ValidationResult


class TestRFC7591Validator:
    """Test RFC 7591 request and response validation."""
    
    def test_valid_basic_request(self):
        """Test validation of a basic valid request."""
        request = {
            "client_name": "Test Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        }
        
        result = RFC7591Validator.validate_registration_request(request)
        assert result.valid is True
        assert len(result.errors) == 0
    
    def test_empty_redirect_uris(self):
        """Test that empty redirect_uris is invalid."""
        request = {
            "redirect_uris": []
        }
        
        result = RFC7591Validator.validate_registration_request(request)
        assert result.valid is False
        assert "redirect_uris must be a non-empty array" in result.errors
    
    def test_invalid_auth_method(self):
        """Test invalid token_endpoint_auth_method."""
        request = {
            "token_endpoint_auth_method": "invalid_method"
        }
        
        result = RFC7591Validator.validate_registration_request(request)
        assert result.valid is False
        assert any("Invalid token_endpoint_auth_method" in error for error in result.errors)
    
    def test_invalid_application_type(self):
        """Test invalid application_type."""
        request = {
            "application_type": "mobile"  # Should be "web" or "native"
        }
        
        result = RFC7591Validator.validate_registration_request(request)
        assert result.valid is False
        assert any("Invalid application_type" in error for error in result.errors)
    
    def test_non_standard_grant_type_warning(self):
        """Test non-standard grant types generate warnings."""
        request = {
            "grant_types": ["authorization_code", "custom_grant"]
        }
        
        result = RFC7591Validator.validate_registration_request(request)
        assert result.valid is True  # Still valid, just warned
        assert any("Non-standard grant_type: custom_grant" in warning for warning in result.warnings)
    
    def test_oob_redirect_uri_info(self):
        """Test out-of-band redirect URI generates info message."""
        request = {
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"]
        }
        
        result = RFC7591Validator.validate_registration_request(request)
        assert result.valid is True
        assert any("out-of-band redirect URI" in info for info in result.info)
    
    def test_valid_response(self):
        """Test validation of a valid response."""
        request = {
            "client_name": "Test Client",
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        }
        
        response = {
            "client_id": "client_123",
            "client_secret": "secret_" + "x" * 40,
            "client_name": "Test Client",
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is True
        assert len(result.errors) == 0
    
    def test_missing_client_id(self):
        """Test response missing required client_id."""
        request = {}
        response = {
            "client_secret": "secret_123"
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is False
        assert "Missing required response parameter: client_id" in result.errors
    
    def test_invalid_timestamp(self):
        """Test invalid client_id_issued_at timestamp."""
        request = {}
        response = {
            "client_id": "client_123",
            "client_id_issued_at": -1
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is False
        assert any("positive number" in error for error in result.errors)
    
    def test_short_client_secret_warning(self):
        """Test short client secret generates warning."""
        request = {}
        response = {
            "client_id": "client_123",
            "client_secret": "short"
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is True  # Still valid
        assert any("Client secret seems short" in warning for warning in result.warnings)
    
    def test_rfc7592_params_consistency(self):
        """Test RFC 7592 parameters must be provided together."""
        request = {}
        
        # Token without URI
        response = {
            "client_id": "client_123",
            "registration_access_token": "token_123"
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is False
        assert any("without registration_client_uri" in error for error in result.errors)
        
        # URI without token
        response = {
            "client_id": "client_123",
            "registration_client_uri": "https://auth.example.com/reg/123"
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is False
        assert any("without registration_access_token" in error for error in result.errors)
    
    def test_grant_response_type_consistency(self):
        """Test grant_types and response_types consistency."""
        request = {}
        response = {
            "client_id": "client_123",
            "grant_types": ["authorization_code"],
            "response_types": ["token"]  # Should include "code"
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is False
        assert any("missing 'code'" in error for error in result.errors)
    
    def test_modified_params_warning(self):
        """Test warning when server modifies requested parameters."""
        request = {
            "client_name": "My App",
            "scope": "read write"
        }
        response = {
            "client_id": "client_123",
            "client_name": "My App (Modified)",
            "scope": "read"  # Server reduced scope
        }
        
        result = RFC7591Validator.validate_registration_response(response, request)
        assert result.valid is True
        assert any("Server modified client_name" in warning for warning in result.warnings)
        assert any("Server modified scope" in warning for warning in result.warnings)


@pytest.mark.asyncio
class TestRFC7592Validator:
    """Test RFC 7592 management protocol validation."""
    
    # Note: These would require actual HTTP client mocking
    # Shown here for documentation purposes
    
    async def test_validate_management_support_structure(self):
        """Test the structure of RFC 7592 validation."""
        # This would need httpx mocking in real tests
        pass