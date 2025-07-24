"""RFC 7591/7592 Dynamic Client Registration validation."""

from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
import httpx


class RFC7591ValidationResult(BaseModel):
    """Result of RFC 7591 validation."""
    
    valid: bool
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    info: List[str] = Field(default_factory=list)
    request_data: Dict[str, Any] = Field(default_factory=dict)
    response_data: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(extra="allow")


class RFC7592ValidationResult(BaseModel):
    """Result of RFC 7592 validation."""
    
    valid: bool
    read_supported: bool = False
    update_supported: bool = False
    delete_supported: bool = False
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    info: List[str] = Field(default_factory=list)
    
    model_config = ConfigDict(extra="allow")


class RFC7591Validator:
    """Validator for RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol."""
    
    # Required response parameters per RFC 7591 Section 3.2.1
    REQUIRED_RESPONSE_PARAMS = ["client_id"]
    
    # Optional but commonly expected response parameters
    COMMON_RESPONSE_PARAMS = [
        "client_secret",
        "registration_access_token",
        "registration_client_uri",
        "client_id_issued_at",
        "client_secret_expires_at"
    ]
    
    # Valid client metadata parameters per RFC 7591 Section 2
    VALID_METADATA_PARAMS = [
        "redirect_uris",
        "token_endpoint_auth_method",
        "grant_types",
        "response_types",
        "client_name",
        "client_uri",
        "logo_uri",
        "scope",
        "contacts",
        "tos_uri",
        "policy_uri",
        "jwks_uri",
        "jwks",
        "software_id",
        "software_version",
        "software_statement",
        "application_type",
    ]
    
    # Token endpoint auth methods per RFC 7591 Section 2
    VALID_AUTH_METHODS = [
        "none",
        "client_secret_post",
        "client_secret_basic",
        "client_secret_jwt",
        "private_key_jwt"
    ]
    
    # Grant types per RFC 7591 Section 2
    VALID_GRANT_TYPES = [
        "authorization_code",
        "implicit",
        "password",
        "client_credentials",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "urn:ietf:params:oauth:grant-type:saml2-bearer"
    ]
    
    # Response types per RFC 7591 Section 2
    VALID_RESPONSE_TYPES = [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token"
    ]
    
    # Application types per RFC 7591 Section 2
    VALID_APPLICATION_TYPES = ["web", "native"]
    
    @classmethod
    def validate_registration_request(
        cls,
        request_data: Dict[str, Any]
    ) -> RFC7591ValidationResult:
        """Validate a client registration request per RFC 7591."""
        result = RFC7591ValidationResult(
            valid=True,
            request_data=request_data
        )
        
        # Check redirect_uris for public clients
        if "redirect_uris" in request_data:
            redirect_uris = request_data["redirect_uris"]
            if not isinstance(redirect_uris, list) or len(redirect_uris) == 0:
                result.errors.append("redirect_uris must be a non-empty array")
                result.valid = False
            
            # Check for out-of-band URI
            for uri in redirect_uris:
                if uri == "urn:ietf:wg:oauth:2.0:oob":
                    result.info.append("Using out-of-band redirect URI (deprecated but still supported)")
        
        # Validate token_endpoint_auth_method
        if "token_endpoint_auth_method" in request_data:
            auth_method = request_data["token_endpoint_auth_method"]
            if auth_method not in cls.VALID_AUTH_METHODS:
                result.errors.append(f"Invalid token_endpoint_auth_method: {auth_method}")
                result.valid = False
        
        # Validate grant_types
        if "grant_types" in request_data:
            grant_types = request_data["grant_types"]
            if not isinstance(grant_types, list):
                result.errors.append("grant_types must be an array")
                result.valid = False
            else:
                for grant_type in grant_types:
                    if grant_type not in cls.VALID_GRANT_TYPES and not grant_type.startswith("urn:"):
                        result.warnings.append(f"Non-standard grant_type: {grant_type}")
        
        # Validate response_types
        if "response_types" in request_data:
            response_types = request_data["response_types"]
            if not isinstance(response_types, list):
                result.errors.append("response_types must be an array")
                result.valid = False
            else:
                for response_type in response_types:
                    if response_type not in cls.VALID_RESPONSE_TYPES:
                        result.warnings.append(f"Non-standard response_type: {response_type}")
        
        # Validate application_type
        if "application_type" in request_data:
            app_type = request_data["application_type"]
            if app_type not in cls.VALID_APPLICATION_TYPES:
                result.errors.append(f"Invalid application_type: {app_type} (must be 'web' or 'native')")
                result.valid = False
        
        # Check for unknown parameters
        for key in request_data:
            if key not in cls.VALID_METADATA_PARAMS:
                result.info.append(f"Non-standard metadata parameter: {key}")
        
        return result
    
    @classmethod
    def validate_registration_response(
        cls,
        response_data: Dict[str, Any],
        request_data: Dict[str, Any]
    ) -> RFC7591ValidationResult:
        """Validate a client registration response per RFC 7591."""
        result = RFC7591ValidationResult(
            valid=True,
            request_data=request_data,
            response_data=response_data
        )
        
        # Check required parameters
        for param in cls.REQUIRED_RESPONSE_PARAMS:
            if param not in response_data:
                result.errors.append(f"Missing required response parameter: {param}")
                result.valid = False
        
        # Check client_id format
        if "client_id" in response_data:
            client_id = response_data["client_id"]
            if not isinstance(client_id, str) or len(client_id) == 0:
                result.errors.append("client_id must be a non-empty string")
                result.valid = False
        
        # Check timestamps
        if "client_id_issued_at" in response_data:
            issued_at = response_data["client_id_issued_at"]
            if not isinstance(issued_at, (int, float)) or issued_at <= 0:
                result.errors.append("client_id_issued_at must be a positive number (seconds since epoch)")
                result.valid = False
        
        if "client_secret_expires_at" in response_data:
            expires_at = response_data["client_secret_expires_at"]
            if not isinstance(expires_at, (int, float)) or expires_at < 0:
                result.errors.append("client_secret_expires_at must be 0 (never expires) or positive number")
                result.valid = False
            elif expires_at == 0:
                result.info.append("Client secret never expires (client_secret_expires_at = 0)")
        
        # Check registration management (RFC 7592)
        has_reg_token = "registration_access_token" in response_data
        has_reg_uri = "registration_client_uri" in response_data
        
        if has_reg_token and not has_reg_uri:
            result.errors.append("registration_access_token provided without registration_client_uri")
            result.valid = False
        elif has_reg_uri and not has_reg_token:
            result.errors.append("registration_client_uri provided without registration_access_token")
            result.valid = False
        elif has_reg_token and has_reg_uri:
            result.info.append("RFC 7592 support detected (registration management)")
        
        # Validate echoed parameters
        echo_params = ["client_name", "redirect_uris", "grant_types", "response_types", "scope"]
        for param in echo_params:
            if param in request_data and param in response_data:
                if request_data[param] != response_data[param]:
                    result.warnings.append(f"Server modified {param} from request")
        
        # Check for server-assigned values
        if "client_secret" in response_data:
            secret = response_data["client_secret"]
            if not isinstance(secret, str) or len(secret) < 32:
                result.warnings.append("Client secret seems short (less than 32 characters)")
        
        # Check grant types consistency
        if "grant_types" in response_data:
            grant_types = response_data["grant_types"]
            if "authorization_code" in grant_types and "response_types" in response_data:
                if "code" not in response_data["response_types"]:
                    result.errors.append("grant_types includes 'authorization_code' but response_types missing 'code'")
                    result.valid = False
        
        return result


class RFC7592Validator:
    """Validator for RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol."""
    
    @classmethod
    async def validate_management_support(
        cls,
        client: httpx.AsyncClient,
        registration_client_uri: str,
        registration_access_token: str,
        client_id: str
    ) -> RFC7592ValidationResult:
        """Validate RFC 7592 management protocol support."""
        result = RFC7592ValidationResult(valid=True)
        
        headers = {
            "Authorization": f"Bearer {registration_access_token}",
            "Accept": "application/json"
        }
        
        # Test READ operation (GET)
        try:
            response = await client.get(
                registration_client_uri,
                headers=headers
            )
            
            if response.status_code == 200:
                result.read_supported = True
                result.info.append("Client configuration read (GET) supported")
                
                # Validate response
                data = response.json()
                if "client_id" not in data:
                    result.errors.append("GET response missing client_id")
                    result.valid = False
                elif data["client_id"] != client_id:
                    result.errors.append(f"GET response client_id mismatch: {data['client_id']} != {client_id}")
                    result.valid = False
                    
            elif response.status_code == 401:
                result.errors.append("Registration access token rejected for GET")
                result.valid = False
            elif response.status_code == 404:
                result.errors.append("Client configuration endpoint not found")
                result.valid = False
            else:
                result.warnings.append(f"GET returned unexpected status: {response.status_code}")
                
        except Exception as e:
            result.errors.append(f"Failed to test GET operation: {str(e)}")
            result.valid = False
        
        # Test UPDATE operation (PUT) - non-destructive test
        if result.read_supported:
            try:
                # First get current config
                response = await client.get(registration_client_uri, headers=headers)
                if response.status_code == 200:
                    current_config = response.json()
                    
                    # Try minimal update (just echo back with minor change)
                    update_data = current_config.copy()
                    update_data["client_name"] = current_config.get("client_name", "Test Client") + " (RFC 7592 Test)"
                    
                    response = await client.put(
                        registration_client_uri,
                        headers={**headers, "Content-Type": "application/json"},
                        json=update_data
                    )
                    
                    if response.status_code == 200:
                        result.update_supported = True
                        result.info.append("Client configuration update (PUT) supported")
                        
                        # Restore original
                        await client.put(
                            registration_client_uri,
                            headers={**headers, "Content-Type": "application/json"},
                            json=current_config
                        )
                    elif response.status_code == 405:
                        result.info.append("PUT method not allowed (update not supported)")
                    else:
                        result.warnings.append(f"PUT returned unexpected status: {response.status_code}")
                        
            except Exception as e:
                result.warnings.append(f"Could not test PUT operation: {str(e)}")
        
        # Note: We don't test DELETE as it would remove the client
        result.info.append("DELETE operation not tested (would remove client)")
        
        # Determine overall compliance
        if not result.read_supported:
            result.warnings.append("RFC 7592 requires at least GET support")
            result.valid = False
        
        return result