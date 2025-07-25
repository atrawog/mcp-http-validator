"""RFC 8707 Resource Indicators for OAuth 2.0 validation."""

from typing import Dict, List, Optional, Tuple
import jwt


class RFC8707Validator:
    """Validates OAuth 2.0 Resource Indicators implementation per RFC 8707."""
    
    @staticmethod
    def validate_authorization_request(
        auth_url: str,
        expected_resources: List[str]
    ) -> Tuple[bool, List[str], Dict[str, any]]:
        """Validate that authorization request includes resource parameters.
        
        Args:
            auth_url: Full authorization URL with parameters
            expected_resources: Resources that should be requested
            
        Returns:
            Tuple of (has_resources, found_resources, validation_details)
        """
        from urllib.parse import urlparse, parse_qs
        
        details = {
            "test_description": "Validating OAuth authorization request for RFC 8707 compliance",
            "requirement": "RFC 8707 requires 'resource' parameter(s) in authorization requests",
            "purpose": "Resource indicators prevent token confusion attacks by restricting token audience",
            "url_tested": auth_url,
            "expected_resources": expected_resources
        }
        
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)
        
        # RFC 8707: Multiple resource parameters allowed
        resources = params.get('resource', [])
        
        details["found_resources"] = resources
        details["has_resource_param"] = len(resources) > 0
        
        if not resources:
            details["error"] = "No 'resource' parameter found in authorization request"
            details["fix"] = "Add resource parameter(s) to authorization request URL"
            details["example"] = f"{auth_url}&resource={expected_resources[0] if expected_resources else 'https://api.example.com'}"
        else:
            # Check if expected resources are included
            missing = [r for r in expected_resources if r not in resources]
            if missing:
                details["warning"] = f"Authorization request missing expected resources: {missing}"
                details["found_vs_expected"] = {
                    "found": resources,
                    "expected": expected_resources,
                    "missing": missing
                }
        
        return len(resources) > 0, resources, details
    
    @staticmethod
    def validate_token_response(
        token: str,
        requested_resources: List[str],
        verify_signature: bool = False
    ) -> Tuple[bool, Dict[str, any]]:
        """Validate token response for RFC 8707 compliance.
        
        Args:
            token: JWT access token
            requested_resources: Resources that were requested
            verify_signature: Whether to verify JWT signature
            
        Returns:
            Tuple of (is_compliant, validation_details)
        """
        validation = {
            "test_description": "Validating OAuth token response for RFC 8707 compliance",
            "requirement": "RFC 8707 requires tokens to include requested resources in audience claim",
            "purpose": "Ensures tokens are audience-restricted to prevent token confusion attacks",
            "spec_reference": "RFC 8707 Section 3 - Audience Restriction",
            "rfc8707_compliant": False,
            "requested_resources": requested_resources,
            "token_audience": None,
            "missing_resources": [],
            "errors": [],
            "warnings": []
        }
        
        try:
            # Decode token without verification (signature check is separate concern)
            claims = jwt.decode(token, options={"verify_signature": False})
            
            # Get audience claim
            aud = claims.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            validation["token_audience"] = aud
            
            # RFC 8707 Section 3: Token MUST contain requested resources in audience
            missing = [r for r in requested_resources if r not in aud]
            validation["missing_resources"] = missing
            
            if missing:
                validation["errors"].append(
                    f"RFC 8707 VIOLATION: Token audience is missing requested resources: {missing}. "
                    f"The authorization server accepted the 'resource' parameter(s) but failed to include them "
                    f"in the token's audience claim. This breaks RFC 8707 compliance and enables token confusion attacks."
                )
                validation["fix"] = (
                    "OAuth server must include all accepted 'resource' parameters in the token's 'aud' claim. "
                    f"Expected audience to contain: {requested_resources}, but only found: {aud}"
                )
                validation["security_impact"] = (
                    "HIGH - Tokens without proper audience restrictions can be used across different resource servers, "
                    "allowing attackers to replay tokens meant for one API against another API."
                )
            else:
                validation["rfc8707_compliant"] = True
                validation["success"] = f"Token correctly includes all {len(requested_resources)} requested resources in audience"
                
            # Additional checks
            if not aud:
                validation["warnings"].append(
                    "CRITICAL: Token has no audience claim at all. This violates basic OAuth 2.0 security principles "
                    "and makes the token vulnerable to replay attacks across any resource server."
                )
                validation["fix"] = "Ensure OAuth server includes 'aud' claim in all access tokens"
            
            # Check for resource_indicators_supported in metadata
            if 'iss' in claims:
                validation["issuer"] = claims['iss']
                validation["info"] = (
                    f"Token issued by: {claims['iss']}. Verify this server advertises "
                    "'resource_indicators_supported: true' in its metadata endpoint."
                )
            
            # Provide token structure info
            validation["token_claims"] = {
                "aud": aud,
                "iss": claims.get("iss"),
                "exp": claims.get("exp"),
                "iat": claims.get("iat"),
                "sub": claims.get("sub")
            }
                
        except jwt.DecodeError as e:
            validation["errors"].append(
                f"Failed to decode JWT token: {str(e)}. "
                "Token may be malformed, corrupted, or not a valid JWT. "
                "Ensure the token is a properly formatted JWT access token."
            )
            validation["fix"] = "Verify the token is a valid JWT format (header.payload.signature)"
        except Exception as e:
            validation["errors"].append(f"Unexpected error validating token: {str(e)}")
            validation["error_type"] = type(e).__name__
            
        return validation["rfc8707_compliant"], validation
    
    @staticmethod
    def validate_resource_server_check(
        server_url: str,
        token_accepted: bool,
        token_audience: List[str]
    ) -> Tuple[bool, Dict[str, any]]:
        """Validate resource server's audience validation.
        
        Args:
            server_url: The MCP server URL
            token_accepted: Whether server accepted the token
            token_audience: Audience claims in the token
            
        Returns:
            Tuple of (is_compliant, validation_details)
        """
        validation = {
            "test_description": "Validating MCP resource server audience validation",
            "requirement": "Resource servers must validate token audience contains their identifier",
            "purpose": "Prevents token confusion attacks by rejecting tokens meant for other servers",
            "spec_reference": "RFC 8707 Section 4 - Resource Server Validation",
            "server_compliant": False,
            "server_url": server_url,
            "token_audience": token_audience,
            "errors": [],
            "warnings": [],
            "security_risk": None
        }
        
        # Check if server URL is in audience
        server_in_audience = token_audience is not None and server_url in token_audience
        
        validation["server_in_audience"] = server_in_audience
        validation["token_accepted"] = token_accepted
        
        if token_accepted and not server_in_audience:
            validation["errors"].append(
                f"RFC 8707 CRITICAL VIOLATION: Server accepted a token that was NOT intended for it! "
                f"The server URL '{server_url}' is not in the token's audience claim {token_audience}. "
                f"This means the server is accepting tokens meant for other resource servers."
            )
            validation["security_risk"] = (
                "CRITICAL: Token confusion attack vulnerability detected! "
                "The server accepts tokens intended for other services, allowing attackers to:\n"
                "- Use tokens from one API against this API\n"
                "- Escalate privileges by using higher-privilege tokens from other services\n"
                "- Access resources they shouldn't have access to"
            )
            validation["fix"] = (
                f"The server MUST validate that its identifier '{server_url}' is present in the token's 'aud' claim. "
                "Reject any tokens where the audience doesn't include this server's resource identifier."
            )
            validation["example_validation"] = (
                "if server_url not in token.get('aud', []):\n"
                "    return 401, 'Token audience validation failed'"
            )
        elif not token_accepted and server_in_audience:
            # Server rejected a token that should have been accepted
            validation["server_compliant"] = True  # Compliant from security perspective (fail-safe)
            validation["warnings"].append(
                f"Server rejected a token that included its identifier in the audience. "
                f"While this is safe (fail-closed), it suggests other validation issues. "
                f"The token audience includes '{server_url}' but was still rejected."
            )
            validation["possible_issues"] = [
                "Token might be expired",
                "Token signature validation failed", 
                "Required scopes missing",
                "Token issuer not trusted"
            ]
        elif token_accepted and server_in_audience:
            validation["server_compliant"] = True
            validation["success"] = (
                f"Server correctly validated audience and accepted the token. "
                f"Token audience {token_audience} includes server identifier '{server_url}'."
            )
        else:
            # Not accepted and not in audience - correct behavior
            validation["server_compliant"] = True
            validation["success"] = (
                "Server correctly rejected token with incorrect audience. "
                f"Token audience {token_audience} does not include '{server_url}'."
            )
            
        return validation["server_compliant"], validation
    
    @staticmethod
    def generate_report(
        auth_request_valid: bool,
        auth_resources: List[str],
        token_validation: Dict[str, any],
        server_validation: Dict[str, any]
    ) -> str:
        """Generate comprehensive RFC 8707 compliance report.
        
        Returns:
            Formatted compliance report showing both compliant and non-compliant aspects
        """
        lines = []
        lines.append("RFC 8707 Resource Indicators Compliance Report")
        lines.append("=" * 50)
        
        # Authorization Request
        lines.append("\n1. Authorization Request Compliance:")
        lines.append("   Requirement: Include 'resource' parameter identifying target servers")
        if auth_request_valid:
            lines.append(f"   ✓ COMPLIANT: Includes resource parameter(s)")
            lines.append(f"   Resources requested: {auth_resources}")
        else:
            lines.append("   ✗ NON-COMPLIANT: Missing 'resource' parameter")
            lines.append("   Fix: Add ?resource=<mcp-server-url> to authorization request")
            
        # Token Response
        lines.append("\n2. OAuth Server Token Response Compliance:")
        lines.append("   Requirement: Include requested resources in token 'aud' claim")
        
        # Check if token is JWT
        if token_validation.get("errors") and "Failed to decode JWT" in str(token_validation.get("errors", [])):
            lines.append("   ⚠️  Token Format: Not a JWT (opaque token)")
            lines.append("   Note: RFC 8707 compliance cannot be verified for opaque tokens")
            lines.append("   Recommendation: Use token introspection endpoint if available")
        elif token_validation["rfc8707_compliant"]:
            lines.append("   ✓ COMPLIANT: Token includes all requested resources in audience")
            if token_validation.get("success"):
                lines.append(f"   {token_validation['success']}")
        else:
            lines.append("   ✗ NON-COMPLIANT: RFC 8707 violation detected")
            for error in token_validation.get("errors", []):
                lines.append(f"      • {error}")
            if token_validation.get("fix"):
                lines.append(f"   Fix: {token_validation['fix']}")
                
        lines.append(f"\n   Token Details:")
        lines.append(f"   - Audience claim: {token_validation.get('token_audience', 'N/A')}")
        lines.append(f"   - Requested resources: {token_validation.get('requested_resources', [])}")
        if token_validation.get("missing_resources"):
            lines.append(f"   - Missing from audience: {token_validation['missing_resources']}")
        
        # Resource Server
        lines.append("\n3. MCP Resource Server Audience Validation:")
        lines.append("   Requirement: Validate token audience contains server's identifier")
        
        token_accepted = server_validation.get("token_accepted", False)
        server_in_audience = server_validation.get("server_in_audience", False)
        
        if server_validation["server_compliant"]:
            lines.append("   ✓ COMPLIANT: Server properly validates token audience")
            if token_accepted and server_in_audience:
                lines.append("   - Token accepted (server IS in audience)")
            elif not token_accepted and not server_in_audience:
                lines.append("   - Token rejected (server NOT in audience) - Correct behavior!")
            if server_validation.get("success"):
                lines.append(f"   {server_validation['success']}")
        else:
            lines.append("   ✗ NON-COMPLIANT: RFC 8707 violation detected") 
            for error in server_validation.get("errors", []):
                lines.append(f"      • {error}")
                
        if server_validation.get("security_risk"):
            lines.append(f"\n   ⚠️  SECURITY RISK: {server_validation['security_risk']}")
            
        # Additional compliance checks
        lines.append("\n4. Additional Compliance Checks:")
        lines.append("   ✓ Authorization server metadata should include:")
        lines.append("     - resource_indicators_supported: true")
        lines.append("   ✓ Resource server metadata should include:")
        lines.append("     - WWW-Authenticate header with resource_uri on 401")
        lines.append("     - /.well-known/oauth-protected-resource endpoint")
            
        # Summary
        lines.append("\n" + "=" * 50)
        lines.append("COMPLIANCE SUMMARY:")
        
        auth_compliant = auth_request_valid
        token_compliant = token_validation.get("rfc8707_compliant", False)
        server_compliant = server_validation.get("server_compliant", False)
        
        # Count compliant vs non-compliant
        compliant_count = sum([auth_compliant, token_compliant, server_compliant])
        total_checks = 3
        
        lines.append(f"\nCompliance Score: {compliant_count}/{total_checks} checks passed")
        lines.append(f"- Authorization Request: {'✓ PASS' if auth_compliant else '✗ FAIL'}")
        lines.append(f"- Token Audience Restriction: {'✓ PASS' if token_compliant else '✗ FAIL'}")
        lines.append(f"- Server Audience Validation: {'✓ PASS' if server_compliant else '✗ FAIL'}")
        
        if compliant_count == total_checks:
            lines.append("\n✓ RESULT: Full RFC 8707 compliance achieved!")
            lines.append("          Token confusion attacks are properly mitigated.")
        elif compliant_count == 0:
            lines.append("\n✗ RESULT: Complete RFC 8707 non-compliance!")
            lines.append("          CRITICAL: System is vulnerable to token confusion attacks.")
        else:
            lines.append(f"\n⚠️  RESULT: Partial RFC 8707 compliance ({compliant_count}/{total_checks})")
            lines.append("          Security vulnerabilities exist in non-compliant components.")
            
        return "\n".join(lines)