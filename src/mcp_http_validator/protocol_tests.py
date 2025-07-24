"""Protocol-related test methods for MCP HTTP Validator."""

from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
import json

import httpx

from .base_validator import BaseMCPValidator
from .transport_detector import TransportDetector, TransportType


class ProtocolTests(BaseMCPValidator):
    """Protocol-specific test methods for MCP validation."""


    async def test_http_transport(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test HTTP transport implementation for MCP protocol.
        
        MCP supports multiple transport types:
        1. HTTP with SSE (GET only, SSE responses)
        2. Streamable HTTP (POST with JSON or SSE responses)
        3. JSON-RPC (POST with JSON responses only)
        """
        url = self.mcp_endpoint
        
        details = {
            "test_description": "Testing MCP HTTP transport implementation",
            "requirement": "MCP servers must support at least one HTTP transport method",
            "purpose": "Detects and validates the server's transport capabilities",
            "url_tested": url,
            "spec_reference": "MCP Transport Specifications"
        }
        
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        # Use transport detector to determine capabilities
        detector = TransportDetector(self.client)
        base_headers = self._get_headers({})
        
        try:
            caps = await detector.detect(url, base_headers)
            if caps is None:
                return False, "Transport detection returned None - internal error", details
            details["transport_capabilities"] = {
                "primary": caps.primary_transport.value,
                "supports_get_sse": caps.supports_get_sse,
                "supports_post_json": caps.supports_post_json,
                "supports_post_sse": caps.supports_post_sse,
                "description": caps.describe()
            }
            
            if caps.primary_transport == TransportType.UNKNOWN:
                # Check if authentication is required
                if caps.error_details and caps.error_details.get("status_code") == 401:
                    return False, (
                        "Failed to detect MCP transport - authentication required. "
                        "Run 'mcp-validate flow' for interactive OAuth flow to obtain a token."
                    ), details
                return False, (
                    "Failed to detect any supported MCP transport method. "
                    "The server doesn't respond to GET with SSE or POST with JSON/SSE. "
                    "MCP servers must support at least one transport method."
                ), details
            
            # Success - describe what we found
            return True, (
                f"MCP transport detected: {caps.describe()}. "
                f"The server successfully responds to "
                f"{'GET requests' if caps.supports_get_sse else ''}"
                f"{' and ' if caps.supports_get_sse and (caps.supports_post_json or caps.supports_post_sse) else ''}"
                f"{'POST requests' if caps.supports_post_json or caps.supports_post_sse else ''} "
                f"with appropriate content types for MCP message exchange."
            ), details
        except httpx.RequestError as e:
            return False, f"HTTP transport request failed: {str(e)}", {"url": url, "error": str(e)}
    
    async def test_protocol_version(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test MCP protocol version handling according to spec.
        
        Per spec requirements:
        1. Server MUST respond with 400 Bad Request for invalid/unsupported versions
        2. Server SHOULD assume 2024-03-26 if header is missing (but may still reject if unsupported)
        3. Server must accept at least one valid protocol version
        4. Servers can choose which versions to support - rejecting old versions is allowed
        """
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        url = self.mcp_endpoint
        details = {
            "url": url,
            "test_description": "Testing protocol version header handling per MCP spec",
            "spec_reference": "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#protocol-version-header",
            "tests_performed": []
        }
        
        # First detect transport type WITHOUT the protocol version header
        # This helps us test the raw transport
        detector = TransportDetector(self.client)
        base_headers = {}
        if self.access_token:
            base_headers["Authorization"] = f"Bearer {self.access_token}"
        
        try:
            caps = await detector.detect(url, base_headers)
            if caps is None:
                return False, "Transport detection returned None - internal error", details
            details["transport_type"] = caps.primary_transport.value
            details["transport_detected"] = caps.primary_transport != TransportType.UNKNOWN
            
            # If transport detection failed, we can't test protocol version properly
            if caps.primary_transport == TransportType.UNKNOWN:
                details["transport_errors"] = caps.error_details if caps.error_details else {}
                # Check if authentication is required
                if caps.error_details and caps.error_details.get("status_code") == 401:
                    return False, (
                        "Cannot test protocol version header - authentication required. "
                        "Run 'mcp-validate flow' for interactive OAuth flow to obtain a token."
                    ), details
                return False, (
                    "Cannot test protocol version header - no MCP transport detected. "
                    "Protocol version validation requires a working MCP endpoint."
                ), details
            
            # Transport detected - now run comprehensive protocol version tests
            test_results = []
            all_passed = True
            
            # Determine which endpoint to test based on transport type
            if caps.primary_transport == TransportType.HTTP_SSE:
                # For SSE, we test on GET requests
                test_method = "GET"
                test_endpoint = url
            else:
                # For POST-based transports
                test_method = "POST"
                test_endpoint = url
            
            # Test 1: INVALID protocol version - MUST return 400 Bad Request
            details["tests_performed"].append("invalid_version")
            try:
                test_headers = base_headers.copy()
                test_headers["MCP-Protocol-Version"] = "1999-01-01"  # Invalid version
                
                status_code = None
                if test_method == "GET":
                    test_headers["Accept"] = "text/event-stream"
                    # For SSE, use stream to check status without hanging
                    async with self.client.stream("GET", test_endpoint, headers=test_headers, timeout=2.0) as response:
                        status_code = response.status_code
                else:
                    test_headers["Content-Type"] = "application/json"
                    test_request = {
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {"clientInfo": {"name": "test", "version": "1.0"}},
                        "id": 1
                    }
                    response = await self.client.post(test_endpoint, headers=test_headers, json=test_request, timeout=5.0)
                    status_code = response.status_code
                
                if status_code == 400:
                    test_results.append("✓ Server correctly rejected invalid protocol version with 400 Bad Request")
                elif status_code == 401:
                    test_results.append("⚠ Cannot test invalid version handling - authentication required. Run 'mcp-validate flow' for interactive OAuth flow.")
                else:
                    all_passed = False
                    test_results.append(f"✗ Server returned {status_code} instead of 400 for invalid version")
                    details["invalid_version_status"] = status_code
            except Exception as e:
                all_passed = False
                test_results.append(f"✗ Failed to test invalid version: {str(e)}")
            
            # Test 2: NO protocol version header - server SHOULD assume 2024-03-26
            details["tests_performed"].append("missing_header")
            try:
                test_headers = base_headers.copy()
                # Explicitly remove any protocol version header
                test_headers.pop("MCP-Protocol-Version", None)
                
                status_code = None
                if test_method == "GET":
                    test_headers["Accept"] = "text/event-stream"
                    # For SSE, use stream to check status without hanging
                    async with self.client.stream("GET", test_endpoint, headers=test_headers, timeout=2.0) as response:
                        status_code = response.status_code
                else:
                    test_headers["Content-Type"] = "application/json"
                    test_request = {
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {"clientInfo": {"name": "test", "version": "1.0"}},
                        "id": 1
                    }
                    response = await self.client.post(test_endpoint, headers=test_headers, json=test_request, timeout=5.0)
                    status_code = response.status_code
                
                if status_code in [200, 202, 204]:
                    test_results.append("✓ Server accepts requests without protocol version header (assumes 2024-03-26)")
                elif status_code == 401:
                    test_results.append("⚠ Cannot test missing header behavior - authentication required. Run 'mcp-validate flow' for interactive OAuth flow.")
                else:
                    # This is actually OK per spec - server SHOULD (not MUST) assume 2024-03-26
                    test_results.append(f"⚠ Server returned {status_code} for missing header (assuming 2024-03-26 is SHOULD, not MUST)")
                    details["missing_header_status"] = status_code
            except Exception as e:
                test_results.append(f"⚠ Failed to test missing header: {str(e)}")
            
            # Test 3: VALID protocol version 2024-03-26 - server MAY support this
            details["tests_performed"].append("valid_old_version")
            try:
                test_headers = base_headers.copy()
                test_headers["MCP-Protocol-Version"] = "2024-03-26"  # Old version - server may reject
                
                status_code = None
                if test_method == "GET":
                    test_headers["Accept"] = "text/event-stream"
                    # For SSE, use stream to check status without hanging
                    async with self.client.stream("GET", test_endpoint, headers=test_headers, timeout=2.0) as response:
                        status_code = response.status_code
                else:
                    test_headers["Content-Type"] = "application/json"
                    test_request = {
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {"clientInfo": {"name": "test", "version": "1.0"}},
                        "id": 1
                    }
                    response = await self.client.post(test_endpoint, headers=test_headers, json=test_request, timeout=5.0)
                    status_code = response.status_code
                
                if status_code in [200, 202, 204]:
                    test_results.append("✓ Server accepts protocol version 2024-03-26 (backward compatible)")
                    details["supports_old_version"] = True
                elif status_code == 400:
                    # This is OK - server may not support old versions
                    test_results.append("ℹ Server rejects 2024-03-26 with 400 (only supports newer versions)")
                    details["supports_old_version"] = False
                    details["old_version_status"] = status_code
                elif status_code == 401:
                    test_results.append("⚠ Cannot test 2024-03-26 version - authentication required. Run 'mcp-validate flow' for interactive OAuth flow.")
                else:
                    all_passed = False
                    test_results.append(f"✗ Server returned unexpected status {status_code} for 2024-03-26 (should be 200 or 400)")
                    details["old_version_status"] = status_code
            except Exception as e:
                all_passed = False
                test_results.append(f"✗ Failed to test 2024-03-26 version: {str(e)}")
            
            # Test 4: VALID protocol version 2025-06-18 - at least one valid version MUST work
            details["tests_performed"].append("valid_current_version")
            current_version_accepted = False
            try:
                test_headers = base_headers.copy()
                test_headers["MCP-Protocol-Version"] = "2025-06-18"  # Current version
                
                status_code = None
                if test_method == "GET":
                    test_headers["Accept"] = "text/event-stream"
                    # For SSE, use stream to check status without hanging
                    async with self.client.stream("GET", test_endpoint, headers=test_headers, timeout=2.0) as response:
                        status_code = response.status_code
                else:
                    test_headers["Content-Type"] = "application/json"
                    test_request = {
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {"clientInfo": {"name": "test", "version": "1.0"}},
                        "id": 1
                    }
                    response = await self.client.post(test_endpoint, headers=test_headers, json=test_request, timeout=5.0)
                    status_code = response.status_code
                
                if status_code in [200, 202, 204]:
                    test_results.append("✓ Server accepts protocol version 2025-06-18")
                    current_version_accepted = True
                    details["supports_current_version"] = True
                elif status_code == 400:
                    # Server might only support older versions
                    test_results.append("⚠ Server rejects 2025-06-18 with 400 (may only support older versions)")
                    details["supports_current_version"] = False
                    details["current_version_status"] = status_code
                elif status_code == 401:
                    test_results.append("⚠ Cannot test 2025-06-18 version - authentication required. Run 'mcp-validate flow' for interactive OAuth flow.")
                else:
                    all_passed = False
                    test_results.append(f"✗ Server returned unexpected status {status_code} for 2025-06-18 (should be 200 or 400)")
                    details["current_version_status"] = status_code
            except Exception as e:
                all_passed = False
                test_results.append(f"✗ Failed to test 2025-06-18 version: {str(e)}")
            
            # Compile results
            details["test_results"] = test_results
            
            # Determine overall pass/fail
            # Server MUST:
            # 1. Reject truly invalid versions with 400
            # 2. Accept at least one valid version
            invalid_version_handled = any("correctly rejected invalid" in r for r in test_results)
            at_least_one_version_works = details.get("supports_old_version", False) or details.get("supports_current_version", False)
            
            if not invalid_version_handled and "invalid_version_status" in details:
                all_passed = False
                
            if not at_least_one_version_works:
                all_passed = False
                test_results.append("✗ Server doesn't accept ANY valid protocol versions!")
            
            # Build summary
            if all_passed:
                supported_versions = []
                if details.get("supports_old_version"):
                    supported_versions.append("2024-03-26")
                if details.get("supports_current_version"):
                    supported_versions.append("2025-06-18")
                    
                return True, (
                    f"Protocol version header validation PASSED. "
                    f"Server correctly rejects invalid versions and supports: {', '.join(supported_versions)}. "
                    f"Protocol negotiation is working as designed."
                ), details
            else:
                failures = [r for r in test_results if r.startswith("✗")]
                return False, (
                    f"Protocol version header validation FAILED. "
                    f"Issues: {'; '.join(failures)}"
                ), details
                
        except httpx.RequestError as e:
            return False, f"Request failed: {str(e)}", details
    
    async def test_streamable_http(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test Streamable HTTP transport compliance.
        
        Per spec requirements:
        1. Server MUST accept POST requests with JSON-RPC messages
        2. Server MUST support both application/json and text/event-stream responses
        3. Client MUST include Accept header with both types
        4. SSE responses must use 'message' events with JSON data
        5. Server MAY implement session management
        """
        url = self.mcp_endpoint
        details = {
            "url": url,
            "test_description": "Testing Streamable HTTP transport compliance",
            "spec_reference": "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http",
            "tests_performed": []
        }
        
        test_results = []
        all_passed = True
        response = None  # Initialize response variable
        
        # Test 1: Verify server accepts POST with proper Accept header
        details["tests_performed"].append("accept_header_compliance")
        try:
            headers = self._get_headers({
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"  # MUST include both
            })
            
            test_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {"clientInfo": {"name": "streamable-test", "version": "1.0"}},
                "id": 1
            }
            
            response = await self.client.post(url, headers=headers, json=test_request, timeout=5.0)
            
            if response.status_code in [200, 202, 204]:
                test_results.append("✓ Server accepts POST with proper Accept header")
                details["post_accepted"] = True
                details["response_status"] = response.status_code
                details["response_content_type"] = response.headers.get("content-type", "")
            elif response.status_code == 401:
                # If we get 401 without auth, we can't test this transport
                return None, (
                    "Cannot test Streamable HTTP transport - authentication required. "
                    "The server returned 401 Unauthorized. Streamable HTTP transport testing "
                    "requires the ability to make POST requests to verify transport compliance. "
                    "Run 'mcp-validate flow' for interactive OAuth flow to obtain a token."
                ), {
                    **details,
                    "status_code": 401,
                    "auth_required": True,
                    "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow"
                }
            else:
                all_passed = False
                test_results.append(f"✗ Server rejected POST with status {response.status_code}")
                details["post_rejected"] = True
                details["response_status"] = response.status_code
        except Exception as e:
            all_passed = False
            test_results.append(f"✗ Failed to test POST request: {str(e)}")
            details["post_error"] = str(e)
        
        # Test 2: Verify response type handling
        details["tests_performed"].append("response_type_handling")
        if details.get("post_accepted"):
            content_type = details.get("response_content_type", "").lower()
            
            if "application/json" in content_type:
                # Test JSON response
                try:
                    json_data = response.json()
                    if "jsonrpc" in json_data and json_data["jsonrpc"] == "2.0":
                        test_results.append("✓ Server properly returns JSON-RPC responses")
                        details["json_response_valid"] = True
                    else:
                        all_passed = False
                        test_results.append("✗ JSON response is not valid JSON-RPC 2.0")
                        details["json_response_invalid"] = True
                except Exception as e:
                    all_passed = False
                    test_results.append(f"✗ Failed to parse JSON response: {str(e)}")
            elif "text/event-stream" in content_type:
                test_results.append("✓ Server supports SSE streaming responses")
                details["sse_response"] = True
            else:
                all_passed = False
                test_results.append(f"✗ Invalid response Content-Type: {content_type}")
                details["invalid_content_type"] = True
        
        # Test 3: Test SSE streaming response specifically
        details["tests_performed"].append("sse_streaming")
        try:
            # Force SSE response by using a method that typically streams
            headers = self._get_headers({
                "Content-Type": "application/json",
                "Accept": "text/event-stream"  # Prefer SSE
            })
            
            stream_request = {
                "jsonrpc": "2.0",
                "method": "tools/list",  # This often returns immediately
                "params": {},
                "id": 2
            }
            
            # Use streaming to test SSE
            response_received = False
            sse_events = []
            
            async with self.client.stream("POST", url, headers=headers, json=stream_request, timeout=5.0) as response:
                if response.status_code in [200, 202] and "text/event-stream" in response.headers.get("content-type", ""):
                    # Read SSE events
                    async for line in response.aiter_lines():
                        if line.startswith("event:"):
                            event_type = line[6:].strip()
                            sse_events.append({"type": event_type})
                        elif line.startswith("data:") and sse_events:
                            try:
                                data = json.loads(line[5:].strip())
                                sse_events[-1]["data"] = data
                                if "jsonrpc" in data and "id" in data and data["id"] == 2:
                                    response_received = True
                                    break
                            except:
                                pass
                        
                        # Don't read forever
                        if len(sse_events) > 10:
                            break
            
            if sse_events:
                # Check SSE format compliance
                message_events = [e for e in sse_events if e.get("type") == "message"]
                if message_events:
                    test_results.append("✓ Server uses 'message' events for SSE as required")
                    details["sse_format_valid"] = True
                else:
                    all_passed = False
                    test_results.append("✗ Server doesn't use 'message' events for SSE data")
                    details["sse_format_invalid"] = True
                    details["sse_events"] = sse_events[:5]  # First 5 for debugging
                
                if response_received:
                    test_results.append("✓ Server can stream JSON-RPC responses via SSE")
                else:
                    test_results.append("⚠ SSE stream received but no JSON-RPC response found")
            else:
                test_results.append("⚠ Could not test SSE streaming (server may only support JSON)")
        except Exception as e:
            test_results.append(f"⚠ Failed to test SSE streaming: {str(e)}")
        
        # Test 4: Session management (optional feature)
        details["tests_performed"].append("session_management")
        if response is not None and hasattr(response, 'headers') and response.headers.get("mcp-session-id"):
            test_results.append("✓ Server implements session management")
            details["session_id"] = response.headers["mcp-session-id"]
            
            # Test session ID inclusion
            headers_with_session = self._get_headers({
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            })
            headers_with_session["MCP-Session-ID"] = details["session_id"]
            
            # Use same test request as before
            session_test_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {"clientInfo": {"name": "session-test", "version": "1.0"}},
                "id": 3
            }
            
            try:
                session_response = await self.client.post(
                    url, 
                    headers=headers_with_session, 
                    json=session_test_request, 
                    timeout=5.0
                )
                if session_response.status_code in [200, 202, 204]:
                    test_results.append("✓ Server accepts session ID in subsequent requests")
                else:
                    test_results.append(f"⚠ Server returned {session_response.status_code} with session ID")
            except:
                test_results.append("⚠ Failed to test session ID handling")
        else:
            test_results.append("ℹ Server does not implement session management (optional)")
        
        # Test 5: Security headers (for non-localhost)
        details["tests_performed"].append("security_headers")
        parsed = urlparse(url)
        if parsed.hostname not in ["localhost", "127.0.0.1", "::1"]:
            # Test Origin header validation
            headers_with_origin = self._get_headers({
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            })
            headers_with_origin["Origin"] = "https://evil.example.com"
            
            # Use a simple test request
            security_test_request = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {"clientInfo": {"name": "security-test", "version": "1.0"}},
                "id": 99
            }
            
            try:
                security_response = await self.client.post(
                    url,
                    headers=headers_with_origin,
                    json=security_test_request,
                    timeout=5.0
                )
                
                if security_response.status_code in [400, 403]:
                    test_results.append("✓ Server validates Origin header for security")
                    details["origin_validation"] = True
                else:
                    test_results.append("⚠ Server may not validate Origin header (recommended for security)")
                    details["origin_validation"] = False
            except:
                test_results.append("⚠ Could not test Origin validation")
        else:
            test_results.append("ℹ Origin validation not tested (localhost server)")
        
        # Compile results
        details["test_results"] = test_results
        
        # Check if we actually tested anything meaningful
        if not details.get("post_accepted") and details.get("post_rejected"):
            # POST was rejected - this is a failure for Streamable HTTP
            return False, (
                f"Streamable HTTP transport validation FAILED. "
                f"Server rejected POST request with status {details.get('response_status', 'unknown')}. "
                f"Streamable HTTP requires POST support."
            ), details
        elif not details.get("post_accepted") and not details.get("post_rejected"):
            # We couldn't even test POST (network error, etc)
            return False, (
                "Streamable HTTP transport validation FAILED. "
                "Could not complete basic POST request testing."
            ), details
        
        if all_passed:
            return True, (
                "Streamable HTTP transport validation PASSED. "
                "Server correctly implements required features: POST support, proper response types, "
                "and SSE message format compliance."
            ), details
        else:
            failures = [r for r in test_results if r.startswith("✗")]
            if failures:
                return False, (
                    f"Streamable HTTP transport validation FAILED. "
                    f"Issues found: {'; '.join(failures)}"
                ), details
            else:
                # Only warnings, technically passed
                return True, (
                    "Streamable HTTP transport validation PASSED with warnings. "
                    "All required features work, but some optional features or edge cases need attention."
                ), details