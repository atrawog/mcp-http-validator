"""MCP Transport Detection and Testing."""

from enum import Enum
from typing import Optional, Dict, Any, Tuple
import httpx
from dataclasses import dataclass


class TransportType(str, Enum):
    """MCP Transport Types."""
    HTTP_SSE = "http_sse"  # HTTP with SSE (GET only)
    STREAMABLE_HTTP = "streamable_http"  # POST with JSON or SSE response
    JSON_RPC = "json_rpc"  # POST with JSON response only
    UNKNOWN = "unknown"


@dataclass
class TransportCapabilities:
    """Detected transport capabilities of an MCP server."""
    primary_transport: TransportType
    supports_get_sse: bool = False
    supports_post_json: bool = False
    supports_post_sse: bool = False
    get_response_type: Optional[str] = None
    post_response_type: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    
    def describe(self) -> str:
        """Human-readable description of capabilities."""
        if self.primary_transport == TransportType.HTTP_SSE:
            return "HTTP with SSE transport (GET requests only, SSE responses)"
        elif self.primary_transport == TransportType.STREAMABLE_HTTP:
            modes = []
            if self.supports_post_json:
                modes.append("JSON")
            if self.supports_post_sse:
                modes.append("SSE")
            return f"Streamable HTTP transport (POST requests, {' or '.join(modes)} responses)"
        elif self.primary_transport == TransportType.JSON_RPC:
            return "JSON-RPC transport (POST requests, JSON responses only)"
        else:
            return "Unknown transport type"


class TransportDetector:
    """Detects MCP server transport capabilities."""
    
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
    
    async def detect(self, url: str, headers: Dict[str, str]) -> TransportCapabilities:
        """Detect transport capabilities of an MCP server.
        
        Tests both GET and POST methods with appropriate Accept headers
        to determine what transport methods the server supports.
        """
        caps = TransportCapabilities(primary_transport=TransportType.UNKNOWN)
        error_details = {}
        
        # Test GET with SSE accept header
        get_sse_result = await self._test_get_sse(url, headers)
        if get_sse_result[0]:
            caps.supports_get_sse = True
            caps.get_response_type = get_sse_result[1]
        elif get_sse_result[2]:  # Error details
            error_details["get_sse"] = get_sse_result[2]
        
        # Test POST with JSON
        post_json_result = await self._test_post_json(url, headers)
        if post_json_result[0]:
            caps.supports_post_json = True
            caps.post_response_type = post_json_result[1]
        elif post_json_result[2]:  # Error details
            error_details["post_json"] = post_json_result[2]
        
        # Test POST with SSE accept
        post_sse_result = await self._test_post_sse(url, headers)
        if post_sse_result[0]:
            caps.supports_post_sse = True
            if not caps.post_response_type:
                caps.post_response_type = post_sse_result[1]
        elif post_sse_result[2]:  # Error details
            error_details["post_sse"] = post_sse_result[2]
        
        # Store error details if no transport was detected
        if not (caps.supports_get_sse or caps.supports_post_json or caps.supports_post_sse):
            caps.error_details = error_details
        
        # Determine primary transport type
        if caps.supports_get_sse and not caps.supports_post_json and not caps.supports_post_sse:
            caps.primary_transport = TransportType.HTTP_SSE
        elif caps.supports_post_json or caps.supports_post_sse:
            if caps.supports_post_sse:
                caps.primary_transport = TransportType.STREAMABLE_HTTP
            else:
                caps.primary_transport = TransportType.JSON_RPC
        
        return caps
    
    async def _test_get_sse(self, url: str, base_headers: Dict[str, str]) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Test GET request with SSE accept header."""
        headers = base_headers.copy()
        headers["Accept"] = "text/event-stream"
        
        try:
            # Use stream=True to handle SSE connections properly
            # Set a very short timeout for just the initial connection
            async with self.client.stream("GET", url, headers=headers, timeout=5.0) as response:
                if response.status_code == 200:
                    content_type = response.headers.get("content-type", "")
                    if "text/event-stream" in content_type:
                        # Try to read a small amount to verify it's actually SSE
                        # SSE servers will send data or keep connection open
                        # For SSE, just having the right content-type is enough
                        # We don't need to read data - SSE streams stay open
                        return True, content_type, None
                elif response.status_code == 405:
                    # Method not allowed - server doesn't support GET
                    return False, None, {"status_code": 405, "reason": "Method not allowed"}
                elif response.status_code == 401:
                    # Unauthorized - might need auth first
                    return False, None, {"status_code": 401, "reason": "Authentication required"}
                elif response.status_code >= 400:
                    # Client error
                    return False, None, {"status_code": response.status_code, "reason": f"HTTP {response.status_code} error"}
                return False, None, {"status_code": response.status_code, "content_type": response.headers.get("content-type", "")}
        except (httpx.TimeoutException, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
            # These might be expected for SSE connections, but could also indicate issues
            return False, None, {"error": "timeout", "type": type(e).__name__}
        except Exception as e:
            return False, None, {"error": str(e), "type": type(e).__name__}
    
    async def _test_post_json(self, url: str, base_headers: Dict[str, str]) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Test POST request with JSON accept header."""
        headers = base_headers.copy()
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"
        
        # Minimal JSON-RPC request
        test_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            # Use a shorter timeout for transport detection
            response = await self.client.post(url, headers=headers, json=test_request, timeout=httpx.Timeout(5.0))
            if response.status_code in [200, 202]:
                content_type = response.headers.get("content-type", "")
                if "application/json" in content_type:
                    return True, content_type, None
                else:
                    # Success but not JSON - might be SSE or other format
                    return False, None, {"status_code": response.status_code, "content_type": content_type}
            elif response.status_code == 405:
                # Don't treat 405 Method Not Allowed as an error - it's expected for GET-only servers
                return False, None, {"status_code": 405, "reason": "POST not supported"}
            elif response.status_code == 401:
                return False, None, {"status_code": 401, "reason": "Authentication required"}
            elif response.status_code == 404:
                return False, None, {"status_code": 404, "reason": "Endpoint not found - may need path like /mcp"}
            else:
                return False, None, {"status_code": response.status_code, "content_type": response.headers.get("content-type", "")}
        except httpx.TimeoutException as e:
            return False, None, {"error": "timeout", "type": type(e).__name__}
        except Exception as e:
            return False, None, {"error": str(e), "type": type(e).__name__}
    
    async def _test_post_sse(self, url: str, base_headers: Dict[str, str]) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Test POST request with SSE accept header."""
        headers = base_headers.copy()
        headers["Accept"] = "text/event-stream"
        headers["Content-Type"] = "application/json"
        
        test_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            # Use a shorter timeout for transport detection
            response = await self.client.post(url, headers=headers, json=test_request, timeout=httpx.Timeout(5.0))
            if response.status_code in [200, 202]:
                content_type = response.headers.get("content-type", "")
                if "text/event-stream" in content_type:
                    return True, content_type, None
                else:
                    # Success but not SSE - likely JSON response
                    return False, None, {"status_code": response.status_code, "content_type": content_type}
            elif response.status_code == 405:
                # Don't treat 405 Method Not Allowed as an error - it's expected for GET-only servers
                return False, None, {"status_code": 405, "reason": "POST not supported"}
            elif response.status_code == 401:
                return False, None, {"status_code": 401, "reason": "Authentication required"}
            else:
                return False, None, {"status_code": response.status_code, "content_type": response.headers.get("content-type", "")}
        except httpx.TimeoutException as e:
            return False, None, {"error": "timeout", "type": type(e).__name__}
        except Exception as e:
            return False, None, {"error": str(e), "type": type(e).__name__}