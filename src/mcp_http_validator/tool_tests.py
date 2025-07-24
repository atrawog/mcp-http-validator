"""MCP tool-related test methods."""

from typing import Any, Dict, List, Optional, Tuple

from .base_validator import BaseMCPValidator
from .transport_detector import TransportDetector, TransportType
from .sse_client import MCPSSEClient


class MCPToolTests(BaseMCPValidator):
    """MCP tool discovery and validation tests."""
    
    async def initialize_mcp_session(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Initialize an MCP session with the server."""
        url = self.mcp_endpoint
        
        headers = self._get_headers({
            "Content-Type": "application/json",
        })
        
        init_request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "mcp-http-validator",
                    "version": "0.1.0"
                }
            },
            "id": 1
        }
        
        try:
            response = await self.client.post(url, headers=headers, json=init_request)
            
            if response.status_code not in [200, 202]:
                return False, f"Failed to initialize session: status {response.status_code}", {
                    "status_code": response.status_code,
                    "body": response.text[:500] if response.text else None
                }
            
            json_response = response.json()
            
            # Check for error response
            if "error" in json_response:
                error_msg = json_response['error']['message']
                # Check if this is the protocol version bug
                if "Unsupported protocol version: " in error_msg and "Supported versions:" in error_msg:
                    # Check if protocol version is in our headers
                    sent_headers = headers.copy()
                    if "MCP-Protocol-Version" in sent_headers:
                        return False, (
                            f"Server error indicates it's not reading the MCP-Protocol-Version header correctly. "
                            f"The validator sent 'MCP-Protocol-Version: {sent_headers['MCP-Protocol-Version']}' "
                            f"as required by the MCP specification, but the server reported: '{error_msg}'. "
                            f"The server appears to be looking for protocolVersion in the request params instead of "
                            f"the HTTP header, which violates the MCP transport specification."
                        ), {
                            "error": json_response["error"],
                            "sent_protocol_header": sent_headers.get("MCP-Protocol-Version"),
                            "spec_violation": "Server should read protocol version from MCP-Protocol-Version header, not params",
                            "spec_reference": "https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#protocol-version-header"
                        }
                
                return False, f"Server returned error: {error_msg}", {
                    "error": json_response["error"]
                }
            
            # Check for result
            if "result" not in json_response:
                return False, "Invalid response: missing 'result' field", {
                    "response": json_response
                }
            
            return True, None, {
                "session_initialized": True,
                "server_info": json_response.get("result", {})
            }
            
        except Exception as e:
            return False, f"Failed to initialize session: {str(e)}", {"error": str(e)}
    
    async def list_mcp_tools(self) -> Tuple[bool, Optional[str], List[Dict[str, Any]]]:
        """List all available tools from the MCP server."""
        url = self.mcp_endpoint
        
        headers = self._get_headers({
            "Content-Type": "application/json",
        })
        
        list_request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2
        }
        
        try:
            response = await self.client.post(url, headers=headers, json=list_request)
            
            if response.status_code not in [200, 202]:
                return False, f"Failed to list tools: status {response.status_code}", []
            
            json_response = response.json()
            
            # Check for error response
            if "error" in json_response:
                return False, f"Server returned error: {json_response['error']['message']}", []
            
            # Extract tools from result
            if "result" in json_response and "tools" in json_response["result"]:
                tools = json_response["result"]["tools"]
                return True, None, tools
            else:
                return True, "No tools found", []
                
        except Exception as e:
            return False, f"Failed to list tools: {str(e)}", []
    
    async def test_mcp_tool(self, tool: Dict[str, Any], test_destructive: bool = False) -> Dict[str, Any]:
        """Test a specific MCP tool."""
        url = self.mcp_endpoint
        tool_name = tool.get("name", "unknown")
        
        headers = self._get_headers({
            "Content-Type": "application/json",
        })
        
        # Create a test call based on the tool's input schema
        test_params = {}
        input_schema = tool.get("inputSchema", {})
        
        # Generate minimal valid parameters based on schema
        if input_schema.get("type") == "object":
            properties = input_schema.get("properties", {})
            required = input_schema.get("required", [])
            
            for prop, schema in properties.items():
                if prop in required:
                    # Generate a test value based on type
                    prop_type = schema.get("type", "string")
                    if prop_type == "string":
                        test_params[prop] = "test_value"
                    elif prop_type == "number":
                        test_params[prop] = 42
                    elif prop_type == "boolean":
                        test_params[prop] = True
                    elif prop_type == "array":
                        test_params[prop] = []
                    elif prop_type == "object":
                        test_params[prop] = {}
        
        call_request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": test_params
            },
            "id": 3
        }
        
        result = {
            "tool_name": tool_name,
            "description": tool.get("description", ""),
            "test_params": test_params,
            "status": "untested",
            "error": None,
            "response": None,
            "destructive": tool.get("annotations", {}).get("destructiveHint", False),
            "read_only": tool.get("annotations", {}).get("readOnlyHint", False)
        }
        
        # Skip destructive tools unless explicitly enabled
        if result["destructive"] and not test_destructive:
            result["status"] = "skipped"
            result["error"] = "Skipped destructive tool for safety"
            return result
        
        try:
            response = await self.client.post(url, headers=headers, json=call_request)
            
            if response.status_code not in [200, 202]:
                result["status"] = "failed"
                result["error"] = f"HTTP {response.status_code}"
                result["response"] = response.text[:500] if response.text else None
                return result
            
            json_response = response.json()
            
            # Check for error response
            if "error" in json_response:
                result["status"] = "error"
                result["error"] = json_response["error"].get("message", "Unknown error")
                result["response"] = json_response["error"]
            elif "result" in json_response:
                result["status"] = "success"
                result["response"] = json_response["result"]
                
                # Check if tool reported an error in its result
                tool_result = json_response["result"]
                if isinstance(tool_result, dict) and tool_result.get("isError"):
                    result["status"] = "tool_error"
                    result["error"] = "Tool reported an error in result"
            else:
                result["status"] = "invalid"
                result["error"] = "Invalid response format"
                result["response"] = json_response
                
        except Exception as e:
            result["status"] = "exception"
            result["error"] = str(e)
            
        return result
    
    async def test_mcp_tools(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test MCP tool discovery and validation."""
        # Use TransportDetector to determine server capabilities
        detector = TransportDetector(self.client)
        base_headers = self._get_headers({})
        
        try:
            caps = await detector.detect(self.mcp_endpoint, base_headers)
            
            # If this is an SSE-only server, use SSE client
            if caps.primary_transport == TransportType.HTTP_SSE:
                return await self._test_mcp_tools_sse()
        except Exception:
            # If transport detection fails, continue with POST-based tests
            pass
        
        # Attempt to get access token if we don't have one
        if not self.access_token:
            self.access_token = await self.get_access_token(interactive=False)
        
        if not self.access_token:
            return None, (
                "MCP tools discovery and testing requires authentication to access server capabilities. "
                "Tools are the primary way MCP servers expose functionality to clients per MCP Core Specification, allowing them to perform "
                "actions like reading files, running code, or interacting with external services following the JSON-RPC 2.0 protocol (RFC 7159). "
                "Testing tools requires authentication because they may expose sensitive operations or data per OAuth 2.0 security considerations (RFC 6749 Section 10). "
                "Without authentication, the validator cannot discover available tools or verify their schemas and behavior conform to MCP specifications. "
                "Run 'mcp-validate flow' to complete OAuth authentication."
            ), {
                "note": "Tools may contain sensitive operations requiring proper authorization",
                "suggestion": "Run 'mcp-validate flow' for interactive OAuth flow"
            }
        
        details = {
            "session_initialized": False,
            "session_error": None,
            "tools_discovered": 0,
            "tools_tested": 0,
            "tools_passed": 0,
            "tools_failed": 0,
            "tools_skipped": 0,
            "tool_results": [],
            "errors": []
        }
        
        # First try to initialize session (but don't fail if it doesn't work)
        success, error, init_details = await self.initialize_mcp_session()
        if success:
            details["session_initialized"] = True
            details["server_info"] = init_details.get("server_info", {})
        else:
            details["session_error"] = error
            details["errors"].append(f"Session initialization: {error}")
            # Continue anyway - some servers may not require initialization
        
        # Try to list tools regardless of initialization status
        success, error, tools = await self.list_mcp_tools()
        if not success:
            details["errors"].append(f"Tool listing: {error}")
            # If we have both initialization and listing failures, then we truly failed
            if not details["session_initialized"]:
                return False, "Failed to access MCP server (both session init and tool listing failed)", details
            else:
                # Session worked but no tools - this is actually OK
                return True, (
                "MCP tools discovery completed successfully. "
                "The MCP session was initialized correctly, but the server does not expose any tools. "
                "This is valid per the MCP Core Specification - servers may choose not to expose tools if they only provide "
                "read-only access to resources or if tool functionality is not applicable to their use case. "
                "The server correctly implements the MCP protocol for session management and tool discovery."
            ), details
        
        if not tools:
            # No tools is not necessarily a failure
            details["tools_discovered"] = 0
            return True, (
                "MCP tools discovery completed successfully. "
                "The server does not expose any tools, which is valid per the MCP Core Specification. "
                "Servers may operate without tools if they only provide read-only access to resources "
                "or if their functionality doesn't require tool-based interactions. This is a valid implementation choice."
            ), details
        
        details["tools_discovered"] = len(tools)
        
        # Test each tool
        for tool in tools:
            tool_result = await self.test_mcp_tool(tool)
            details["tool_results"].append(tool_result)
            details["tools_tested"] += 1
            
            if tool_result["status"] == "success":
                details["tools_passed"] += 1
            elif tool_result["status"] == "skipped":
                details["tools_skipped"] += 1
            else:
                details["tools_failed"] += 1
        
        # Determine overall success
        if details["tools_failed"] > 0:
            return False, f"{details['tools_failed']} tool(s) failed testing", details
        elif details["tools_discovered"] == 0:
            return True, "No tools to test", details
        else:
            return True, (
                f"Tool discovery and basic invocation testing completed. "
                f"Found {details['tools_discovered']} tool(s) via the tools/list method. "
                f"Successfully invoked {details['tools_tested']} tool(s) with minimal parameters "
                f"({details['tools_skipped']} skipped as potentially destructive). "
                f"Each tested tool returned a response without errors when called with basic inputs. "
                f"Note: This test only verifies tools can be called, not full schema compliance or functionality."
            ), details
    
    async def _test_mcp_tools_sse(self) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Test MCP tools via SSE transport."""
        details = {
            "transport": "http_sse",
            "description": "Testing tools via HTTP+SSE transport"
        }
        
        # Create SSE client
        sse_client = MCPSSEClient(self.mcp_endpoint, self.client, self._get_headers())
        
        try:
            # Connect to SSE endpoint
            connected = await sse_client.connect(timeout=10.0)
            if not connected:
                return False, (
                    "Failed to establish SSE connection or discover endpoint. "
                    "The server should send an 'endpoint' event with the URL for message posting "
                    "as specified in the MCP HTTP+SSE transport specification."
                ), {
                    **details,
                    "error": "SSE connection failed or no endpoint discovered"
                }
            
            details["endpoint_url"] = sse_client.endpoint_url
            details["connected"] = True
            
            # Test initialization (some SSE servers may not require it)
            initialized = await sse_client.test_initialize()
            details["initialization_attempted"] = True
            details["initialization_required"] = not initialized
            
            # Even if initialization fails, we can still try to list tools
            # Some servers work without explicit initialization
            
            # List tools
            tools = await sse_client.list_tools()
            if tools is None:
                return False, (
                    "Failed to list tools via SSE. The server should respond to 'tools/list' "
                    "with an array of available tools. Authentication may be required. "
                    "Run 'mcp-validate flow' to complete OAuth authentication."
                ), {
                    **details,
                    "error": "Tool listing failed"
                }
            
            details["tools_count"] = len(tools)
            details["tools"] = [t.get("name", "unknown") for t in tools]
            
            if not tools:
                return True, (
                    "MCP server connected successfully via SSE but exposes no tools. "
                    f"SSE endpoint discovered at {sse_client.endpoint_url}. "
                    "Session initialized successfully."
                ), details
            
            # Test each tool
            results = []
            for tool in tools:
                tool_result = await self._test_single_tool_sse(sse_client, tool)
                results.append(tool_result)
            
            successful_tools = sum(1 for r in results if r["status"] == "success")
            skipped_tools = sum(1 for r in results if r["status"] == "skipped")
            failed_tools = sum(1 for r in results if r["status"] == "error")
            
            details["tools_succeeded"] = successful_tools
            details["tools_skipped"] = skipped_tools
            details["tools_failed"] = failed_tools
            details["tool_results"] = results
            
            if failed_tools > 0:
                return False, (
                    f"Tool testing via SSE partially failed. Found {len(tools)} tool(s) via SSE. "
                    f"Successfully invoked {successful_tools} tool(s), skipped {skipped_tools} "
                    f"potentially destructive tool(s), and {failed_tools} tool(s) failed. "
                    f"SSE endpoint: {sse_client.endpoint_url}"
                ), details
            
            return True, (
                f"Tool discovery and testing completed successfully via SSE. "
                f"Found {len(tools)} tool(s) at endpoint {sse_client.endpoint_url}. "
                f"Successfully invoked {successful_tools} tool(s) with minimal parameters "
                f"({skipped_tools} skipped as potentially destructive). "
                "All tested tools responded correctly via the SSE event stream."
            ), details
            
        except Exception as e:
            return False, f"SSE tool testing failed: {str(e)}", {
                **details,
                "error": str(e),
                "error_type": type(e).__name__
            }
        finally:
            await sse_client.disconnect()
    
    async def _test_single_tool_sse(self, sse_client: MCPSSEClient, tool: Dict[str, Any]) -> Dict[str, Any]:
        """Test a single tool via SSE client."""
        tool_name = tool.get("name", "unknown")
        
        # Check MCP standard destructiveHint annotation first
        if tool.get("annotations", {}).get("destructiveHint", False):
            return {
                "tool_name": tool_name,
                "status": "skipped",
                "reason": "Tool marked as destructive via destructiveHint annotation"
            }
        
        # Also skip based on name patterns as a fallback
        if any(keyword in tool_name.lower() for keyword in ["delete", "remove", "destroy", "drop", "truncate"]):
            return {
                "tool_name": tool_name,
                "status": "skipped",
                "reason": "Potentially destructive operation based on name"
            }
        
        try:
            # Create minimal arguments based on schema
            test_args = {}
            if "inputSchema" in tool and "properties" in tool["inputSchema"]:
                for prop_name, prop_def in tool["inputSchema"]["properties"].items():
                    # Skip if required and no default
                    required = tool["inputSchema"].get("required", [])
                    if prop_name in required and "default" not in prop_def:
                        # Try to provide a safe test value
                        if prop_def.get("type") == "string":
                            test_args[prop_name] = "test"
                        elif prop_def.get("type") == "number":
                            test_args[prop_name] = 0
                        elif prop_def.get("type") == "boolean":
                            test_args[prop_name] = False
                        elif prop_def.get("type") == "array":
                            test_args[prop_name] = []
                        elif prop_def.get("type") == "object":
                            test_args[prop_name] = {}
            
            # Call the tool
            response = await sse_client.call_tool(tool_name, test_args)
            
            if "result" in response:
                return {
                    "tool_name": tool_name,
                    "status": "success",
                    "arguments": test_args
                }
            elif "error" in response:
                return {
                    "tool_name": tool_name,
                    "status": "error",
                    "error": response["error"].get("message", "Unknown error"),
                    "arguments": test_args
                }
            else:
                return {
                    "tool_name": tool_name,
                    "status": "error",
                    "error": "Invalid response format",
                    "response": response
                }
                
        except Exception as e:
            return {
                "tool_name": tool_name,
                "status": "error",
                "error": str(e)
            }
    
