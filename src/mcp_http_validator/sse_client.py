"""SSE Client for MCP HTTP+SSE transport validation."""

import asyncio
import json
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
import httpx
from datetime import datetime, timedelta


@dataclass 
class SSEMessage:
    """Represents a Server-Sent Event message."""
    event: Optional[str] = None
    data: Optional[str] = None
    id: Optional[str] = None
    retry: Optional[int] = None


class MCPSSEClient:
    """Client for MCP servers using HTTP+SSE transport.
    
    Handles the SSE connection, endpoint discovery, and message exchange
    pattern required by MCP HTTP+SSE transport specification.
    """
    
    def __init__(self, api_url: str, client: httpx.AsyncClient, headers: Optional[Dict[str, str]] = None):
        """Initialize SSE client.
        
        Args:
            api_url: The SSE endpoint URL
            client: HTTP client to use for requests
            headers: Optional headers to include in requests
        """
        self.api_url = api_url
        self.client = client
        self.headers = headers or {}
        self.endpoint_url: Optional[str] = None
        self.sse_task: Optional[asyncio.Task] = None
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.connected = False
        self._response_futures: Dict[int, asyncio.Future] = {}
        self._next_id = 1
        
    async def connect(self, timeout: float = 10.0) -> bool:
        """Establish SSE connection and wait for endpoint discovery.
        
        Args:
            timeout: Maximum time to wait for endpoint event
            
        Returns:
            True if connected and endpoint discovered, False otherwise
        """
        try:
            # Start SSE connection
            self.sse_task = asyncio.create_task(self._sse_reader())
            
            # Wait for endpoint discovery
            start_time = datetime.now()
            while not self.endpoint_url and (datetime.now() - start_time).total_seconds() < timeout:
                await asyncio.sleep(0.1)
                
            if self.endpoint_url:
                self.connected = True
                return True
            else:
                await self.disconnect()
                return False
                
        except Exception:
            await self.disconnect()
            return False
    
    async def disconnect(self):
        """Close SSE connection and cleanup."""
        self.connected = False
        if self.sse_task and not self.sse_task.done():
            self.sse_task.cancel()
            try:
                await self.sse_task
            except asyncio.CancelledError:
                pass
        
        # Cancel any pending response futures
        for future in self._response_futures.values():
            if not future.done():
                future.cancel()
        self._response_futures.clear()
    
    async def _sse_reader(self):
        """Read SSE events from the server."""
        headers = {**self.headers, "Accept": "text/event-stream"}
        
        try:
            async with self.client.stream("GET", self.api_url, headers=headers) as response:
                if response.status_code != 200:
                    return
                    
                buffer = ""
                message = SSEMessage()
                
                async for line in response.aiter_lines():
                    if not line:  # Empty line = end of message
                        if message.event or message.data:
                            await self._handle_sse_message(message)
                        message = SSEMessage()
                        continue
                    
                    if line.startswith("event:"):
                        message.event = line[6:].strip()
                    elif line.startswith("data:"):
                        data = line[5:].strip()
                        if message.data:
                            message.data += "\n" + data
                        else:
                            message.data = data
                    elif line.startswith("id:"):
                        message.id = line[3:].strip()
                    elif line.startswith("retry:"):
                        try:
                            message.retry = int(line[6:].strip())
                        except ValueError:
                            pass
                            
        except asyncio.CancelledError:
            raise
        except Exception:
            # Connection error - mark as disconnected
            self.connected = False
    
    async def _handle_sse_message(self, message: SSEMessage):
        """Handle an SSE message from the server."""
        if message.event == "endpoint":
            # Extract endpoint URL from data
            if message.data:
                # Handle both absolute and relative URLs
                endpoint = message.data.strip()
                if endpoint.startswith("/"):
                    # Relative URL - combine with base
                    from urllib.parse import urlparse, urljoin
                    parsed = urlparse(self.api_url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    self.endpoint_url = urljoin(base, endpoint)
                else:
                    # Absolute URL
                    self.endpoint_url = endpoint
                    
        elif message.event == "message" and message.data:
            # MCP response message
            try:
                response_data = json.loads(message.data)
                if "id" in response_data and response_data["id"] in self._response_futures:
                    future = self._response_futures.pop(response_data["id"])
                    if not future.done():
                        future.set_result(response_data)
            except json.JSONDecodeError:
                pass
        
        # Store all messages in queue for inspection
        await self.message_queue.put(message)
    
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 30.0) -> Dict[str, Any]:
        """Send a JSON-RPC request via the discovered endpoint.
        
        Args:
            method: JSON-RPC method name
            params: Optional parameters
            timeout: Request timeout
            
        Returns:
            JSON-RPC response
            
        Raises:
            Exception if not connected or request fails
        """
        if not self.connected or not self.endpoint_url:
            raise Exception("Not connected or endpoint not discovered")
        
        # Create request
        request_id = self._next_id
        self._next_id += 1
        
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "id": request_id
        }
        if params:
            request["params"] = params
        
        # Create future for response
        response_future = asyncio.Future()
        self._response_futures[request_id] = response_future
        
        try:
            # Send request to endpoint
            headers = {**self.headers, "Content-Type": "application/json"}
            response = await self.client.post(
                self.endpoint_url,
                headers=headers,
                json=request,
                timeout=5.0
            )
            
            if response.status_code not in [200, 202, 204]:
                raise Exception(f"Request failed with status {response.status_code}")
            
            # For 202 Accepted, the response comes via SSE, not the HTTP response
            if response.status_code == 202:
                # Response will come through SSE stream
                pass
            elif response.status_code == 200:
                # Some servers might return response directly
                try:
                    direct_response = response.json()
                    if "id" in direct_response and direct_response["id"] == request_id:
                        return direct_response
                except Exception:
                    pass
            
            # Wait for response via SSE
            try:
                return await asyncio.wait_for(response_future, timeout=timeout)
            except asyncio.TimeoutError:
                raise Exception(f"Timeout waiting for response to {method}")
                
        finally:
            # Clean up future if still pending
            if request_id in self._response_futures:
                self._response_futures.pop(request_id)
                if not response_future.done():
                    response_future.cancel()
    
    async def test_initialize(self) -> bool:
        """Test MCP initialization via SSE.
        
        Some SSE servers may not require initialization.
        
        Returns:
            True if initialization succeeds or is not required
        """
        try:
            # Try to initialize
            response = await self.send_request(
                "initialize",
                {
                    "clientInfo": {
                        "name": "mcp-http-validator",
                        "version": "0.1.0"
                    }
                },
                timeout=5.0
            )
            return "result" in response
        except Exception:
            # Initialization might not be required - try a simple method
            try:
                # Try listing tools to see if server works without init
                response = await self.send_request("tools/list", timeout=5.0)
                if "result" in response:
                    # Server works without initialization
                    return True
            except Exception:
                pass
            return False
    
    async def list_tools(self) -> Optional[list]:
        """List available tools via SSE.
        
        Returns:
            List of tools or None if failed
        """
        try:
            response = await self.send_request("tools/list")
            if "result" in response and "tools" in response["result"]:
                return response["result"]["tools"]
            return None
        except Exception:
            return None
    
    async def call_tool(self, tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Call a tool via SSE.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
            
        Returns:
            Tool response
        """
        return await self.send_request(
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments or {}
            }
        )