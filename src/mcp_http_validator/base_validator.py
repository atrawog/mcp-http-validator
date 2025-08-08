"""Base MCP Validator class with common utilities."""

import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from abc import ABC, abstractmethod

import httpx

from .models import (
    MCPServerInfo,
    TestCase,
    TestResult,
    TestStatus,
)
from .oauth import OAuthTestClient
from .env_manager import EnvManager


class BaseMCPValidator(ABC):
    """Base class for MCP validators with common utilities."""
    
    def __init__(
        self,
        server_url: str,
        access_token: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        env_file: Optional[str] = None,
        auto_register: bool = True,
        progress_callback: Optional[callable] = None,
    ):
        """Initialize the MCP validator.
        
        Args:
            server_url: Base URL of the MCP server to validate
            access_token: Optional OAuth access token for authenticated requests
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            env_file: Path to .env file for storing credentials
            auto_register: Whether to automatically register OAuth client if needed
            progress_callback: Optional callback for streaming test results
        """
        # Store both the base server URL and the MCP endpoint URL
        # For .well-known paths, we need the base domain
        # For MCP protocol, we use the exact URL provided
        self.server_url = server_url.rstrip("/")
        # Extract base URL for .well-known paths
        parsed = urlparse(server_url)
        self.api_url = f"{parsed.scheme}://{parsed.netloc}"
        self.mcp_endpoint = server_url  # Use exact URL for MCP endpoint
        self.access_token = access_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.auto_register = auto_register
        self.client = httpx.AsyncClient(timeout=timeout, verify=verify_ssl)
        self.test_results: List[TestResult] = []
        self.server_info: Optional[MCPServerInfo] = None
        self.oauth_client: Optional[OAuthTestClient] = None
        self.env_manager = EnvManager(env_file)
        self.progress_callback = progress_callback
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
        if self.oauth_client:
            await self.oauth_client.close()
    
    def _get_headers(self, additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Get request headers with optional authentication."""
        headers = {
            "Accept": "application/json",
            "MCP-Protocol-Version": "2025-06-18",
        }
        
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    async def _execute_test(self, test_case: TestCase, test_func) -> TestResult:
        """Execute a single test and record the result."""
        start_time = time.time()
        
        try:
            # Run the test function
            result = await test_func()
            
            # Handle different return formats
            if result is None or (isinstance(result, tuple) and result[0] is None):
                # Test was skipped
                status = TestStatus.SKIPPED
                passed = None
                message = result[1] if isinstance(result, tuple) else "Test skipped"
                details = result[2] if isinstance(result, tuple) and len(result) > 2 else {}
            else:
                # Normal test result
                passed, message, details = result
                status = TestStatus.PASSED if passed else TestStatus.FAILED
            
            result = TestResult(
                test_case=test_case,
                status=status,
                duration_ms=(time.time() - start_time) * 1000,
                message=message,
                error_message=message if status == TestStatus.FAILED else None,  # Keep for backward compatibility
                details=details,
            )
            
            # Call progress callback if provided
            if self.progress_callback:
                await self.progress_callback(result)
            
            return result
        except Exception as e:
            result = TestResult(
                test_case=test_case,
                status=TestStatus.ERROR,
                duration_ms=(time.time() - start_time) * 1000,
                message=str(e),
                error_message=str(e),  # Keep for backward compatibility
                details={"exception_type": type(e).__name__},
            )
            
            # Call progress callback if provided
            if self.progress_callback:
                await self.progress_callback(result)
            
            return result