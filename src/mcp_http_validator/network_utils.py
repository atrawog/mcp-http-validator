"""Network utilities for detecting public IPs and managing OAuth redirects."""

import socket
import ipaddress
import asyncio
import httpx
from typing import Optional, Tuple, List
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time
from urllib.parse import urlparse, parse_qs
import json


class NetworkInfo:
    """Network information and utilities."""
    
    @staticmethod
    def get_local_ips() -> List[str]:
        """Get all local IP addresses."""
        ips = []
        try:
            # Get hostname
            hostname = socket.gethostname()
            # Get all IPs for hostname
            for ip in socket.gethostbyname_ex(hostname)[2]:
                ips.append(ip)
                
            # Also try to get IPs from all interfaces
            import subprocess
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                import re
                # Extract IPv4 addresses
                for match in re.finditer(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout):
                    ip = match.group(1)
                    if ip not in ips:
                        ips.append(ip)
        except Exception:
            pass
            
        return ips
    
    @staticmethod
    def is_public_ip(ip_str: str) -> bool:
        """Check if an IP address is public (not private/local)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_reserved
            )
        except ValueError:
            return False
    
    @staticmethod
    async def detect_public_ip() -> Optional[str]:
        """Detect public IP address of this machine."""
        # First check local IPs
        local_ips = NetworkInfo.get_local_ips()
        for ip in local_ips:
            if NetworkInfo.is_public_ip(ip):
                return ip
        
        # If no public IP found locally, try external services
        external_services = [
            "https://api.ipify.org?format=json",
            "https://ipinfo.io/json",
            "https://api.myip.com"
        ]
        
        async with httpx.AsyncClient(timeout=5.0) as client:
            for service in external_services:
                try:
                    response = await client.get(service)
                    if response.status_code == 200:
                        data = response.json()
                        # Different services use different field names
                        ip = data.get("ip") or data.get("ipAddress")
                        if ip and NetworkInfo.is_public_ip(ip):
                            # Verify this IP actually belongs to us by checking local IPs
                            if ip in local_ips:
                                return ip
                except Exception:
                    continue
                    
        return None
    
    @staticmethod
    def find_available_port(start_port: int = 8080, max_attempts: int = 100) -> Optional[int]:
        """Find an available port starting from start_port."""
        for port in range(start_port, start_port + max_attempts):
            try:
                # Try to bind to the port
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_socket.bind(('', port))
                test_socket.close()
                return port
            except OSError:
                continue
        return None


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handle OAuth callback to extract authorization code."""
    
    def do_GET(self):
        """Handle GET request with authorization code."""
        # Parse the query parameters
        query = urlparse(self.path).query
        params = parse_qs(query)
        
        # Extract authorization code
        if 'code' in params:
            self.server.auth_code = params['code'][0]
            self.server.auth_state = params.get('state', [None])[0]
            
            # Send success response
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html_template = """
                <html>
                <head>
                    <title>Authorization Complete - MCP Validator</title>
                    <style>
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; 
                            text-align: center; 
                            padding: 50px;
                            background: #f5f5f5;
                        }
                        .container {
                            background: white;
                            border-radius: 10px;
                            padding: 40px;
                            max-width: 600px;
                            margin: 0 auto;
                            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        }
                        .success { 
                            color: #22c55e; 
                            font-size: 48px; 
                            margin: 0 0 20px 0;
                        }
                        h1 { 
                            color: #333; 
                            margin: 0 0 20px 0;
                            font-size: 28px;
                        }
                        .message {
                            color: #666;
                            font-size: 18px;
                            line-height: 1.6;
                            margin: 20px 0;
                        }
                        .important {
                            background: #e0f2fe;
                            border-left: 4px solid #0284c7;
                            padding: 15px 20px;
                            margin: 30px 0;
                            text-align: left;
                            border-radius: 4px;
                        }
                        .important strong {
                            color: #0369a1;
                            display: block;
                            margin-bottom: 5px;
                        }
                        .terminal {
                            background: #1e293b;
                            color: #e2e8f0;
                            padding: 10px 15px;
                            border-radius: 5px;
                            font-family: 'Monaco', 'Consolas', monospace;
                            font-size: 14px;
                            margin: 10px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="success">✓</div>
                        <h1>OAuth Authentication Complete!</h1>
                        
                        <p class="message">
                            The authorization code has been <strong>automatically captured</strong> by the MCP validator.
                        </p>
                        
                        <div class="important">
                            <strong>No action needed!</strong>
                            The authentication is already complete on your server. 
                            You do NOT need to copy any codes or URLs.
                        </div>
                        
                        <p class="message">
                            Please return to your terminal to see the results:
                        </p>
                        
                        <div class="terminal">
                            ✓ Authentication successful!<br>
                            Access token: 01d1d072841511...
                        </div>
                        
                        <p class="message" style="margin-top: 30px; color: #999;">
                            You can safely close this browser window.
                        </p>
                    </div>
                </body>
                </html>
            """
            self.wfile.write(html_template.encode())
        else:
            # Handle error
            error = params.get('error', ['unknown'])[0]
            error_desc = params.get('error_description', [''])[0]
            
            self.server.auth_error = f"{error}: {error_desc}" if error_desc else error
            
            # Send error response
            self.send_response(400)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            error_html = """
                <html>
                <head>
                    <title>Authorization Failed</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .error { color: red; font-size: 24px; }
                    </style>
                </head>
                <body>
                    <h1 class="error">✗ Authorization Failed</h1>
                    <p>%s</p>
                    <p>Please return to your terminal and try again.</p>
                </body>
                </html>
            """ % (error_desc or error)
            self.wfile.write(error_html.encode())
    
    def log_message(self, format, *args):
        """Suppress request logging."""
        pass


class OAuthCallbackServer:
    """Temporary OAuth callback server."""
    
    def __init__(self, host: str = '0.0.0.0', port: Optional[int] = None):
        """Initialize callback server.
        
        Args:
            host: Host to bind to (0.0.0.0 for all interfaces)
            port: Port to use (auto-detect if None)
        """
        self.host = host
        self.port = port or NetworkInfo.find_available_port()
        self.server = None
        self.thread = None
        
    def start(self) -> str:
        """Start the callback server.
        
        Returns:
            The callback URL
        """
        if not self.port:
            raise ValueError("No available port found")
            
        self.server = HTTPServer((self.host, self.port), OAuthCallbackHandler)
        self.server.auth_code = None
        self.server.auth_state = None
        self.server.auth_error = None
        
        # Run server in background thread
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
        return f"http://{self.host}:{self.port}/callback"
    
    async def wait_for_code(self, timeout: int = 300) -> Tuple[Optional[str], Optional[str]]:
        """Wait for authorization code.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            Tuple of (auth_code, error_message)
        """
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            if self.server.auth_code:
                return self.server.auth_code, None
            if self.server.auth_error:
                return None, self.server.auth_error
            await asyncio.sleep(0.5)
            
        return None, "Timeout waiting for authorization"
    
    def stop(self):
        """Stop the callback server."""
        if self.server:
            self.server.shutdown()
            self.server = None
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None


async def get_best_redirect_uri(prefer_public: bool = True) -> Tuple[str, Optional[OAuthCallbackServer]]:
    """Determine the best redirect URI based on network configuration.
    
    Args:
        prefer_public: Whether to prefer public IP if available
        
    Returns:
        Tuple of (redirect_uri, callback_server)
        If callback_server is None, use OOB flow
    """
    # Try to detect public IP
    public_ip = await NetworkInfo.detect_public_ip() if prefer_public else None
    
    if public_ip:
        # We have a public IP - use it for callback
        port = NetworkInfo.find_available_port(8080)
        if port:
            callback_server = OAuthCallbackServer(public_ip, port)
            callback_url = f"http://{public_ip}:{port}/callback"
            return callback_url, callback_server
    
    # Check if we can use localhost (only works if browser is on same machine)
    if not prefer_public:
        port = NetworkInfo.find_available_port(8080)
        if port:
            callback_server = OAuthCallbackServer('localhost', port)
            callback_url = f"http://localhost:{port}/callback"
            return callback_url, callback_server
    
    # Fall back to OOB
    return "urn:ietf:wg:oauth:2.0:oob", None