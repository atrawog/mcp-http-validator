"""Environment file management utilities."""

import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from dotenv import dotenv_values, set_key


class EnvManager:
    """Manages .env file for storing OAuth credentials and configuration."""
    
    def __init__(self, env_file: Optional[Path] = None):
        """Initialize environment manager.
        
        Args:
            env_file: Path to .env file (defaults to current directory)
        """
        self.env_file = env_file or Path(".env")
        self._ensure_env_file()
    
    def _ensure_env_file(self):
        """Ensure .env file exists."""
        if not self.env_file.exists():
            # Create from example if it exists
            example_file = self.env_file.parent / ".env.example"
            if example_file.exists():
                self.env_file.write_text(example_file.read_text())
            else:
                # Create empty file
                self.env_file.touch()
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get value from .env file.
        
        Args:
            key: Environment variable key
            default: Default value if not found
        
        Returns:
            Value from .env file or default
        """
        values = dotenv_values(self.env_file)
        return values.get(key, default)
    
    def set(self, key: str, value: str) -> bool:
        """Set value in .env file.
        
        Args:
            key: Environment variable key
            value: Value to set
        
        Returns:
            True if successful
        """
        try:
            set_key(str(self.env_file), key, value)
            # Also set in current environment
            os.environ[key] = value
            return True
        except Exception:
            return False
    
    def update(self, values: Dict[str, str]) -> bool:
        """Update multiple values in .env file.
        
        Args:
            values: Dictionary of key-value pairs
        
        Returns:
            True if all updates successful
        """
        success = True
        for key, value in values.items():
            if not self.set(key, value):
                success = False
        return success
    
    def delete(self, key: str) -> bool:
        """Delete a key from .env file.
        
        Args:
            key: Environment variable key to delete
        
        Returns:
            True if successful
        """
        try:
            # set_key with empty value removes the key
            set_key(str(self.env_file), key, "")
            # Also remove from current environment
            if key in os.environ:
                del os.environ[key]
            return True
        except Exception:
            return False
    
    def get_oauth_credentials(self, server_url: str) -> Dict[str, Optional[str]]:
        """Get OAuth credentials for a specific server.
        
        Args:
            server_url: MCP server URL
        
        Returns:
            Dictionary with client_id, client_secret, and registration_token
        """
        # Normalize server URL to create consistent keys
        server_key = server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").replace("-", "_").upper()
        
        return {
            "client_id": self.get(f"OAUTH_CLIENT_ID_{server_key}"),
            "client_secret": self.get(f"OAUTH_CLIENT_SECRET_{server_key}"),
            "registration_token": self.get(f"OAUTH_REGISTRATION_TOKEN_{server_key}"),
            "redirect_uri": self.get(f"OAUTH_REDIRECT_URI_{server_key}"),
        }
    
    def save_oauth_credentials(
        self,
        server_url: str,
        client_id: str,
        client_secret: Optional[str] = None,
        registration_token: Optional[str] = None,
        redirect_uri: Optional[str] = None,
    ) -> bool:
        """Save OAuth credentials for a specific server.
        
        Args:
            server_url: MCP server URL
            client_id: OAuth client ID
            client_secret: OAuth client secret
            registration_token: Client registration access token
            redirect_uri: OAuth redirect URI used during registration
        
        Returns:
            True if successful
        """
        # Normalize server URL - replace all non-alphanumeric chars with underscores
        server_key = server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").replace("-", "_").upper()
        
        values = {
            f"OAUTH_CLIENT_ID_{server_key}": client_id,
        }
        
        if client_secret:
            values[f"OAUTH_CLIENT_SECRET_{server_key}"] = client_secret
        
        if registration_token:
            values[f"OAUTH_REGISTRATION_TOKEN_{server_key}"] = registration_token
            
        if redirect_uri:
            values[f"OAUTH_REDIRECT_URI_{server_key}"] = redirect_uri
        
        return self.update(values)
    
    def save_tokens(
        self,
        server_url: str,
        access_token: str,
        expires_in: int,
        refresh_token: Optional[str] = None,
    ) -> bool:
        """Save OAuth tokens for a specific server.
        
        Args:
            server_url: MCP server URL
            access_token: OAuth access token
            expires_in: Token lifetime in seconds
            refresh_token: Optional refresh token
        
        Returns:
            True if successful
        """
        # Normalize server URL - replace all non-alphanumeric chars with underscores
        server_key = server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").replace("-", "_").upper()
        
        # Calculate expiration timestamp (with 5 minute buffer for safety)
        expires_at = int(time.time()) + expires_in - 300
        
        values = {
            f"OAUTH_ACCESS_TOKEN_{server_key}": access_token,
            f"OAUTH_TOKEN_EXPIRES_AT_{server_key}": str(expires_at),
        }
        
        if refresh_token:
            values[f"OAUTH_REFRESH_TOKEN_{server_key}"] = refresh_token
        
        return self.update(values)
    
    def get_valid_access_token(self, server_url: str) -> Optional[str]:
        """Get access token if it exists and hasn't expired.
        
        Args:
            server_url: MCP server URL
            
        Returns:
            Valid access token or None if expired/missing
        """
        server_key = server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").replace("-", "_").upper()
        
        access_token = self.get(f"OAUTH_ACCESS_TOKEN_{server_key}")
        expires_at = self.get(f"OAUTH_TOKEN_EXPIRES_AT_{server_key}")
        
        if not access_token or not expires_at:
            return None
            
        try:
            # Check if token has expired
            if int(expires_at) > time.time():
                return access_token
        except ValueError:
            pass
            
        return None
    
    def get_refresh_token(self, server_url: str) -> Optional[str]:
        """Get refresh token for a specific server.
        
        Args:
            server_url: MCP server URL
            
        Returns:
            Refresh token or None
        """
        server_key = server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").replace("-", "_").upper()
        return self.get(f"OAUTH_REFRESH_TOKEN_{server_key}")
    
    def remove_oauth_credentials(self, server_url: str) -> bool:
        """Remove OAuth credentials for a specific server.
        
        Args:
            server_url: MCP server URL
        
        Returns:
            True if successful
        """
        server_key = server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").replace("-", "_").upper()
        
        keys_to_remove = [
            f"OAUTH_CLIENT_ID_{server_key}",
            f"OAUTH_CLIENT_SECRET_{server_key}",
            f"OAUTH_REGISTRATION_TOKEN_{server_key}",
            f"OAUTH_REDIRECT_URI_{server_key}",
            f"OAUTH_ACCESS_TOKEN_{server_key}",
            f"OAUTH_TOKEN_EXPIRES_AT_{server_key}",
            f"OAUTH_REFRESH_TOKEN_{server_key}",
        ]
        
        success = True
        for key in keys_to_remove:
            if self.get(key):
                # set_key with empty value removes the key
                try:
                    set_key(str(self.env_file), key, "")
                    if key in os.environ:
                        del os.environ[key]
                except Exception:
                    success = False
        
        return success
    
    def list_credentials(self) -> Dict[str, Dict[str, str]]:
        """List all stored OAuth credentials.
        
        Returns:
            Dictionary mapping server keys to credentials
        """
        values = dotenv_values(self.env_file)
        credentials = {}
        
        # Find all unique server keys
        server_keys = set()
        for key in values:
            if key.startswith("OAUTH_CLIENT_ID_") and not key.endswith("_"):
                server_key = key.replace("OAUTH_CLIENT_ID_", "")
                server_keys.add(server_key)
        
        # Collect credentials for each server
        for server_key in server_keys:
            # Check if access token exists and is valid
            access_token = values.get(f"OAUTH_ACCESS_TOKEN_{server_key}")
            expires_at = values.get(f"OAUTH_TOKEN_EXPIRES_AT_{server_key}")
            has_valid_token = False
            
            if access_token and expires_at:
                try:
                    has_valid_token = int(expires_at) > time.time()
                except ValueError:
                    pass
            
            credentials[server_key] = {
                "client_id": values.get(f"OAUTH_CLIENT_ID_{server_key}", ""),
                "client_secret": values.get(f"OAUTH_CLIENT_SECRET_{server_key}", ""),
                "registration_token": values.get(f"OAUTH_REGISTRATION_TOKEN_{server_key}", ""),
                "has_access_token": bool(access_token),
                "token_valid": has_valid_token,
                "has_refresh_token": bool(values.get(f"OAUTH_REFRESH_TOKEN_{server_key}")),
            }
        
        # Add generic credentials if present
        if values.get("OAUTH_CLIENT_ID"):
            credentials["DEFAULT"] = {
                "client_id": values.get("OAUTH_CLIENT_ID", ""),
                "client_secret": values.get("OAUTH_CLIENT_SECRET", ""),
            }
        
        return credentials