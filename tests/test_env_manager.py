"""Tests for environment file management."""

import os
import tempfile
from pathlib import Path

import pytest

from mcp_http_validator.env_manager import EnvManager


def test_env_manager_creation():
    """Test EnvManager initialization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        # Should create empty file
        assert env_file.exists()


def test_env_manager_get_set():
    """Test getting and setting values."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        # Set value
        assert manager.set("TEST_KEY", "test_value")
        
        # Get value
        assert manager.get("TEST_KEY") == "test_value"
        
        # Get with default
        assert manager.get("MISSING_KEY", "default") == "default"


def test_env_manager_update():
    """Test updating multiple values."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        # Update multiple
        values = {
            "KEY1": "value1",
            "KEY2": "value2",
            "KEY3": "value3",
        }
        assert manager.update(values)
        
        # Verify all set
        for key, value in values.items():
            assert manager.get(key) == value


def test_oauth_credentials_management():
    """Test OAuth credential storage and retrieval."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        server_url = "https://mcp.example.com"
        
        # Save credentials
        assert manager.save_oauth_credentials(
            server_url,
            client_id="test_client_123",
            client_secret="test_secret_456",
            registration_token="test_reg_789",
        )
        
        # Get credentials
        creds = manager.get_oauth_credentials(server_url)
        assert creds["client_id"] == "test_client_123"
        assert creds["client_secret"] == "test_secret_456"
        assert creds["registration_token"] == "test_reg_789"
        
        # Also should set default
        assert manager.get("OAUTH_CLIENT_ID") == "test_client_123"


def test_oauth_credentials_server_specific():
    """Test server-specific credential storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        # Save for two different servers
        manager.save_oauth_credentials(
            "https://mcp1.example.com",
            client_id="client1",
            client_secret="secret1",
        )
        
        manager.save_oauth_credentials(
            "https://mcp2.example.com",
            client_id="client2",
            client_secret="secret2",
        )
        
        # Get credentials for each
        creds1 = manager.get_oauth_credentials("https://mcp1.example.com")
        creds2 = manager.get_oauth_credentials("https://mcp2.example.com")
        
        assert creds1["client_id"] == "client1"
        assert creds2["client_id"] == "client2"


def test_oauth_credentials_removal():
    """Test removing OAuth credentials."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        server_url = "https://mcp.example.com"
        
        # Save credentials
        manager.save_oauth_credentials(
            server_url,
            client_id="test_client",
            client_secret="test_secret",
        )
        
        # Remove credentials
        assert manager.remove_oauth_credentials(server_url)
        
        # Should be gone
        creds = manager.get_oauth_credentials(server_url)
        assert creds["client_id"] is None
        assert creds["client_secret"] is None


def test_list_credentials():
    """Test listing all stored credentials."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        # Save multiple credentials
        manager.save_oauth_credentials(
            "https://mcp1.example.com",
            client_id="client1",
        )
        
        manager.save_oauth_credentials(
            "https://mcp2.example.com",
            client_id="client2",
            client_secret="secret2",
        )
        
        # List all
        all_creds = manager.list_credentials()
        
        assert "MCP1_EXAMPLE_COM" in all_creds
        assert "MCP2_EXAMPLE_COM" in all_creds
        assert "DEFAULT" in all_creds  # Default should be set too
        
        assert all_creds["MCP1_EXAMPLE_COM"]["client_id"] == "client1"
        assert all_creds["MCP2_EXAMPLE_COM"]["client_id"] == "client2"


def test_env_file_from_example():
    """Test creating .env from .env.example."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create example file
        example_file = Path(tmpdir) / ".env.example"
        example_file.write_text("EXAMPLE_KEY=example_value\n")
        
        # Create manager
        env_file = Path(tmpdir) / ".env"
        manager = EnvManager(env_file)
        
        # Should copy from example
        assert env_file.exists()
        assert manager.get("EXAMPLE_KEY") == "example_value"