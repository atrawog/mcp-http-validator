"""Tests for the flow command token management."""

import time
from unittest.mock import MagicMock, patch
import pytest
from click.testing import CliRunner
from mcp_http_validator.cli import cli
from mcp_http_validator.env_manager import EnvManager


class TestFlowCommand:
    """Test the flow command's token management features."""
    
    def test_flow_with_valid_token(self, tmp_path):
        """Test flow command skips OAuth when valid token exists."""
        # Create temporary .env with valid token
        env_file = tmp_path / ".env"
        env_file.write_text(
            f"OAUTH_CLIENT_ID_TEST_EXAMPLE_COM_MCP='test_client'\n"
            f"OAUTH_CLIENT_SECRET_TEST_EXAMPLE_COM_MCP='test_secret'\n"
            f"OAUTH_ACCESS_TOKEN_TEST_EXAMPLE_COM_MCP='valid_token_123'\n"
            f"OAUTH_TOKEN_EXPIRES_AT_TEST_EXAMPLE_COM_MCP='{int(time.time()) + 3600}'\n"
        )
        
        runner = CliRunner()
        
        # Mock the various async operations
        with patch('mcp_http_validator.cli.MCPValidator') as mock_validator:
            with patch('mcp_http_validator.cli.OAuthTestClient') as mock_oauth:
                with patch('mcp_http_validator.cli.EnvManager') as mock_env:
                    # Setup mocks
                    mock_env_instance = MagicMock()
                    mock_env.return_value = mock_env_instance
                    
                    # Mock get_valid_access_token to return our token
                    mock_env_instance.get_valid_access_token.return_value = 'valid_token_123'
                    mock_env_instance.get_oauth_credentials.return_value = {
                        'client_id': 'test_client',
                        'client_secret': 'test_secret'
                    }
                    mock_env_instance.get.side_effect = lambda key: {
                        'OAUTH_TOKEN_EXPIRES_AT_TEST_EXAMPLE_COM_MCP': str(int(time.time()) + 3600)
                    }.get(key)
                    
                    # Mock OAuth server discovery
                    mock_validator_instance = MagicMock()
                    mock_validator.return_value.__aenter__.return_value = mock_validator_instance
                    mock_validator_instance.discover_oauth_server.return_value = 'https://auth.example.com'
                    
                    # Mock token test success
                    mock_oauth_instance = MagicMock()
                    mock_oauth.return_value.__aenter__.return_value = mock_oauth_instance
                    mock_oauth_instance.test_mcp_server_with_token.return_value = (True, None, {})
                    
                    # Run command
                    result = runner.invoke(cli, ['flow', 'https://test.example.com/mcp'])
                    
                    # Check output
                    assert result.exit_code == 0
                    assert 'Valid access token found' in result.output
                    assert 'Token is valid and working' in result.output
                    assert 'Use --force to get a new token' in result.output
                    
                    # Verify OAuth flow was NOT initiated
                    mock_oauth_instance.generate_authorization_url.assert_not_called()
    
    def test_flow_with_force_flag(self):
        """Test flow command with --force bypasses token check."""
        runner = CliRunner()
        
        with patch('mcp_http_validator.cli.MCPValidator') as mock_validator:
            with patch('mcp_http_validator.cli.OAuthTestClient') as mock_oauth:
                with patch('mcp_http_validator.cli.EnvManager') as mock_env:
                    # Setup basic mocks
                    mock_env_instance = MagicMock()
                    mock_env.return_value = mock_env_instance
                    mock_env_instance.get_oauth_credentials.return_value = {
                        'client_id': 'test_client',
                        'client_secret': 'test_secret'
                    }
                    
                    # Mock OAuth server discovery
                    mock_validator_instance = MagicMock()
                    mock_validator.return_value.__aenter__.return_value = mock_validator_instance
                    mock_validator_instance.discover_oauth_server.return_value = 'https://auth.example.com'
                    
                    # Mock OAuth client
                    mock_oauth_instance = MagicMock()
                    mock_oauth.return_value.__aenter__.return_value = mock_oauth_instance
                    mock_oauth_instance.generate_authorization_url.return_value = (
                        'https://auth.example.com/authorize?...',
                        'state123',
                        'verifier123'
                    )
                    
                    # Run command with --force
                    result = runner.invoke(cli, ['flow', 'https://test.example.com/mcp', '--force'])
                    
                    # Check that it proceeds to OAuth flow
                    assert 'Starting OAuth authorization flow' in result.output
                    assert 'Checking for existing tokens' not in result.output
                    
                    # Verify OAuth flow was initiated
                    mock_oauth_instance.generate_authorization_url.assert_called_once()
    
    def test_flow_with_expired_token_and_refresh(self):
        """Test flow command refreshes expired token."""
        runner = CliRunner()
        
        with patch('mcp_http_validator.cli.MCPValidator') as mock_validator:
            with patch('mcp_http_validator.cli.OAuthTestClient') as mock_oauth:
                with patch('mcp_http_validator.cli.EnvManager') as mock_env:
                    # Setup mocks
                    mock_env_instance = MagicMock()
                    mock_env.return_value = mock_env_instance
                    
                    # No valid access token (expired)
                    mock_env_instance.get_valid_access_token.return_value = None
                    mock_env_instance.get_refresh_token.return_value = 'refresh_token_123'
                    mock_env_instance.get_oauth_credentials.return_value = {
                        'client_id': 'test_client',
                        'client_secret': 'test_secret'
                    }
                    
                    # Mock OAuth server discovery
                    mock_validator_instance = MagicMock()
                    mock_validator.return_value.__aenter__.return_value = mock_validator_instance
                    mock_validator_instance.discover_oauth_server.return_value = 'https://auth.example.com'
                    
                    # Mock successful refresh
                    mock_oauth_instance = MagicMock()
                    mock_oauth.return_value.__aenter__.return_value = mock_oauth_instance
                    
                    mock_token_response = MagicMock()
                    mock_token_response.access_token = 'new_token_123'
                    mock_token_response.expires_in = 3600
                    mock_token_response.refresh_token = 'new_refresh_123'
                    
                    mock_oauth_instance.refresh_token.return_value = mock_token_response
                    mock_oauth_instance.test_mcp_server_with_token.return_value = (True, None, {})
                    
                    # Run command
                    result = runner.invoke(cli, ['flow', 'https://test.example.com/mcp'])
                    
                    # Check output
                    assert 'Attempting to refresh token' in result.output
                    assert 'Token refreshed successfully' in result.output
                    assert 'New tokens saved to .env' in result.output
                    
                    # Verify refresh was called
                    mock_oauth_instance.refresh_token.assert_called_once()
                    
                    # Verify new tokens were saved
                    mock_env_instance.save_tokens.assert_called_once()