# MCP HTTP Validator

HTTP-based validator for Model Context Protocol (MCP) servers with OAuth 2.0 authorization testing.

## Quick Example

```bash
# Install
pip install mcp-http-validator

# Run full validation suite (handles OAuth automatically)
mcp-validate full https://mcp.example.com

# Or validate with existing token
mcp-validate validate https://mcp.example.com --token $ACCESS_TOKEN
```

## Overview

MCP HTTP Validator is a comprehensive testing tool for validating MCP server implementations against the [MCP specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization). It focuses on:

- OAuth 2.0 authorization compliance (RFC 6749, RFC 8707, RFC 9728)
- MCP-specific endpoint validation
- Token audience validation
- Server-Sent Events (SSE) support
- Protected resource metadata compliance

## Features

### Core Features
- **Automatic OAuth Discovery**: Discovers OAuth servers from MCP metadata
- **Zero Configuration**: Automatically registers and saves OAuth clients
- **Full MCP Compliance Testing**: Validates servers against MCP 2025-06-18 specification
- **OAuth Flow Testing**: Complete OAuth 2.0 authorization flow validation
- **Dynamic Client Registration**: Supports RFC 7591 for automatic client setup
- **Client Management**: RFC 7592 support for updating/deleting clients
- **Resource Indicators**: Validates RFC 8707 resource-restricted tokens
- **Multiple Output Formats**: Terminal, JSON, and Markdown reports
- **Credential Management**: Secure .env file storage for OAuth credentials
- **No stdio Dependencies**: Pure HTTP-based testing

### Advanced Features
- **Smart Token Management**: Automatically checks token validity before OAuth flows
- **Token Refresh**: Attempts refresh token flow before initiating new authentication
- **SSE Support**: Full Server-Sent Events testing for MCP SSE transport
- **Tool Discovery**: Automatic discovery and testing of MCP server tools
- **Transport Detection**: Automatically detects SSE vs HTTP transport
- **Batch Testing**: `full` command runs complete test suite automatically
- **Progress Reporting**: Real-time progress updates during long operations
- **Redirect Strategies**: Supports both public IP and out-of-band OAuth flows
- **JWT Validation**: Decodes and validates JWT tokens for expiry and audience
- **Per-Server Isolation**: Each MCP server gets its own credentials namespace

## Installation

```bash
pip install mcp-http-validator
```

Or install from source:

```bash
git clone https://github.com/example/mcp-http-validator
cd mcp-http-validator
pip install -e .
```

## Quick Start

### Command Line Usage

#### 1. Basic Validation

```bash
# Validate an MCP server (automatic OAuth discovery and setup)
mcp-validate validate https://mcp.example.com

# Use existing access token
mcp-validate validate https://mcp.example.com --token $ACCESS_TOKEN

# With additional options
mcp-validate validate https://mcp.example.com \
  --output json \
  --output-file report.json \
  --verbose \
  --timeout 60
```

**Options:**
- `--token, -t`: OAuth access token for authenticated tests
- `--output, -o`: Output format (terminal/json/markdown)
- `--output-file, -f`: Save output to file
- `--no-ssl-verify`: Disable SSL certificate verification
- `--timeout`: Request timeout in seconds (default: 30)
- `--verbose, -v`: Show detailed test information

#### 2. Complete Test Suite

```bash
# Run ALL validation tests in the correct order
mcp-validate full https://mcp.example.com

# Include destructive tool tests (use with caution!)
mcp-validate full https://mcp.example.com --test-destructive --verbose
```

This command automatically:
1. Discovers OAuth server from MCP metadata
2. Registers OAuth client if needed
3. Completes OAuth flow for access token
4. Runs main MCP validation
5. Tests all MCP tools

#### 3. OAuth Authentication Flow

```bash
# Complete OAuth flow (checks for existing valid token first)
mcp-validate flow https://mcp.example.com

# Force new flow even if valid token exists
mcp-validate flow https://mcp.example.com --force

# Request specific scopes
mcp-validate flow https://mcp.example.com --scope "mcp:read"
```

The flow command automatically:
- Checks for existing valid access token
- Attempts token refresh if expired
- Only initiates new OAuth flow if necessary
- Supports both public IP and out-of-band redirect strategies

#### 4. OAuth Client Management (RFC 7591/7592)

```bash
# Register a new OAuth client
mcp-validate client register https://mcp.example.com

# Force new registration (replaces existing)
mcp-validate client register https://mcp.example.com --force

# Also validate RFC 7592 support
mcp-validate client register https://mcp.example.com --validate-rfc7592

# List all saved OAuth clients
mcp-validate client list

# Update client configuration (RFC 7592)
mcp-validate client update https://mcp.example.com \
  --client-name "My MCP Client" \
  --redirect-uri "http://localhost:8080/callback" \
  --scope "mcp:read mcp:write"

# Delete client registration
mcp-validate client delete https://mcp.example.com
```

#### 5. Token Management

```bash
# List all stored tokens and their status
mcp-validate tokens list

# Show detailed token status for a specific server
mcp-validate tokens show https://mcp.example.com

# Refresh access token using refresh token
mcp-validate tokens refresh https://mcp.example.com

# Clear tokens for a server (keeps client credentials)
mcp-validate tokens clear https://mcp.example.com
```

#### 6. MCP Tools Testing

```bash
# Discover and test all tools
mcp-validate tools https://mcp.example.com

# List tools without testing
mcp-validate tools https://mcp.example.com --list-only

# Test specific tool
mcp-validate tools https://mcp.example.com --tool-name "search"

# Include destructive tool tests
mcp-validate tools https://mcp.example.com --test-destructive
```

#### 7. Direct OAuth Server Testing

```bash
# Test an OAuth authorization server directly
mcp-validate oauth https://auth.example.com

# Register new client with OAuth server
mcp-validate oauth https://auth.example.com --register
```

### Programmatic Usage

```python
import asyncio
from mcp_http_validator import MCPValidator, ComplianceChecker

async def validate_server():
    async with MCPValidator(
        server_url="https://mcp.example.com",
        auto_register=True  # Automatically discover OAuth and register client
    ) as validator:
        # OAuth client is automatically set up if needed
        await validator.setup_oauth_client()
        
        result = await validator.validate()
        
    checker = ComplianceChecker(result, validator.server_info)
    report = checker.check_compliance()
    
    print(f"Compliance Level: {report.compliance_level}")
    print(f"Success Rate: {result.success_rate:.1f}%")

asyncio.run(validate_server())
```

## Configuration

The validator automatically manages OAuth credentials and tokens in a `.env` file:

### Manual Configuration
```env
# Manual access token for pre-authenticated testing
MCP_ACCESS_TOKEN=your-access-token

# Default OAuth credentials (fallback if server-specific not found)
OAUTH_CLIENT_ID=default-client-id
OAUTH_CLIENT_SECRET=default-client-secret
```

### Automatic Per-Server Storage
The validator automatically saves credentials with server-specific keys:

```env
# OAuth client credentials (RFC 7591)
OAUTH_CLIENT_ID_MCP_EXAMPLE_COM=mcp_client_123456
OAUTH_CLIENT_SECRET_MCP_EXAMPLE_COM=secret_abcdef...
OAUTH_REGISTRATION_TOKEN_MCP_EXAMPLE_COM=reg_token_xyz...
OAUTH_REDIRECT_URI_MCP_EXAMPLE_COM=http://localhost:61234/callback

# OAuth tokens
OAUTH_ACCESS_TOKEN_MCP_EXAMPLE_COM=eyJhbGc...
OAUTH_TOKEN_EXPIRES_AT_MCP_EXAMPLE_COM=1234567890
OAUTH_REFRESH_TOKEN_MCP_EXAMPLE_COM=refresh_token_abc...
```

Server URLs are converted to environment variable keys by:
1. Removing protocol (`https://`)
2. Replacing dots and special characters with underscores
3. Converting to uppercase

Example: `https://mcp.example.com` → `MCP_EXAMPLE_COM`

### Automatic Features
The validator provides intelligent credential management:

1. **Auto-Discovery**: OAuth servers discovered from MCP metadata
2. **Auto-Registration**: Clients registered via RFC 7591 when needed
3. **Token Management**: Automatic token validation and refresh
4. **Secure Storage**: All credentials saved to `.env` file
5. **Server Isolation**: Each server has its own credentials

## Validation Tests

The validator performs the following tests:

### Critical Tests (Required)
- **Protected Resource Metadata**: `/.well-known/oauth-protected-resource` endpoint
- **Authentication Challenge**: Proper 401 responses with WWW-Authenticate header
- **Authenticated Access**: Valid bearer token acceptance

### Important Tests
- **Token Audience Validation**: Validates token `aud` claim contains server URL
- **Resource-Token Consistency**: Verifies protected resource metadata matches token audience
- **SSE Support**: Server-Sent Events for MCP protocol

### OAuth Server Tests
- Authorization server metadata discovery
- Resource indicators support (RFC 8707)
- Required endpoints availability
- MCP scope support (`mcp:read`, `mcp:write`)

## Output Formats

### Terminal Output
Rich, colored output with tables and progress indicators:
```
┌─────────────────────────────────────┐
│ MCP Compliance Report               │
│ Server: https://mcp.example.com     │
│ Compliance Level: FULLY_COMPLIANT   │
└─────────────────────────────────────┘
```

### JSON Output
Complete structured data for programmatic processing:
```bash
mcp-validate validate https://mcp.example.com -o json -f report.json
```

### Markdown Output
Human-readable reports for documentation:
```bash
mcp-validate validate https://mcp.example.com -o markdown -f report.md
```

### Full Test Suite Output
The `full` command provides comprehensive results:
```bash
mcp-validate full https://mcp.example.com --verbose
```

Shows progress through each phase:
- OAuth server discovery and validation
- Client registration status
- Token acquisition progress
- MCP validation results
- Tool discovery and testing

## Compliance Levels

- **FULLY_COMPLIANT**: All tests pass (100%)
- **MOSTLY_COMPLIANT**: 90%+ tests pass
- **PARTIALLY_COMPLIANT**: 70%+ tests pass or critical test failed
- **MINIMALLY_COMPLIANT**: Some tests pass but major issues
- **NON_COMPLIANT**: Critical required tests failed

## Advanced Usage

### Custom Validation Tests

```python
from mcp_http_validator import MCPValidator, TestCase, TestSeverity

class CustomValidator(MCPValidator):
    async def test_custom_endpoint(self):
        """Test a custom MCP endpoint."""
        response = await self.client.get(
            f"{self.server_url}/custom",
            headers=self._get_headers()
        )
        
        passed = response.status_code == 200
        error = None if passed else f"Got {response.status_code}"
        
        return passed, error, {"status": response.status_code}
    
    async def validate(self):
        # Add custom test
        custom_test = TestCase(
            id="custom-endpoint",
            name="Custom Endpoint Test",
            description="Validates custom MCP endpoint",
            severity=TestSeverity.MEDIUM,
            category="custom"
        )
        
        result = await self._execute_test(
            custom_test,
            self.test_custom_endpoint
        )
        self.test_results.append(result)
        
        # Run standard tests
        return await super().validate()
```

### OAuth Flow Automation

```python
from mcp_http_validator import MCPValidator, EnvManager

async def automated_oauth_test(mcp_server: str):
    # Automatic OAuth discovery and registration
    async with MCPValidator(mcp_server) as validator:
        # Discovers OAuth server and registers client automatically
        oauth_client = await validator.setup_oauth_client()
        
        if oauth_client:
            # Generate auth URL with discovered OAuth server
            auth_url, state, verifier = oauth_client.generate_authorization_url(
                resources=[mcp_server]
            )
            
            print(f"Visit: {auth_url}")
            code = input("Enter code: ")
            
            # Exchange for token
            token = await oauth_client.exchange_code_for_token(
                code, verifier, [mcp_server]
            )
            
            # Test access
            success, error, _ = await oauth_client.test_mcp_server_with_token(
                mcp_server, token.access_token
            )
            print(f"Access: {'✓' if success else '✗'} {error or 'OK'}")

# RFC 7592 Client Management
async def manage_oauth_client(mcp_server: str):
    env_manager = EnvManager()
    credentials = env_manager.get_oauth_credentials(mcp_server)
    
    async with MCPValidator(mcp_server) as validator:
        auth_server = await validator.discover_oauth_server()
        
        async with OAuthTestClient(
            auth_server,
            registration_access_token=credentials["registration_token"]
        ) as client:
            # Get current config
            config = await client.get_client_configuration()
            
            # Update client
            await client.update_client_configuration({
                "client_name": "Updated Name"
            })
            
            # Or delete client
            # await client.delete_client_registration()
```

## Troubleshooting

### Common Issues

1. **"No OAuth server discovered"**
   - Ensure the MCP server implements `/.well-known/oauth-protected-resource`
   - Check that the metadata includes `authorization_servers` array
   - Use `--no-ssl-verify` for development servers with self-signed certificates

2. **"Token expired" during validation**
   - Run `mcp-validate tokens refresh https://mcp.example.com` to refresh
   - Or use `mcp-validate flow https://mcp.example.com` for new token

3. **"Client registration failed"**
   - Check if the OAuth server supports RFC 7591 dynamic registration
   - Try manual registration on the OAuth server's web interface
   - Use environment variables for manual client credentials

4. **"SSL verification failed"**
   - For development: use `--no-ssl-verify` flag
   - For production: ensure valid SSL certificates

5. **"Permission denied on .env"**
   - Check file permissions: `chmod 600 .env`
   - Ensure the directory is writable

### Debug Mode

For detailed debugging information:
```bash
# Verbose output for any command
mcp-validate validate https://mcp.example.com --verbose

# Check stored credentials
mcp-validate client list
mcp-validate tokens list

# Test OAuth server directly
mcp-validate oauth https://auth.example.com
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## See Also

- [MCP Specification](https://modelcontextprotocol.io/specification)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [Dynamic Client Registration RFC 7591](https://tools.ietf.org/html/rfc7591)
- [Dynamic Client Registration Management RFC 7592](https://tools.ietf.org/html/rfc7592)
- [Resource Indicators RFC 8707](https://tools.ietf.org/html/rfc8707)
- [Protected Resource Metadata RFC 9728](https://tools.ietf.org/html/rfc9728)