"""Merged validate command implementation."""

import asyncio
import json
import textwrap
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from .compliance import ComplianceChecker
from .models import TestResult, TestStatus
from .oauth import OAuthTestClient
from .validator import MCPValidator
from .env_manager import EnvManager
from .rfc7591 import RFC7591Validator

console = Console()


def create_merged_validate_command():
    """Create the merged validate command with all features."""
    
    @click.command()
    @click.argument("server_url")
    @click.option(
        "--token",
        "-t",
        help="OAuth access token for authenticated tests",
        envvar="MCP_ACCESS_TOKEN",
    )
    @click.option(
        "--output",
        "-o",
        type=click.Choice(["terminal", "json", "markdown"]),
        default="terminal",
        help="Output format",
    )
    @click.option(
        "--output-file",
        "-f",
        type=click.Path(),
        help="Save output to file",
    )
    @click.option(
        "--no-ssl-verify",
        is_flag=True,
        help="Disable SSL certificate verification",
    )
    @click.option(
        "--timeout",
        default=30.0,
        help="Request timeout in seconds",
    )
    @click.option(
        "--verbose",
        "-v",
        is_flag=True,
        help="Show detailed test information",
    )
    @click.option(
        "--auto-auth",
        is_flag=True,
        help="Automatically handle OAuth registration and authentication if needed",
    )
    @click.option(
        "--test-tools",
        is_flag=True,
        help="Also test MCP tools after validation",
    )
    @click.option(
        "--test-destructive",
        is_flag=True,
        help="Include destructive tool tests (use with caution)",
    )
    def validate(
        server_url: str,
        token: Optional[str],
        output: str,
        output_file: Optional[str],
        no_ssl_verify: bool,
        timeout: float,
        verbose: bool,
        auto_auth: bool,
        test_tools: bool,
        test_destructive: bool,
    ):
        """Validate an MCP server for specification compliance.
        
        Comprehensive testing of MCP servers including:
        - OAuth authorization server discovery and validation
        - Protected resource metadata compliance
        - Authentication and authorization flows
        - Core MCP protocol compliance
        - Tool discovery and testing (with --test-tools)
        
        Authentication options:
        - Use --token to provide an existing access token
        - Use --auto-auth to automatically handle OAuth setup
        - Or manually run 'client register' and 'flow' commands first
        
        Examples:
            mcp-validate https://mcp.example.com
            mcp-validate https://mcp.example.com --auto-auth
            mcp-validate https://mcp.example.com --token YOUR_TOKEN
            mcp-validate https://mcp.example.com --auto-auth --test-tools
        """
        async def run_comprehensive_validation():
            env_manager = EnvManager()
            
            # Track overall results
            all_passed = True
            validation_results = []
            
            console.print("[bold]MCP Server Validation[/bold]")
            console.print(f"Server: [cyan]{server_url}[/cyan]")
            console.print()
            
            # Step 1: Check if server requires authentication
            auth_required = False
            oauth_server_url = None
            
            async with MCPValidator(server_url, verify_ssl=not no_ssl_verify) as validator:
                auth_required = await validator._check_auth_required()
                
            if not auth_required:
                console.print("[green]ℹ️  This is a public MCP server (no authentication required)[/green]")
                console.print()
            
            # Step 2: Handle OAuth if authentication is required or auto-auth is enabled
            if auth_required or auto_auth:
                # Discover OAuth server
                console.print("[bold blue]═══ OAuth Server Discovery ═══[/bold blue]")
                
                async with MCPValidator(server_url, verify_ssl=not no_ssl_verify) as validator:
                    oauth_server_url = await validator.discover_oauth_server()
                    
                    if oauth_server_url:
                        console.print(f"[green]✓[/green] OAuth server discovered: {oauth_server_url}")
                    else:
                        console.print("[yellow]No OAuth server discovered[/yellow]")
                        if auth_required:
                            console.print("[yellow]This server requires authentication but no OAuth server was found[/yellow]")
                            all_passed = False
                
                # Test OAuth server compliance if found
                if oauth_server_url:
                    console.print()
                    console.print("[bold]Testing OAuth server compliance...[/bold]")
                    
                    async with OAuthTestClient(oauth_server_url, verify_ssl=not no_ssl_verify) as client:
                        try:
                            metadata = await client.discover_metadata()
                            console.print(f"[green]✓[/green] OAuth metadata endpoint accessible")
                            
                            # Show key endpoints
                            console.print(f"  Authorization: {metadata.authorization_endpoint}")
                            console.print(f"  Token: {metadata.token_endpoint}")
                            if metadata.registration_endpoint:
                                console.print(f"  Registration: {metadata.registration_endpoint}")
                            
                            # Check for MCP support
                            if metadata.scopes_supported and any('mcp' in scope for scope in metadata.scopes_supported):
                                console.print(f"  [green]✓[/green] MCP scopes supported: {', '.join([s for s in metadata.scopes_supported if 'mcp' in s])}")
                            else:
                                console.print(f"  [yellow]⚠[/yellow] No MCP scopes found in supported scopes")
                                
                        except Exception as e:
                            console.print(f"[red]✗[/red] OAuth server error: {e}")
                            all_passed = False
                    
                    # Handle client registration if auto-auth is enabled
                    if auto_auth:
                        credentials = env_manager.get_oauth_credentials(server_url)
                        
                        if not credentials["client_id"]:
                            console.print()
                            console.print("[bold blue]═══ OAuth Client Registration ═══[/bold blue]")
                            console.print("[dim]Attempting automatic client registration...[/dim]")
                            
                            async with OAuthTestClient(oauth_server_url, verify_ssl=not no_ssl_verify) as client:
                                try:
                                    # Get metadata for registration endpoint
                                    metadata = await client.discover_metadata()
                                    if metadata.registration_endpoint:
                                        # Use RFC7591Validator for registration
                                        validator_7591 = RFC7591Validator(client.client, str(metadata.registration_endpoint))
                                        result = await validator_7591.validate_registration()
                                        
                                        if result.valid and result.client_id and result.client_secret:
                                            # Save credentials
                                            env_manager.save_oauth_credentials(
                                                server_url,
                                                result.client_id,
                                                result.client_secret,
                                                result.registration_access_token,
                                            )
                                            console.print(f"[green]✓[/green] Client registered successfully: {result.client_id}")
                                        else:
                                            console.print(f"[red]✗[/red] Registration failed: {result.errors}")
                                            console.print("[yellow]Run manually: mcp-validate client register {server_url}[/yellow]")
                                    else:
                                        console.print("[yellow]OAuth server does not support dynamic registration[/yellow]")
                                        console.print("Manual client registration may be required")
                                except Exception as e:
                                    console.print(f"[red]✗[/red] Registration error: {e}")
                        else:
                            console.print(f"[green]✓[/green] OAuth client already registered: {credentials['client_id']}")
                        
                        # Handle token acquisition if needed
                        if not token and not env_manager.get_valid_access_token(server_url):
                            console.print()
                            console.print("[bold blue]═══ OAuth Authentication ═══[/bold blue]")
                            console.print("[yellow]Automatic OAuth flow not implemented yet[/yellow]")
                            console.print(f"Run manually: [cyan]mcp-validate flow {server_url}[/cyan]")
                            console.print("Then re-run validation with the stored token")
                
                console.print()
            
            # Step 3: Create display callback based on verbosity
            async def display_test_result(result: TestResult):
                """Display test result with appropriate detail level."""
                validation_results.append(result)
                
                status_icons = {
                    TestStatus.PASSED: "✓",
                    TestStatus.FAILED: "✗", 
                    TestStatus.SKIPPED: "⊘",
                    TestStatus.ERROR: "⚠",
                }
                
                status_colors = {
                    TestStatus.PASSED: "green",
                    TestStatus.FAILED: "red",
                    TestStatus.SKIPPED: "yellow",
                    TestStatus.ERROR: "red",
                }
                
                icon = status_icons.get(result.status, "?")
                color = status_colors.get(result.status, "white")
                
                if verbose:
                    # Detailed output (like full command)
                    console.print(f"[bold {color}]{icon} {result.test_case.name}[/bold {color}] [{result.test_case.category}]")
                    
                    # Show test description
                    if result.details and result.details.get("test_description"):
                        desc = result.details["test_description"]
                        console.print(f"   [dim]Testing: {desc}[/dim]")
                    
                    # Show test URL if available
                    if result.details and result.details.get("url_tested"):
                        console.print(f"   [dim]URL: {result.details['url_tested']}[/dim]")
                    
                    # Show test message
                    if result.message:
                        wrapped = textwrap.fill(result.message, width=80, initial_indent="   ", subsequent_indent="   ")
                        if result.status == TestStatus.PASSED:
                            console.print(f"\n[green]{wrapped}[/green]")
                        else:
                            console.print(f"\n[yellow]{wrapped}[/yellow]")
                    
                    # Show fix recommendation for failures
                    if result.details and result.status != TestStatus.PASSED:
                        if result.details.get("fix"):
                            console.print(f"\n   [cyan]Fix: {result.details['fix']}[/cyan]")
                        if result.details.get("spec_reference"):
                            console.print(f"   [yellow]→ {result.details['spec_reference']}[/yellow]")
                    
                    console.print()  # Spacing between tests
                else:
                    # Simple output (original validate style)
                    console.print(f"[{color}]{icon}[/{color}] {result.test_case.name}")
            
            # Step 4: Run main MCP validation
            console.print("[bold blue]═══ MCP Protocol Validation ═══[/bold blue]")
            console.print()
            console.print("[bold]Test Results:[/bold]")
            console.print()
            
            validation_result = None
            server_info = None
            
            async with MCPValidator(
                server_url,
                access_token=token,
                timeout=timeout,
                verify_ssl=not no_ssl_verify,
                auto_register=False,
                progress_callback=display_test_result,
            ) as validator:
                # Use token from env if not provided
                if not token:
                    validator.access_token = validator.env_manager.get_valid_access_token(server_url)
                    if validator.access_token:
                        console.print("[dim]Using stored access token from .env[/dim]")
                        console.print()
                    elif auth_required:
                        console.print("[yellow]Some tests may be skipped without authentication[/yellow]")
                        if not auto_auth:
                            console.print("Use --auto-auth to handle OAuth automatically")
                        console.print()
                
                validation_result = await validator.validate()
                server_info = validator.server_info
            
            # Step 5: Run tool tests if requested
            if test_tools:
                console.print()
                console.print("[bold blue]═══ MCP Tools Testing ═══[/bold blue]")
                
                # Import tool testing functionality
                from .transport_detector import TransportDetector, TransportType
                from .sse_client import MCPSSEClient
                from .tool_tests import MCPToolTests
                
                async with MCPValidator(server_url, verify_ssl=not no_ssl_verify) as validator:
                    # Set token if available
                    validator.access_token = token or validator.env_manager.get_valid_access_token(server_url)
                    
                    # Detect transport type
                    detector = TransportDetector(validator.client)
                    headers = validator._get_headers({})
                    
                    console.print("[dim]Detecting transport type...[/dim]")
                    transport_type = await detector.detect_transport(server_url, headers)
                    
                    if transport_type == TransportType.SSE:
                        console.print("[green]✓[/green] SSE transport detected")
                        
                        # Create SSE client and run tool tests
                        sse_url = f"{server_url}/sse" if not server_url.endswith("/sse") else server_url
                        async with MCPSSEClient(sse_url, headers=headers) as sse_client:
                            # List tools
                            tools = await sse_client.list_tools()
                            
                            if tools:
                                console.print(f"\nFound {len(tools)} tools:")
                                for tool in tools[:5]:  # Show first 5
                                    console.print(f"  • {tool.get('name', 'unnamed')} - {tool.get('description', 'No description')[:60]}...")
                                if len(tools) > 5:
                                    console.print(f"  ... and {len(tools) - 5} more")
                                
                                if not test_destructive:
                                    console.print("\n[yellow]Note: Skipping destructive tool tests. Use --test-destructive to include them[/yellow]")
                            else:
                                console.print("[yellow]No tools found on this server[/yellow]")
                    else:
                        console.print("[yellow]Tool testing requires SSE transport, but server uses HTTP transport[/yellow]")
            
            # Step 6: Generate compliance report
            if validation_result:
                checker = ComplianceChecker(validation_result, server_info)
                report = checker.check_compliance()
                
                # Update overall status
                if validation_result.failed_tests > 0:
                    all_passed = False
                
                # Output results
                console.print()
                if output == "terminal":
                    # Show summary
                    from .cli import display_terminal_summary
                    display_terminal_summary(report)
                elif output == "json":
                    output_data = json.dumps(report.model_dump(), indent=2, default=str)
                    if output_file:
                        Path(output_file).write_text(output_data)
                        console.print(f"[green]Report saved to {output_file}[/green]")
                    else:
                        console.print(output_data)
                elif output == "markdown":
                    markdown = report.to_markdown()
                    if output_file:
                        Path(output_file).write_text(markdown)
                        console.print(f"[green]Report saved to {output_file}[/green]")
                    else:
                        console.print(markdown)
                
                return report
            
            return None
        
        # Run the validation
        try:
            report = asyncio.run(run_comprehensive_validation())
            # Exit with non-zero code if tests failed
            if report and report.validation_result.failed_tests > 0:
                exit(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Validation interrupted by user[/yellow]")
            exit(1)
        except Exception as e:
            console.print(f"\n[red]Error during validation: {e}[/red]")
            if verbose:
                import traceback
                console.print(traceback.format_exc())
            exit(1)
    
    return validate