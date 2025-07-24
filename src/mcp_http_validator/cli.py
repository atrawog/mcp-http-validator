"""Command-line interface for MCP HTTP Validator."""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import click
import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from .compliance import ComplianceChecker
from .models import TestStatus, TestResult
from .oauth import OAuthTestClient
from .validator import MCPValidator
from .env_manager import EnvManager
from .rfc8707 import RFC8707Validator
from .rfc7591 import RFC7591Validator, RFC7592Validator
from .generic_oauth_flow import GenericOAuthFlow
from .oauth_flow_config import OAuthFlowConfig

console = Console()


def load_env_config():
    """Load configuration from .env file."""
    env_file = Path(".env")
    if env_file.exists():
        load_dotenv(env_file)
        console.print(f"[dim]Loaded configuration from {env_file}[/dim]")


@click.group()
@click.version_option(version="0.1.0", prog_name="mcp-validate")
def cli():
    """MCP HTTP Validator - Test MCP servers for specification compliance."""
    load_env_config()


@cli.command()
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
def validate(
    server_url: str,
    token: Optional[str],
    output: str,
    output_file: Optional[str],
    no_ssl_verify: bool,
    timeout: float,
    verbose: bool,
):
    """Validate an MCP server for specification compliance.
    
    Tests MCP server endpoints and OAuth integration. If authentication is
    required, run 'mcp-validate client register' and 'mcp-validate flow' first.
    
    Example:
        mcp-validate validate https://mcp.example.com
        mcp-validate validate https://mcp.example.com --token YOUR_TOKEN
    """
    async def run_validation():
        # Display test results header immediately
        console.print()
        console.print("[bold]Test Results:[/bold]")
        console.print()
        
        # Track results for summary
        test_results = []
        
        async def display_test_result(result: TestResult):
            """Display test result as it completes."""
            test_results.append(result)
            
            # Display the test result immediately
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
            
            # Simple one-line output for each test
            console.print(f"[{color}]{icon}[/{color}] {result.test_case.name}")
        
        async with MCPValidator(
            server_url,
            access_token=token,
            timeout=timeout,
            verify_ssl=not no_ssl_verify,
            auto_register=False,  # Never auto-register in validate command
            progress_callback=display_test_result,  # Stream results
        ) as validator:
            # Check if we have a token
            if not token:
                # Try to get from env
                validator.access_token = validator.env_manager.get_valid_access_token(server_url)
                if validator.access_token:
                    console.print("[dim]Using stored access token from .env[/dim]")
                    console.print()
                else:
                    # Check if we need auth
                    auth_server = await validator.discover_oauth_server()
                    if auth_server:
                        console.print("[yellow]⚠️  This MCP server requires authentication[/yellow]")
                        console.print()
                        console.print("To authenticate:")
                        console.print(f"  1. Register OAuth client: [cyan]mcp-validate client register {server_url}[/cyan]")
                        console.print(f"  2. Get access token: [cyan]mcp-validate flow {server_url}[/cyan]")
                        console.print(f"  3. Run validation: [cyan]mcp-validate validate {server_url}[/cyan]")
                        console.print()
                        console.print("Or run all tests: [cyan]mcp-validate full {server_url}[/cyan]")
                        console.print()
                    console.print("[yellow]Some tests may be skipped without authentication[/yellow]")
                    console.print()
            
            # Run validation tests (results will be displayed via callback)
            validation_result = await validator.validate()
            server_info = validator.server_info
        
        # Generate compliance report
        checker = ComplianceChecker(validation_result, server_info)
        report = checker.check_compliance()
        
        # Output results
        if output == "terminal":
            # Only show summary since we already displayed test results
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
    
    try:
        report = asyncio.run(run_validation())
        # Exit with non-zero code if tests failed
        if report.validation_result.failed_tests > 0:
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def display_terminal_summary(report):
    """Display only the summary of compliance report."""
    result = report.validation_result
    
    console.print()
    console.print("[bold]Test Summary:[/bold]")
    
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column(style="dim")
    summary_table.add_column()
    
    # Determine compliance level color
    level_colors = {
        "FULLY_COMPLIANT": "green",
        "MOSTLY_COMPLIANT": "yellow", 
        "PARTIALLY_COMPLIANT": "yellow",
        "MINIMALLY_COMPLIANT": "red",
        "NON_COMPLIANT": "red",
        "UNKNOWN": "dim"
    }
    level_color = level_colors.get(report.compliance_level, "white")
    
    summary_table.add_row("Server:", f"[cyan]{report.server_info.url}[/cyan]")
    summary_table.add_row("Compliance:", f"[bold {level_color}]{report.compliance_level}[/bold {level_color}]")
    summary_table.add_row("Total Tests:", str(result.total_tests))
    summary_table.add_row("Passed:", f"[green]{result.passed_tests}[/green]")
    summary_table.add_row("Failed:", f"[red]{result.failed_tests}[/red]")
    if result.skipped_tests > 0:
        summary_table.add_row("Skipped:", f"[yellow]{result.skipped_tests}[/yellow]")
    summary_table.add_row("Success Rate:", f"{result.success_rate:.1f}%")
    summary_table.add_row("Duration:", f"{report.validation_result.duration:.2f}s")
    
    # Check for OAuth server discovery
    oauth_test = next((r for r in result.test_results if r.test_case.id == "oauth-server-discovery"), None)
    if oauth_test and oauth_test.details:
        oauth_server = oauth_test.details.get("oauth_server_found")
        if oauth_server:
            summary_table.add_row("OAuth Server:", f"[cyan]{oauth_server}[/cyan]")
    
    console.print(summary_table)


def display_terminal_report(report, verbose=False, show_summary=True):
    """Display compliance report in terminal."""
    result = report.validation_result
    
    # Test results first
    console.print()
    console.print("[bold]Test Results:[/bold]")
    
    # Show message if OAuth tests were skipped for public server
    if report.server_info and not report.server_info.requires_auth:
        console.print()
        console.print("[green]ℹ️  This is a public MCP server (no authentication required)[/green]")
        console.print("[green]   OAuth tests were skipped as they are not applicable[/green]")
    
    console.print()
    
    # Display each test result in a clear, structured way
    for test_result in result.test_results:
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
        
        icon = status_icons.get(test_result.status, "?")
        color = status_colors.get(test_result.status, "white")
        
        # Build test display
        test_info = []
        
        # Test name and status on same line
        test_info.append(f"[bold {color}]{icon} {test_result.test_case.name}[/bold {color}] [{test_result.test_case.category}]")
        
        # What is being tested AND which URL/endpoint (if available)
        if test_result.details:
            details = test_result.details
            
            # Show test description with URL if available
            if "test_description" in details:
                desc = details['test_description']
                if "url_tested" in details:
                    test_info.append(f"   [dim]Testing: {desc}[/dim]")
                    test_info.append(f"   [dim]URL: [cyan]{details['url_tested']}[/cyan][/dim]")
                else:
                    test_info.append(f"   [dim]Testing: {desc}[/dim]")
        
        # Show details for all tests (not just failures) but vary by status
        if test_result.status == TestStatus.PASSED:
            # For passed tests, show the success message if available
            if test_result.message:
                # Success messages are now in message field
                import textwrap
                wrapped = textwrap.fill(test_result.message, width=80, initial_indent="   ", subsequent_indent="   ")
                test_info.append(f"\n[green]{wrapped}[/green]")
            
            # Add any additional details
            if test_result.details:
                details = test_result.details
                
                # Special handling for specific successful tests
                if test_result.test_case.id == "http-transport" and "content_type" in details:
                    test_info.append(f"   [dim]Transport type: {details.get('transport_type', 'json')}[/dim]")
        
        else:  # Failed, Error, or Skipped
            # Primary error message with context
            if test_result.message:
                # Make error messages more specific
                error_msg = test_result.message
                
                # Add URL context to error messages
                if test_result.details and "url_tested" in test_result.details:
                    url = test_result.details["url_tested"]
                    if "requires authentication" in error_msg and url not in error_msg:
                        error_msg = f"{error_msg} (endpoint: {url})"
                    elif "failed with status" in error_msg and url not in error_msg:
                        error_msg = error_msg.replace("failed with status", f"endpoint {url} returned status")
                
                # Split long messages into readable chunks
                import textwrap
                wrapped = textwrap.fill(error_msg, width=80, initial_indent="   ", subsequent_indent="   ")
                test_info.append(f"\n[yellow]{wrapped}[/yellow]")
            
            # Detailed failure information
            if test_result.details:
                details = test_result.details
                
                # Show what was expected vs what happened with full context
                if "expected_status" in details and "status_code" in details:
                    url = details.get('url_tested', 'endpoint')
                    test_info.append(f"\n   Expected: HTTP {details['expected_status']} → Got: HTTP {details['status_code']} from {url}")
                
                # For WWW-Authenticate issues, show exactly what's missing
                if test_result.test_case.id == "auth-challenge":
                    if details.get("missing_params"):
                        params = details["missing_params"]
                        test_info.append(f"\n   Missing WWW-Authenticate parameters: {', '.join(params)}")
                        test_info.append(f"   Required format: Bearer realm=\"...\", as_uri=\"...\", resource_uri=\"...\"")
                    
                    if details.get("www_authenticate"):
                        test_info.append(f"   Current header: {details['www_authenticate']}")
                    elif details.get("status_code") == 401:
                        test_info.append(f"   Current header: [Missing WWW-Authenticate header entirely]")
                
                # For protocol version issues, show what was sent
                if test_result.test_case.id == "protocol-version" and details.get("diagnosis"):
                    test_info.append(f"\n   Sent header: MCP-Protocol-Version: {details.get('protocol_version_sent', '2025-06-18')}")
                    test_info.append(f"   Server response: {details.get('diagnosis', 'Unknown error')}")
                
                # For skipped tests, show why
                if test_result.status == TestStatus.SKIPPED:
                    if details.get("reason"):
                        test_info.append(f"\n   [yellow]Skipped: {details['reason']}[/yellow]")
                    if details.get("suggestion"):
                        test_info.append(f"   [cyan]→ {details['suggestion']}[/cyan]")
                
                # How to fix (always show for failures)
                if "fix" in details:
                    test_info.append(f"\n   [cyan]Fix: {details['fix']}[/cyan]")
                
                # Integrate recommendations directly into the test result
                # Check if this test has a specific recommendation
                if test_result.test_case.id == "oauth-metadata" and test_result.status == TestStatus.FAILED:
                    url = details.get("url_tested", "/.well-known/oauth-protected-resource")
                    if details.get("status_code") == 401:
                        test_info.append(f"\n   [yellow]→ Recommendation: Remove auth requirement from `{url}` (currently returns 401)[/yellow]")
                    elif details.get("status_code") == 404:
                        test_info.append(f"\n   [yellow]→ Recommendation: Implement `{url}` endpoint (currently returns 404)[/yellow]")
                    else:
                        test_info.append(f"\n   [yellow]→ Recommendation: Fix `{url}` endpoint (currently returns {details.get('status_code', 'error')})[/yellow]")
                
                elif test_result.test_case.id == "auth-challenge" and test_result.status == TestStatus.FAILED:
                    url = details.get("url_tested", "/mcp endpoint")
                    if details.get("status_code") != 401:
                        test_info.append(f"\n   [yellow]→ Recommendation: Return 401 Unauthorized for `{url}` (not {details.get('status_code')})[/yellow]")
                    elif details.get("missing_params"):
                        params = details["missing_params"]
                        test_info.append(f"\n   [yellow]→ Recommendation: Add {', '.join(params)} to Bearer challenge on `{url}`[/yellow]")
                    else:
                        test_info.append(f"\n   [yellow]→ Recommendation: Include proper Bearer challenge on `{url}` responses[/yellow]")
                
                elif test_result.test_case.id == "oauth-server-discovery" and test_result.status == TestStatus.FAILED:
                    # For OAuth server discovery, we consolidate the authorization server check info
                    test_info.append(f"\n   [yellow]→ Recommendation: Implement proper OAuth discovery - either expose authorization servers in /.well-known/oauth-protected-resource (RFC 9728) or ensure OAuth server has /.well-known/oauth-authorization-server (RFC 8414)[/yellow]")
                
                elif test_result.test_case.id == "protocol-version" and test_result.status == TestStatus.FAILED:
                    if "server bug" in details.get("diagnosis", "").lower() or (test_result.message and "failed to read" in test_result.message.lower()):
                        test_info.append(f"\n   [yellow]→ Recommendation: Fix MCP-Protocol-Version header parsing per MCP Transport Spec Section 2.4 (case-insensitive lookup required per RFC 9110 Section 5.1)[/yellow]")
        
        # Print test result
        for line in test_info:
            console.print(line)
        
        # Add spacing between tests
        console.print()
    
    # Remove critical failures and recommendations panels - they're now integrated into test results
    
    # Verbose output - show additional technical details
    if verbose:
        console.print()
        console.print("[bold]Additional Technical Details:[/bold]")
        console.print()
        
        for test_result in result.test_results:
            # Only show tests with interesting technical details
            if test_result.details and test_result.status != TestStatus.PASSED:
                # Skip if no technical details beyond what was already shown
                tech_keys = set(test_result.details.keys()) - {
                    "test_description", "requirement", "purpose", "fix", 
                    "expected_status", "status_code", "url_tested", "spec_reference",
                    "missing_params", "found_params", "spec_requirement", "example_header",
                    "diagnosis", "likely_cause", "note", "violation", "auth_status_code",
                    "www_authenticate", "protocol_version_sent", "header_name", "body"
                }
                
                # Skip tests without additional technical details
                if not tech_keys or all(k in {"error", "errors", "warnings"} for k in tech_keys):
                    continue
                    
                console.print(f"[cyan]{test_result.test_case.name}:[/cyan]")
                
                # Special handling for OAuth server discovery
                if test_result.test_case.id == "oauth-server-discovery":
                    details = test_result.details
                    if details.get("oauth_server_found"):
                        console.print(f"  OAuth Server: {details['oauth_server_found']}")
                    
                    rfc8414_validation = details.get("rfc8414_validation")
                    if rfc8414_validation:
                        console.print(f"  RFC 8414 Valid: {rfc8414_validation.get('valid', False)}")
                        
                        issues = rfc8414_validation.get("issues", {})
                        if issues.get("errors"):
                            console.print("  [red]Errors:[/red]")
                            for error in issues["errors"]:
                                console.print(f"    • {error}")
                        
                        if issues.get("warnings"):
                            console.print("  [yellow]Warnings:[/yellow]")
                            for warning in issues["warnings"]:
                                console.print(f"    • {warning}")
                        
                        if issues.get("info"):
                            console.print("  [blue]Info:[/blue]")
                            for info in issues["info"]:
                                console.print(f"    • {info}")
                        
                        # Show metadata summary
                        metadata = rfc8414_validation.get("metadata", {})
                        if metadata:
                            console.print("  [dim]Metadata Summary:[/dim]")
                            console.print(f"    Issuer: {metadata.get('issuer', 'N/A')}")
                            console.print(f"    Scopes: {', '.join(metadata.get('scopes_supported', []))}")
                            console.print(f"    Resource Indicators: {metadata.get('resource_indicators_supported', False)}")
                
                # Special handling for MCP tools test
                elif test_result.test_case.id == "mcp-tools":
                    details = test_result.details
                    console.print(f"  Session initialized: {details.get('session_initialized', False)}")
                    if details.get('session_error'):
                        console.print(f"  Session error: [red]{details['session_error']}[/red]")
                    console.print(f"  Tools discovered: {details.get('tools_discovered', 0)}")
                    
                    # Show any errors encountered
                    errors = details.get('errors', [])
                    if errors:
                        console.print("  [red]Errors encountered:[/red]")
                        for error in errors:
                            console.print(f"    • {error}")
                    
                    if details.get('tools_discovered', 0) > 0:
                        console.print(f"  Tools tested: {details.get('tools_tested', 0)}")
                        console.print(f"  Tools passed: [green]{details.get('tools_passed', 0)}[/green]")
                        console.print(f"  Tools failed: [red]{details.get('tools_failed', 0)}[/red]")
                        console.print(f"  Tools skipped: [yellow]{details.get('tools_skipped', 0)}[/yellow]")
                        
                        # Show individual tool results
                        tool_results = details.get('tool_results', [])
                        if tool_results:
                            console.print("\n  [bold]Tool Test Results:[/bold]")
                            
                            for tool_result in tool_results:
                                status_style = {
                                    "success": "[green]✓[/green]",
                                    "failed": "[red]✗[/red]",
                                    "error": "[red]✗[/red]",
                                    "tool_error": "[yellow]⚠[/yellow]",
                                    "skipped": "[yellow]⊘[/yellow]",
                                    "exception": "[red]⚠[/red]",
                                    "invalid": "[red]✗[/red]"
                                }
                                
                                status_icon = status_style.get(tool_result['status'], "?")
                                tool_name = tool_result['tool_name']
                                
                                console.print(f"\n    {status_icon} [bold]{tool_name}[/bold]")
                                if tool_result.get('description'):
                                    console.print(f"      Description: {tool_result['description']}")
                                
                                if tool_result.get('destructive'):
                                    console.print("      [yellow]⚠ Destructive tool[/yellow]")
                                if tool_result.get('read_only'):
                                    console.print("      [dim]Read-only tool[/dim]")
                                
                                if tool_result['status'] != 'success':
                                    if tool_result.get('error'):
                                        console.print(f"      Error: [red]{tool_result['error']}[/red]")
                                
                                if tool_result.get('test_params'):
                                    console.print(f"      Test params: {json.dumps(tool_result['test_params'], indent=8)}")
                
                # Special handling for skipped tests
                elif test_result.status == TestStatus.SKIPPED:
                    suggestion = test_result.details.get("suggestion")
                    note = test_result.details.get("note")
                    if suggestion:
                        console.print(f"  [yellow]→ {suggestion}[/yellow]")
                    if note:
                        console.print(f"  [dim]{note}[/dim]")
                
                # Generic details display for other tests
                else:
                    for key, value in test_result.details.items():
                        if isinstance(value, (dict, list)):
                            console.print(f"  {key}: {json.dumps(value, indent=2)}")
                        else:
                            console.print(f"  {key}: {value}")
    
    # Summary statistics at the end
    result = report.validation_result
    if show_summary:
        console.print()
        console.print("[bold]Test Summary:[/bold]")
        
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column(style="dim")
        summary_table.add_column()
        
        # Determine compliance level color
        level_colors = {
            "FULLY_COMPLIANT": "green",
            "MOSTLY_COMPLIANT": "yellow", 
            "PARTIALLY_COMPLIANT": "yellow",
            "MINIMALLY_COMPLIANT": "red",
            "NON_COMPLIANT": "red",
            "UNKNOWN": "dim"
        }
        level_color = level_colors.get(report.compliance_level, "white")
        
        summary_table.add_row("Server:", f"[cyan]{report.server_info.url}[/cyan]")
        summary_table.add_row("Compliance:", f"[bold {level_color}]{report.compliance_level}[/bold {level_color}]")
        summary_table.add_row("Total Tests:", str(result.total_tests))
        summary_table.add_row("Passed:", f"[green]{result.passed_tests}[/green]")
        summary_table.add_row("Failed:", f"[red]{result.failed_tests}[/red]")
        if result.skipped_tests > 0:
            summary_table.add_row("Skipped:", f"[yellow]{result.skipped_tests}[/yellow]")
        summary_table.add_row("Success Rate:", f"{result.success_rate:.1f}%")
        summary_table.add_row("Duration:", f"{report.validation_result.duration:.2f}s")
        
        # Check for OAuth server discovery
        oauth_test = next((r for r in result.test_results if r.test_case.id == "oauth-server-discovery"), None)
        if oauth_test and oauth_test.details:
            oauth_server = oauth_test.details.get("oauth_server_found")
            if oauth_server:
                summary_table.add_row("OAuth Server:", f"[cyan]{oauth_server}[/cyan]")
        
        console.print(summary_table)


@cli.command()
@click.argument("auth_server_url")
@click.option(
    "--client-id",
    help="OAuth client ID",
    envvar="OAUTH_CLIENT_ID",
)
@click.option(
    "--client-secret",
    help="OAuth client secret",
    envvar="OAUTH_CLIENT_SECRET",
)
@click.option(
    "--register",
    is_flag=True,
    help="Register a new OAuth client",
)
def oauth(
    auth_server_url: str,
    client_id: Optional[str],
    client_secret: Optional[str],
    register: bool,
):
    """Test OAuth authorization server compliance.
    
    Example:
        mcp-validate oauth https://auth.example.com --register
    """
    async def run_oauth_test():
        has_failures = False
        async with OAuthTestClient(
            auth_server_url,
            client_id=client_id,
            client_secret=client_secret,
        ) as client:
            # Discover metadata
            console.print("[bold]Discovering OAuth server metadata...[/bold]")
            try:
                metadata = await client.discover_metadata()
                metadata_url = f"{auth_server_url}/.well-known/oauth-authorization-server"
                console.print(f"[green]✓[/green] Metadata endpoint found: [cyan]{metadata_url}[/cyan]")
                console.print(f"  Issuer: {metadata.issuer}")
                
                # Show all discovered endpoints
                console.print("\n  Discovered endpoints:")
                console.print(f"  - Authorization: {metadata.authorization_endpoint}")
                console.print(f"  - Token: {metadata.token_endpoint}")
                
                if metadata.jwks_uri:
                    console.print(f"  - JWKS: {metadata.jwks_uri}")
                if metadata.registration_endpoint:
                    console.print(f"  - Registration: {metadata.registration_endpoint}")
                if metadata.introspection_endpoint:
                    console.print(f"  - Introspection: {metadata.introspection_endpoint}")
                if metadata.revocation_endpoint:
                    console.print(f"  - Revocation: {metadata.revocation_endpoint}")
                
                # Show additional metadata
                if metadata.scopes_supported:
                    console.print(f"\n  Scopes supported: {', '.join(metadata.scopes_supported)}")
                if metadata.grant_types_supported:
                    console.print(f"  Grant types: {', '.join(metadata.grant_types_supported)}")
                if metadata.token_endpoint_auth_methods_supported:
                    console.print(f"  Token auth methods: {', '.join(metadata.token_endpoint_auth_methods_supported)}")
                if metadata.id_token_signing_alg_values_supported:
                    console.print(f"  ID token algorithms: {', '.join(metadata.id_token_signing_alg_values_supported)}")
                if metadata.resource_indicators_supported is not None:
                    console.print(f"  Resource indicators: {metadata.resource_indicators_supported}")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to discover metadata: {e}")
                return False  # Failed to discover metadata
            
            # Check compliance
            console.print()
            console.print("[bold]Checking OAuth compliance...[/bold]")
            
            compliance_results = await ComplianceChecker.check_oauth_server_compliance(client)
            
            for check, result in compliance_results.items():
                if result == "PASS":
                    console.print(f"[green]✓[/green] {check}")
                elif result.startswith("WARN"):
                    console.print(f"[yellow]⚠[/yellow] {check}: {result}")
                else:
                    console.print(f"[red]✗[/red] {check}: {result}")
                    has_failures = True  # Track failures
            
            # Register client if requested
            if register:
                console.print()
                console.print("[bold]Registering OAuth client...[/bold]")
                try:
                    new_client_id, new_secret, _ = await client.register_client()
                    console.print("[green]✓[/green] Client registered successfully")
                    console.print(f"  Client ID: {new_client_id}")
                    if new_secret:
                        console.print(f"  Client Secret: {new_secret}")
                        console.print()
                        console.print("[yellow]Save these credentials to your .env file:[/yellow]")
                        console.print(f"OAUTH_CLIENT_ID={new_client_id}")
                        console.print(f"OAUTH_CLIENT_SECRET={new_secret}")
                except Exception as e:
                    console.print(f"[red]✗[/red] Failed to register client: {e}")
                    has_failures = True
            
            return not has_failures  # Return True if no failures
    
    try:
        success = asyncio.run(run_oauth_test())
        if success is False:
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("mcp_server_url")
@click.option(
    "--scope",
    default="mcp:read mcp:write",
    help="OAuth scope to request",
)
@click.option(
    "--no-ssl-verify",
    is_flag=True,
    help="Disable SSL certificate verification",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force new OAuth flow even if valid token exists",
)
def flow(
    mcp_server_url: str,
    scope: str,
    no_ssl_verify: bool,
    force: bool,
):
    """Complete OAuth authentication flow with an MCP server.
    
    Checks for existing valid tokens first. Only initiates new flow if:
    - No valid access token exists
    - Token refresh fails
    - --force flag is used
    
    Automatically discovers OAuth server and uses saved credentials.
    
    Examples:
        mcp-validate flow https://mcp.example.com         # Check/refresh first
        mcp-validate flow https://mcp.example.com --force # Force new flow
    """
    async def run_oauth_flow():
        # First, create validator to discover OAuth server
        env_manager = EnvManager()
        
        async with MCPValidator(
            mcp_server_url,
            verify_ssl=not no_ssl_verify,
        ) as validator:
            # Discover OAuth server
            console.print("[bold]Discovering OAuth server...[/bold]")
            auth_server_url = await validator.discover_oauth_server()
            
            if not auth_server_url:
                console.print("[red]✗[/red] Failed to discover OAuth server from MCP metadata")
                console.print()
                console.print("This MCP server doesn't implement OAuth discovery (/.well-known/oauth-protected-resource).")
                console.print("You may need to obtain a token through the service's standard authentication method.")
                sys.exit(1)
            
            console.print(f"[green]✓[/green] Found OAuth server: {auth_server_url}")
            
            # Get credentials for this server
            credentials = env_manager.get_oauth_credentials(mcp_server_url)
            
            # If force flag is set, clear existing tokens (NOT client registration)
            if force:
                console.print("[yellow]Force flag set: Clearing existing access tokens[/yellow]")
                # Clear tokens only, keep client registration
                server_key = mcp_server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").upper()
                env_manager.delete(f"OAUTH_ACCESS_TOKEN_{server_key}")
                env_manager.delete(f"OAUTH_REFRESH_TOKEN_{server_key}")
                env_manager.delete(f"OAUTH_TOKEN_EXPIRES_AT_{server_key}")
                # Reload credentials to ensure we don't use cached values
                credentials = env_manager.get_oauth_credentials(mcp_server_url)
            
            # Check for existing valid token
            if not force:
                console.print("\n[bold]Checking for existing tokens...[/bold]")
                valid_token = env_manager.get_valid_access_token(mcp_server_url)
                
                if valid_token:
                    # Get token expiration info
                    server_key = mcp_server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").upper()
                    expires_at = env_manager.get(f"OAUTH_TOKEN_EXPIRES_AT_{server_key}")
                    
                    # Calculate remaining time
                    remaining = int(expires_at) - int(time.time()) if expires_at else 0
                    if remaining > 3600:
                        time_left = f"{int(remaining/3600)}h {int((remaining%3600)/60)}m"
                    elif remaining > 60:
                        time_left = f"{int(remaining/60)}m"
                    else:
                        time_left = f"{remaining}s"
                    
                    console.print(f"[green]✓[/green] Valid access token found (expires in {time_left})")
                    console.print(f"  Token: {valid_token[:20]}...")
                    
                    # Test token with MCP server
                    console.print("\n[bold]Testing token with MCP server...[/bold]")
                    async with OAuthTestClient(
                        auth_server_url,
                        client_id=credentials["client_id"],
                        client_secret=credentials["client_secret"],
                        verify_ssl=not no_ssl_verify,
                    ) as test_client:
                        success, error, details = await test_client.test_mcp_server_with_token(
                            mcp_server_url,
                            valid_token,
                        )
                        
                        if success:
                            console.print("[green]✓[/green] Token is valid and working")
                            console.print("\n[dim]Use --force to get a new token anyway[/dim]")
                            return
                        else:
                            console.print(f"[yellow]⚠[/yellow] Token rejected by server: {error}")
                            console.print("Proceeding with token refresh/new flow...")
                
                # Check for refresh token if access token is expired
                refresh_token = env_manager.get_refresh_token(mcp_server_url)
                if refresh_token and not force:
                    console.print("\n[bold]Attempting to refresh token...[/bold]")
                    
                    async with OAuthTestClient(
                        auth_server_url,
                        client_id=credentials["client_id"],
                        client_secret=credentials["client_secret"],
                        verify_ssl=not no_ssl_verify,
                    ) as refresh_client:
                        try:
                            await refresh_client.discover_metadata()
                            token_response = await refresh_client.refresh_token(refresh_token, scope=scope)
                            
                            console.print("[green]✓[/green] Token refreshed successfully")
                            console.print(f"  New access token: {token_response.access_token[:20]}...")
                            console.print(f"  Expires in: {token_response.expires_in} seconds")
                            
                            # Save new tokens
                            env_manager.save_tokens(
                                mcp_server_url,
                                token_response.access_token,
                                token_response.expires_in,
                                token_response.refresh_token or refresh_token  # Keep old refresh token if new one not provided
                            )
                            console.print("[green]✓[/green] New tokens saved to .env")
                            
                            # Test new token
                            console.print("\n[bold]Testing refreshed token...[/bold]")
                            success, error, details = await refresh_client.test_mcp_server_with_token(
                                mcp_server_url,
                                token_response.access_token,
                            )
                            
                            if success:
                                console.print("[green]✓[/green] Refreshed token is valid and working")
                                return
                            else:
                                console.print(f"[yellow]⚠[/yellow] Refreshed token rejected: {error}")
                                console.print("Proceeding with new OAuth flow...")
                        except Exception as e:
                            console.print(f"[yellow]⚠[/yellow] Token refresh failed: {e}")
                            console.print("Proceeding with new OAuth flow...")
                
            # If we get here, we need to do the full OAuth flow
            console.print("\n[bold]Starting OAuth authorization flow...[/bold]")
            
            # Use the generic OAuth flow
            from .generic_oauth_flow import GenericOAuthFlow
            from .oauth_flow_config import OAuthFlowConfig, GrantPreference
            
            # Create configuration for CLI usage
            from .oauth_flow_config import RedirectStrategy
            config = OAuthFlowConfig.from_environment()
            config.grant_preference = GrantPreference.CLI  # Try non-interactive grants first
            config.auto_open_browser = True  # Open browser automatically
            
            # Determine redirect strategy based on existing client registration
            if credentials.get("redirect_uri"):
                # We have an existing client with a registered redirect URI
                redirect_uri = credentials["redirect_uri"]
                if redirect_uri == "urn:ietf:wg:oauth:2.0:oob":
                    config.redirect_strategy = RedirectStrategy.OOB
                    console.print("[dim]Using OOB redirect to match existing client registration[/dim]")
                else:
                    # Use custom redirect to match the exact registered URI
                    config.redirect_strategy = RedirectStrategy.CUSTOM
                    config.custom_redirect_uri = redirect_uri
                    console.print(f"[dim]Using registered redirect URI: {redirect_uri}[/dim]")
            else:
                # No existing client, use public IP strategy for better UX
                # The generic flow will automatically fall back to OOB if registration fails
                config.redirect_strategy = RedirectStrategy.PUBLIC_IP
            
            # Create flow handler
            flow = GenericOAuthFlow(
                mcp_server_url=mcp_server_url,
                auth_server_url=auth_server_url,
                config=config
            )
            
            # Run authentication - this handles everything
            try:
                access_token = await flow.authenticate(
                    scope=scope,
                    verify_ssl=not no_ssl_verify
                )
                
                if not access_token:
                    console.print("[red]✗[/red] Authentication failed")
                    console.print("[dim]Check server logs or try with --verbose flag[/dim]")
                    return
                
                console.print("[green]✓[/green] Authentication successful!")
                console.print(f"  Access token: {access_token[:20]}...")
                
                # RFC 8707 validation - concise output
                token_compliant, token_validation = RFC8707Validator.validate_token_response(
                    access_token,
                    [mcp_server_url]
                )
                
                # Create a client to test the token
                async with OAuthTestClient(
                    auth_server_url,
                    client_id=credentials["client_id"],
                    client_secret=credentials["client_secret"],
                    verify_ssl=not no_ssl_verify,
                ) as test_client:
                    success, error, details = await test_client.test_mcp_server_with_token(
                        mcp_server_url,
                        access_token,
                    )
                    
                    # RFC 8707 validation - Step 3: Resource Server Check
                    server_compliant, server_validation = RFC8707Validator.validate_resource_server_check(
                        mcp_server_url,
                        success,
                        token_validation.get("token_audience", [])
                    )
                    
                    # Display concise RFC 8707 status
                    console.print()
                    if not token_compliant:
                        console.print(f"[red]✗[/red] RFC 8707 violation: OAuth server didn't include {mcp_server_url} in token audience")
                    elif not server_compliant:
                        console.print(f"[red]✗[/red] RFC 8707 violation: MCP server didn't validate audience - {server_validation['errors'][0] if server_validation.get('errors') else 'validation failure'}")
                    else:
                        console.print(f"[green]✓[/green] RFC 8707 compliant: Token and server properly validate resource indicators")
                
            except Exception as e:
                console.print(f"[red]✗[/red] Authentication error: {e}")
                if not no_ssl_verify:
                    console.print("[dim]Tip: Try with --no-ssl-verify flag if using self-signed certificates[/dim]")
    
    try:
        asyncio.run(run_oauth_flow())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.group()
def client():
    """Manage OAuth client registrations (RFC 7592)."""
    pass


@client.command("register")
@click.argument("mcp_server_url")
@click.option(
    "--force",
    is_flag=True,
    help="Force new registration even if client already exists",
)
@click.option(
    "--no-ssl-verify",
    is_flag=True,
    help="Disable SSL certificate verification",
)
@click.option(
    "--validate-rfc7592",
    is_flag=True,
    help="Also validate RFC 7592 management protocol support",
)
def register(
    mcp_server_url: str,
    force: bool,
    no_ssl_verify: bool,
    validate_rfc7592: bool,
):
    """Register OAuth client for an MCP server.
    
    Discovers the OAuth server from MCP metadata and registers a new client.
    Saves credentials to .env for future use.
    
    Example:
        mcp-validate client register https://mcp.example.com
    """
    async def run_register():
        env_manager = EnvManager()
        
        # Check existing credentials
        existing_creds = env_manager.get_oauth_credentials(mcp_server_url)
        if existing_creds["client_id"] and not force:
            console.print(f"[yellow]OAuth client already registered: {existing_creds['client_id']}[/yellow]")
            console.print("Use --force to register a new client")
            return
        
        # Create validator to discover OAuth server
        async with MCPValidator(
            mcp_server_url,
            verify_ssl=not no_ssl_verify,
            auto_register=False,  # We'll handle registration manually
        ) as validator:
            # Discover OAuth server
            console.print("[bold]Discovering OAuth server...[/bold]")
            auth_server_url = await validator.discover_oauth_server()
            
            if not auth_server_url:
                console.print("[red]✗[/red] Failed to discover OAuth server from MCP metadata")
                console.print()
                console.print("This MCP server doesn't implement OAuth discovery (/.well-known/oauth-protected-resource).")
                console.print("Manual OAuth client registration may be required through the service's standard method.")
                sys.exit(1)
            
            console.print(f"[green]✓[/green] Found OAuth server: {auth_server_url}")
            
            # Create OAuth client
            async with OAuthTestClient(
                auth_server_url,
                verify_ssl=not no_ssl_verify,
            ) as client:
                # Discover metadata
                console.print("[bold]Checking OAuth server metadata...[/bold]")
                try:
                    metadata = await client.discover_metadata()
                    console.print("[green]✓[/green] OAuth server metadata valid")
                    
                    # Check for dynamic registration support
                    if not metadata.registration_endpoint:
                        console.print("[red]✗[/red] OAuth server does not support dynamic client registration")
                        console.print("Please register a client manually and add credentials to .env")
                        return
                except Exception as e:
                    console.print(f"[red]✗[/red] Failed to get OAuth metadata: {e}")
                    return
                
                # Prepare registration request
                console.print("[bold]Preparing client registration...[/bold]")
                
                # Always try public IP first, regardless of environment
                from .network_utils import NetworkInfo
                public_ip = await NetworkInfo.detect_public_ip()
                if public_ip:
                    redirect_uri = f"http://{public_ip}:8080/callback"
                    console.print(f"[dim]Attempting registration with public IP: {redirect_uri}[/dim]")
                else:
                    redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
                    console.print(f"[dim]No public IP detected, using OOB: {redirect_uri}[/dim]")
                
                registration_data = {
                    "client_name": f"MCP Validator for {mcp_server_url}",
                    "redirect_uris": [redirect_uri],
                    "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
                    "response_types": ["code"],
                    "scope": "mcp:read mcp:write",
                    "software_id": "mcp-http-validator",
                    "software_version": "0.1.0",
                    "application_type": "native",
                    "token_endpoint_auth_method": "client_secret_post",
                }
                
                # Validate request per RFC 7591
                console.print("\n[bold]RFC 7591 Request Validation:[/bold]")
                request_validation = RFC7591Validator.validate_registration_request(registration_data)
                
                if request_validation.errors:
                    console.print("[red]Request Errors:[/red]")
                    for error in request_validation.errors:
                        console.print(f"  ✗ {error}")
                
                if request_validation.warnings:
                    console.print("[yellow]Request Warnings:[/yellow]")
                    for warning in request_validation.warnings:
                        console.print(f"  ⚠ {warning}")
                
                if request_validation.info:
                    console.print("[blue]Request Info:[/blue]")
                    for info in request_validation.info:
                        console.print(f"  ℹ {info}")
                
                if not request_validation.valid:
                    console.print("\n[red]✗[/red] Registration request invalid per RFC 7591")
                    return
                else:
                    console.print("[green]✓[/green] Registration request valid per RFC 7591")
                
                # Register new client
                console.print("\n[bold]Registering OAuth client...[/bold]")
                response_data = None
                successful_redirect_uri = None
                
                try:
                    # Send registration request manually to capture full response
                    response = await client.client.post(
                        str(metadata.registration_endpoint),
                        json=registration_data,
                        headers={"Content-Type": "application/json"},
                    )
                    response.raise_for_status()
                    
                    response_data = response.json()
                    successful_redirect_uri = redirect_uri
                    
                    # Validate response per RFC 7591
                    console.print("\n[bold]RFC 7591 Response Validation:[/bold]")
                    response_validation = RFC7591Validator.validate_registration_response(
                        response_data,
                        registration_data
                    )
                    
                    if response_validation.errors:
                        console.print("[red]Response Errors:[/red]")
                        for error in response_validation.errors:
                            console.print(f"  ✗ {error}")
                    
                    if response_validation.warnings:
                        console.print("[yellow]Response Warnings:[/yellow]")
                        for warning in response_validation.warnings:
                            console.print(f"  ⚠ {warning}")
                    
                    if response_validation.info:
                        console.print("[blue]Response Info:[/blue]")
                        for info in response_validation.info:
                            console.print(f"  ℹ {info}")
                    
                    if not response_validation.valid:
                        console.print("\n[red]✗[/red] Registration response invalid per RFC 7591")
                    else:
                        console.print("[green]✓[/green] Registration response valid per RFC 7591")
                    
                    # Extract credentials
                    client_id = response_data.get("client_id")
                    client_secret = response_data.get("client_secret")
                    reg_token = response_data.get("registration_access_token")
                    reg_uri = response_data.get("registration_client_uri")
                    
                    # Save credentials including redirect URI
                    env_manager.save_oauth_credentials(
                        mcp_server_url,
                        client_id,
                        client_secret,
                        reg_token,
                        redirect_uri=successful_redirect_uri,  # Save the actually registered URI
                    )
                    
                    console.print("\n[green]✓[/green] Client registered successfully")
                    console.print(f"  Client ID: {client_id}")
                    console.print(f"  Client Secret: {'*' * 20}...")
                    if reg_token:
                        console.print(f"  Registration Token: {'*' * 20}...")
                    if reg_uri:
                        console.print(f"  Management URI: {reg_uri}")
                    
                    # Show response details
                    console.print("\n[bold]Registration Response:[/bold]")
                    for key, value in response_data.items():
                        if key in ["client_secret", "registration_access_token"]:
                            console.print(f"  {key}: {'*' * 20}...")
                        else:
                            console.print(f"  {key}: {value}")
                    
                    # Test RFC 7592 if requested and supported
                    if validate_rfc7592 and reg_token and reg_uri:
                        console.print("\n[bold]RFC 7592 Management Protocol Validation:[/bold]")
                        
                        rfc7592_result = await RFC7592Validator.validate_management_support(
                            client.client,
                            reg_uri,
                            reg_token,
                            client_id
                        )
                        
                        if rfc7592_result.errors:
                            console.print("[red]Management Errors:[/red]")
                            for error in rfc7592_result.errors:
                                console.print(f"  ✗ {error}")
                        
                        if rfc7592_result.warnings:
                            console.print("[yellow]Management Warnings:[/yellow]")
                            for warning in rfc7592_result.warnings:
                                console.print(f"  ⚠ {warning}")
                        
                        if rfc7592_result.info:
                            console.print("[blue]Management Info:[/blue]")
                            for info in rfc7592_result.info:
                                console.print(f"  ℹ {info}")
                        
                        console.print("\n[bold]RFC 7592 Support:[/bold]")
                        console.print(f"  Read (GET): {'✓' if rfc7592_result.read_supported else '✗'}")
                        console.print(f"  Update (PUT): {'✓' if rfc7592_result.update_supported else '✗'}")
                        console.print(f"  Delete (DELETE): Not tested")
                        
                        if rfc7592_result.valid:
                            console.print("\n[green]✓[/green] RFC 7592 compliant")
                        else:
                            console.print("\n[red]✗[/red] RFC 7592 non-compliant")
                    
                    console.print("\n[green]✓[/green] Credentials saved to .env")
                    console.print("\nYou can now use:")
                    console.print(f"  • [cyan]mcp-validate flow {mcp_server_url}[/cyan] - Get access token")
                    console.print(f"  • [cyan]mcp-validate validate {mcp_server_url}[/cyan] - Run validation tests")
                    
                except httpx.HTTPStatusError as e:
                    console.print(f"[red]✗[/red] Registration failed with status {e.response.status_code}")
                    try:
                        error_data = e.response.json()
                        console.print(f"  Error: {error_data.get('error', 'Unknown')}")
                        if 'error_description' in error_data:
                            console.print(f"  Description: {error_data['error_description']}")
                    except:
                        console.print(f"  Response: {e.response.text}")
                    
                    # Try fallback to OOB if not already using it
                    if redirect_uri != "urn:ietf:wg:oauth:2.0:oob":
                        console.print("\n[dim]Falling back to out-of-band redirect...[/dim]")
                        registration_data["redirect_uris"] = ["urn:ietf:wg:oauth:2.0:oob"]
                        
                        try:
                            response = await client.client.post(
                                str(metadata.registration_endpoint),
                                json=registration_data,
                                headers={"Content-Type": "application/json"},
                            )
                            response.raise_for_status()
                            response_data = response.json()
                            successful_redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
                            
                            console.print("[green]✓[/green] Registration successful with OOB fallback")
                            
                            # Extract credentials and save
                            client_id = response_data.get("client_id")
                            client_secret = response_data.get("client_secret")
                            reg_token = response_data.get("registration_access_token")
                            
                            env_manager.save_oauth_credentials(
                                mcp_server_url,
                                client_id,
                                client_secret,
                                reg_token,
                                redirect_uri=successful_redirect_uri,
                            )
                            
                            console.print("\n[green]✓[/green] Client registered successfully")
                            console.print(f"  Client ID: {client_id}")
                            console.print(f"  Client Secret: {'*' * 20}...")
                            console.print("\n[green]✓[/green] Credentials saved to .env")
                            console.print("\nYou can now use:")
                            console.print(f"  • [cyan]mcp-validate flow {mcp_server_url}[/cyan] - Get access token")
                            console.print(f"  • [cyan]mcp-validate validate {mcp_server_url}[/cyan] - Run validation tests")
                        except Exception as e2:
                            console.print(f"[red]✗[/red] OOB fallback also failed: {e2}")
                except Exception as e:
                    console.print(f"[red]✗[/red] Failed to register client: {e}")
    
    try:
        asyncio.run(run_register())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.group()
def tokens():
    """Manage OAuth access and refresh tokens."""
    pass


@client.command("list")
def client_list():
    """List all saved OAuth client credentials."""
    env_manager = EnvManager()
    credentials = env_manager.list_credentials()
    
    if not credentials:
        console.print("[yellow]No OAuth clients found in .env[/yellow]")
        return
    
    table = Table(title="OAuth Client Credentials & Tokens")
    table.add_column("Server", style="cyan")
    table.add_column("Client ID", style="green")
    table.add_column("Has Secret", style="yellow")
    table.add_column("Access Token", style="blue")
    table.add_column("Refresh Token", style="magenta")
    
    for server_key, creds in credentials.items():
        # Format access token status
        if creds.get("token_valid"):
            token_status = "✓ Valid"
        elif creds.get("has_access_token"):
            token_status = "⚠ Expired"
        else:
            token_status = "✗"
            
        table.add_row(
            server_key,
            creds.get("client_id", "")[:20] + "..." if len(creds.get("client_id", "")) > 20 else creds.get("client_id", ""),
            "✓" if creds.get("client_secret") else "✗",
            token_status,
            "✓" if creds.get("has_refresh_token") else "✗",
        )
    
    console.print(table)


@client.command("update")
@click.argument("mcp_server_url")
@click.option("--client-name", help="New client name")
@click.option("--redirect-uri", help="New redirect URI")
@click.option("--scope", help="New scope")
def client_update(
    mcp_server_url: str,
    client_name: Optional[str],
    redirect_uri: Optional[str],
    scope: Optional[str],
):
    """Update OAuth client configuration (RFC 7592)."""
    async def run_update():
        env_manager = EnvManager()
        credentials = env_manager.get_oauth_credentials(mcp_server_url)
        
        if not credentials["registration_token"]:
            console.print("[red]No registration token found for client management[/red]")
            return
        
        # Discover OAuth server
        async with MCPValidator(mcp_server_url) as validator:
            auth_server_url = await validator.discover_oauth_server()
            
            if not auth_server_url:
                console.print("[red]Failed to discover OAuth server[/red]")
                return
            
            # Create OAuth client with registration token
            async with OAuthTestClient(
                auth_server_url,
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
                registration_access_token=credentials["registration_token"],
            ) as client:
                # Build updates
                updates = {}
                if client_name:
                    updates["client_name"] = client_name
                if redirect_uri:
                    updates["redirect_uris"] = [redirect_uri]
                if scope:
                    updates["scope"] = scope
                
                if not updates:
                    console.print("[yellow]No updates specified[/yellow]")
                    return
                
                try:
                    updated_config = await client.update_client_configuration(updates)
                    console.print("[green]✓[/green] Client configuration updated")
                    
                    # Save new credentials if changed
                    if updated_config.get("registration_access_token") != credentials["registration_token"]:
                        env_manager.save_oauth_credentials(
                            mcp_server_url,
                            updated_config["client_id"],
                            updated_config.get("client_secret"),
                            updated_config.get("registration_access_token"),
                        )
                        console.print("[yellow]New credentials saved to .env[/yellow]")
                        
                except Exception as e:
                    console.print(f"[red]Update failed: {e}[/red]")
    
    try:
        asyncio.run(run_update())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@client.command("delete")
@click.argument("mcp_server_url")
@click.confirmation_option(prompt="Are you sure you want to delete this client?")
def client_delete(mcp_server_url: str):
    """Delete OAuth client registration (RFC 7592)."""
    async def run_delete():
        env_manager = EnvManager()
        credentials = env_manager.get_oauth_credentials(mcp_server_url)
        
        if not credentials["client_id"]:
            console.print("[red]No client found for this server[/red]")
            return
        
        if not credentials["registration_token"]:
            console.print("[yellow]No registration token - removing local credentials only[/yellow]")
            env_manager.remove_oauth_credentials(mcp_server_url)
            console.print("[green]✓[/green] Local credentials removed")
            return
        
        # Discover OAuth server
        async with MCPValidator(mcp_server_url) as validator:
            auth_server_url = await validator.discover_oauth_server()
            
            if not auth_server_url:
                console.print("[red]Failed to discover OAuth server[/red]")
                return
            
            # Create OAuth client with registration token
            async with OAuthTestClient(
                auth_server_url,
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
                registration_access_token=credentials["registration_token"],
            ) as client:
                try:
                    if await client.delete_client_registration():
                        console.print("[green]✓[/green] Client registration deleted from server")
                        env_manager.remove_oauth_credentials(mcp_server_url)
                        console.print("[green]✓[/green] Local credentials removed")
                    else:
                        console.print("[red]Failed to delete client registration[/red]")
                        
                except Exception as e:
                    console.print(f"[red]Deletion failed: {e}[/red]")
    
    try:
        asyncio.run(run_delete())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@tokens.command("list")
def token_list():
    """List all stored OAuth tokens."""
    env_manager = EnvManager()
    credentials = env_manager.list_credentials()
    
    if not credentials:
        console.print("[yellow]No OAuth credentials or tokens found in .env[/yellow]")
        return
    
    table = Table(title="OAuth Tokens Status")
    table.add_column("Server", style="cyan", no_wrap=True)
    table.add_column("Access Token", style="green")
    table.add_column("Expires", style="yellow")
    table.add_column("Refresh Token", style="blue")
    
    has_tokens = False
    for server_key, creds in credentials.items():
        if server_key == "DEFAULT":
            continue
            
        # Check token details
        server_key_upper = server_key
        access_token = env_manager.get(f"OAUTH_ACCESS_TOKEN_{server_key_upper}")
        expires_at = env_manager.get(f"OAUTH_TOKEN_EXPIRES_AT_{server_key_upper}")
        refresh_token = env_manager.get(f"OAUTH_REFRESH_TOKEN_{server_key_upper}")
        
        if not access_token and not refresh_token:
            continue
            
        has_tokens = True
        
        # Format expiration
        if expires_at:
            try:
                exp_time = int(expires_at)
                remaining = exp_time - time.time()
                if remaining > 0:
                    if remaining > 3600:
                        expires_display = f"[green]{int(remaining/3600)}h {int((remaining%3600)/60)}m[/green]"
                    else:
                        expires_display = f"[yellow]{int(remaining/60)}m[/yellow]"
                else:
                    expires_display = "[red]Expired[/red]"
            except:
                expires_display = "[dim]Unknown[/dim]"
        else:
            expires_display = "[dim]N/A[/dim]"
            
        # Format tokens for display
        access_display = f"{access_token[:20]}..." if access_token else "[red]None[/red]"
        refresh_display = "✓" if refresh_token else "✗"
        
        # Format server name
        server_display = server_key.replace("_", ".").lower()
        if server_display.endswith(".mcp"):
            server_display = server_display[:-4] + "/mcp"
        
        table.add_row(
            server_display,
            access_display,
            expires_display,
            refresh_display,
        )
    
    if has_tokens:
        console.print(table)
        console.print()
        console.print("[dim]Use 'mcp-validate token refresh <server>' to refresh expired tokens[/dim]")
        console.print("[dim]Use 'mcp-validate flow <server>' to obtain new tokens[/dim]")
    else:
        console.print("[yellow]No tokens found. Use 'mcp-validate flow <server>' to obtain tokens.[/yellow]")


@tokens.command("show")
@click.argument("mcp_server_url")
def token_show(mcp_server_url: str):
    """Show token status for a specific server."""
    env_manager = EnvManager()
    
    # Check for valid access token
    valid_token = env_manager.get_valid_access_token(mcp_server_url)
    refresh_token = env_manager.get_refresh_token(mcp_server_url)
    
    console.print(f"[bold]Token Status for {mcp_server_url}[/bold]")
    console.print()
    
    if valid_token:
        console.print("[green]✓[/green] Valid access token found")
        console.print(f"  Token: {valid_token[:20]}...")
    else:
        # Check if expired token exists
        server_key = mcp_server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").upper()
        expired_token = env_manager.get(f"OAUTH_ACCESS_TOKEN_{server_key}")
        if expired_token:
            console.print("[yellow]⚠[/yellow] Access token expired")
        else:
            console.print("[red]✗[/red] No access token")
    
    if refresh_token:
        console.print("[green]✓[/green] Refresh token available")
        console.print(f"  Token: {refresh_token[:20]}...")
    else:
        console.print("[red]✗[/red] No refresh token")
    
    console.print()
    console.print("Use 'mcp-validate flow' to obtain new tokens")


@tokens.command("clear")
@click.argument("mcp_server_url")
@click.confirmation_option(prompt="Are you sure you want to clear tokens?")
def token_clear(mcp_server_url: str):
    """Clear stored tokens for a specific server (keeps client credentials)."""
    env_manager = EnvManager()
    
    server_key = mcp_server_url.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_").upper()
    
    # Clear token-related keys
    token_keys = [
        f"OAUTH_ACCESS_TOKEN_{server_key}",
        f"OAUTH_TOKEN_EXPIRES_AT_{server_key}",
        f"OAUTH_REFRESH_TOKEN_{server_key}",
    ]
    
    success = True
    for key in token_keys:
        if env_manager.get(key):
            env_manager.set(key, "")
    
    if success:
        console.print(f"[green]✓[/green] Tokens cleared for {mcp_server_url}")
    else:
        console.print(f"[red]✗[/red] Failed to clear some tokens")


@tokens.command("refresh")
@click.argument("mcp_server_url")
def token_refresh(mcp_server_url: str):
    """Refresh access token using stored refresh token."""
    async def run_refresh():
        env_manager = EnvManager()
        refresh_token = env_manager.get_refresh_token(mcp_server_url)
        
        if not refresh_token:
            console.print("[red]No refresh token found[/red]")
            return
        
        # Create validator to get OAuth client
        async with MCPValidator(mcp_server_url) as validator:
            auth_server = await validator.discover_oauth_server()
            if not auth_server:
                console.print("[red]Failed to discover OAuth server[/red]")
                return
            
            credentials = env_manager.get_oauth_credentials(mcp_server_url)
            
            async with OAuthTestClient(
                auth_server,
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
            ) as client:
                await client.discover_metadata()
                
                try:
                    console.print("Refreshing token...")
                    token_response = await client.refresh_token(refresh_token)
                    
                    # Save new tokens
                    env_manager.save_tokens(
                        mcp_server_url,
                        token_response.access_token,
                        token_response.expires_in,
                        token_response.refresh_token or refresh_token
                    )
                    
                    console.print("[green]✓[/green] Token refreshed successfully")
                    console.print(f"  New access token: {token_response.access_token[:20]}...")
                    console.print(f"  Expires in: {token_response.expires_in} seconds")
                    
                except Exception as e:
                    console.print(f"[red]✗[/red] Token refresh failed: {e}")
    
    try:
        asyncio.run(run_refresh())
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.argument("mcp_server_url")
@click.option(
    "--no-ssl-verify",
    is_flag=True,
    help="Disable SSL certificate verification",
)
@click.option(
    "--test-destructive",
    is_flag=True,
    help="Also test destructive tools (use with caution)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed test information",
)
def full(
    mcp_server_url: str,
    no_ssl_verify: bool,
    test_destructive: bool,
    verbose: bool,
):
    """Run ALL validation tests on an MCP server.
    
    This runs a comprehensive test suite in the correct order:
    1. OAuth server discovery and testing (if needed)
    2. OAuth client registration (if needed)
    3. OAuth flow to get access token (if needed)
    4. Main MCP validation
    5. MCP tools testing
    
    Example:
        mcp-validate full https://mcp.example.com
    """
    env_manager = EnvManager()
    
    console.print("[bold]Running Full MCP Validation Suite[/bold]")
    console.print(f"Server: [cyan]{mcp_server_url}[/cyan]")
    console.print()
    
    # Track overall results
    all_passed = True
    oauth_passed = None
    validation_passed = None
    
    # 0. First check if server requires authentication
    async def check_auth_required():
        async with MCPValidator(mcp_server_url, verify_ssl=not no_ssl_verify) as validator:
            return await validator._check_auth_required()
    
    auth_required = asyncio.run(check_auth_required())
    
    if not auth_required:
        console.print("[green]ℹ️  This is a public MCP server (no authentication required)[/green]")
        console.print("[green]   Skipping OAuth discovery and authentication steps[/green]")
        console.print()
    
    # Only check OAuth if authentication is required
    oauth_server_url = None
    if auth_required:
        # Check if we need OAuth setup
        credentials = env_manager.get_oauth_credentials(mcp_server_url)
        has_valid_token = env_manager.get_valid_access_token(mcp_server_url) is not None
        
        # 1. Test OAuth server first
        console.print("[bold blue]═══ Testing OAuth Server ═══[/bold blue]")
        
        async def check_oauth_discovery():
            async with MCPValidator(mcp_server_url, verify_ssl=not no_ssl_verify) as validator:
                oauth_server = await validator.discover_oauth_server()
                if oauth_server:
                    console.print(f"[green]✓[/green] OAuth server discovered: {oauth_server}")
                    return oauth_server
                else:
                    console.print("[yellow]No OAuth server discovered - MCP server doesn't implement OAuth discovery[/yellow]")
                    console.print("[dim]This server may use a different authentication method[/dim]")
                    return None
        
        console.print("[bold]Discovering OAuth server metadata...[/bold]")
        oauth_server_url = asyncio.run(check_oauth_discovery())
        
        # If OAuth server discovered, test its compliance
        if oauth_server_url:
            console.print()
            # Run OAuth server compliance test directly
            async def run_oauth_compliance():
                has_failures = False
                async with OAuthTestClient(oauth_server_url) as client:
                    try:
                        metadata = await client.discover_metadata()
                        metadata_url = f"{oauth_server_url}/.well-known/oauth-authorization-server"
                        console.print(f"[green]✓[/green] Metadata endpoint found: [cyan]{metadata_url}[/cyan]")
                        console.print(f"  Issuer: {metadata.issuer}")
                        
                        # Show all discovered endpoints
                        console.print("\n  Discovered endpoints:")
                        console.print(f"  - Authorization: {metadata.authorization_endpoint}")
                        console.print(f"  - Token: {metadata.token_endpoint}")
                        
                        if metadata.jwks_uri:
                            console.print(f"  - JWKS: {metadata.jwks_uri}")
                        if metadata.registration_endpoint:
                            console.print(f"  - Registration: {metadata.registration_endpoint}")
                        if metadata.introspection_endpoint:
                            console.print(f"  - Introspection: {metadata.introspection_endpoint}")
                        if metadata.revocation_endpoint:
                            console.print(f"  - Revocation: {metadata.revocation_endpoint}")
                        
                        # Show additional metadata
                        if metadata.scopes_supported:
                            console.print(f"\n  Scopes supported: {', '.join(metadata.scopes_supported)}")
                        if metadata.grant_types_supported:
                            console.print(f"  Grant types: {', '.join(metadata.grant_types_supported)}")
                        if metadata.token_endpoint_auth_methods_supported:
                            console.print(f"  Token auth methods: {', '.join(metadata.token_endpoint_auth_methods_supported)}")
                        if metadata.id_token_signing_alg_values_supported:
                            console.print(f"  ID token algorithms: {', '.join(metadata.id_token_signing_alg_values_supported)}")
                        if metadata.resource_indicators_supported is not None:
                            console.print(f"  Resource indicators: {metadata.resource_indicators_supported}")
                    except Exception as e:
                        console.print(f"[red]✗[/red] Failed to discover metadata: {e}")
                        return False
                    
                    # Check compliance (without redundant header)
                    console.print()
                    compliance_results = await ComplianceChecker.check_oauth_server_compliance(client)
                    
                    for check, result in compliance_results.items():
                        if result == "PASS":
                            console.print(f"[green]✓[/green] {check}")
                        elif result.startswith("WARN"):
                            console.print(f"[yellow]⚠[/yellow] {check}: {result}")
                        else:
                            console.print(f"[red]✗[/red] {check}: {result}")
                            has_failures = True
                    
                    return not has_failures
            
            oauth_passed = asyncio.run(run_oauth_compliance())
            if not oauth_passed:
                all_passed = False
        else:
            oauth_passed = False  # No OAuth server found when auth required
            all_passed = False
        
        console.print()
    
    # Only proceed with OAuth if server supports it AND requires auth
    if oauth_server_url and auth_required:
        # 2. Register OAuth client if needed
        console.print("[bold blue]═══ OAuth Client Registration ═══[/bold blue]")
        if not credentials["client_id"]:
            console.print("[yellow]No OAuth client registered for this server[/yellow]")
            console.print("[dim]Attempting automatic client registration...[/dim]")
            
            # Run client registration
            async def register_client():
                async with MCPValidator(mcp_server_url, verify_ssl=not no_ssl_verify, auto_register=False) as validator:
                    auth_server_url = await validator.discover_oauth_server()
                    if not auth_server_url:
                        return False
                    
                    async with OAuthTestClient(auth_server_url, verify_ssl=not no_ssl_verify) as client:
                        try:
                            # Get metadata
                            metadata = await client.discover_metadata()
                            if not metadata.registration_endpoint:
                                console.print("[red]✗[/red] OAuth server doesn't support dynamic client registration")
                                return False
                            
                            # Register client
                            registration_data = {
                                "client_name": "MCP HTTP Validator (Full Test)",
                                "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob"],
                                "grant_types": ["authorization_code", "refresh_token"],
                                "response_types": ["code"],
                                "scope": "mcp:read mcp:write",
                                "software_id": "mcp-http-validator",
                                "software_version": "0.1.0",
                            }
                            
                            response = await client.client.post(
                                str(metadata.registration_endpoint),
                                json=registration_data,
                                headers={"Content-Type": "application/json"},
                            )
                            response.raise_for_status()
                            
                            response_data = response.json()
                            client_id = response_data.get("client_id")
                            client_secret = response_data.get("client_secret")
                            reg_token = response_data.get("registration_access_token")
                            
                            # Save credentials
                            env_manager.save_oauth_credentials(
                                mcp_server_url,
                                client_id,
                                client_secret,
                                reg_token,
                            )
                            
                            console.print(f"[green]✓[/green] Client registered successfully: {client_id}")
                            return True
                            
                        except Exception as e:
                            console.print(f"[red]✗[/red] Registration failed: {e}")
                            return False
            
            registration_success = asyncio.run(register_client())
            if registration_success:
                # Reload credentials
                credentials = env_manager.get_oauth_credentials(mcp_server_url)
            else:
                console.print("[yellow]Continuing without OAuth client...[/yellow]")
        else:
            console.print(f"[green]✓[/green] OAuth client already registered: {credentials['client_id']}")
        console.print()
        
        # 3. Get access token if needed
        if not has_valid_token and credentials["client_id"]:
            console.print("[bold blue]═══ OAuth Authentication Flow ═══[/bold blue]")
            console.print("[yellow]No valid access token found[/yellow]")
            console.print(f"[dim]Would obtain token with: mcp-validate flow {mcp_server_url}[/dim]")
            console.print("[red]Skipping - OAuth flow not yet implemented in full command[/red]")
            console.print()
    
    # 4. Run main validation
    console.print("[bold blue]═══ Main MCP Validation ═══[/bold blue]")
    
    # Run validation directly
    async def run_validation_test():
        # Track results for building report at the end
        test_results = []
        
        async def display_detailed_test_result(result: TestResult):
            """Display detailed test result as it completes."""
            test_results.append(result)
            
            # Build detailed test display - same logic as display_terminal_report
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
            
            # Build test display
            test_info = []
            
            # Test name and status on same line
            test_info.append(f"[bold {color}]{icon} {result.test_case.name}[/bold {color}] [{result.test_case.category}]")
            
            # Test description if available
            if result.details and result.details.get("test_description"):
                desc = result.details["test_description"]
                test_info.append(f"   [dim]Testing: {desc}[/dim]")
            
            # Add URL tested if available
            if result.details and result.details.get("url_tested"):
                test_info.append(f"   [dim]URL: {result.details['url_tested']}[/dim]")
        
            # Show details for all tests (not just failures) but vary by status
            if result.status == TestStatus.PASSED:
                # For passed tests, show the success message if available
                if result.message:
                    # Success messages are now in message field
                    import textwrap
                    wrapped = textwrap.fill(result.message, width=80, initial_indent="   ", subsequent_indent="   ")
                    test_info.append(f"\n[green]{wrapped}[/green]")
                
                # Add any additional details
                if result.details:
                    details = result.details
                    
                    # Special handling for specific successful tests
                    if result.test_case.id == "http-transport" and "content_type" in details:
                        test_info.append(f"   [dim]Transport type: {details.get('transport_type', 'json')}[/dim]")
            
            else:  # Failed, Error, or Skipped
                # Primary error message with context
                if result.message:
                    # Make error messages more specific
                    error_msg = result.message
                    
                    # Add URL context to error messages
                    if result.details and "url_tested" in result.details:
                        url = result.details["url_tested"]
                        if "requires authentication" in error_msg and url not in error_msg:
                            error_msg = f"{error_msg} (endpoint: {url})"
                        elif "failed with status" in error_msg and url not in error_msg:
                            error_msg = error_msg.replace("failed with status", f"endpoint {url} returned status")
                    
                    # Split long messages into readable chunks
                    import textwrap
                    wrapped = textwrap.fill(error_msg, width=80, initial_indent="   ", subsequent_indent="   ")
                    test_info.append(f"\n[yellow]{wrapped}[/yellow]")
                
                # Detailed failure information
                if result.details:
                    details = result.details
                    
                    # Show what was expected vs what happened with full context
                    if "expected_status" in details and "status_code" in details:
                        url = details.get('url_tested', 'endpoint')
                        test_info.append(f"\n   Expected: HTTP {details['expected_status']} → Got: HTTP {details['status_code']} from {url}")
                    
                    # Add fix recommendation if available
                    if details.get("fix"):
                        test_info.append(f"\n   [cyan]Fix: {details['fix']}[/cyan]")
                    
                    # Add spec reference recommendation if available
                    if details.get("spec_reference"):
                        test_info.append(f"\n   [yellow]→ {details['spec_reference']}[/yellow]")
            
            # Print test result
            for line in test_info:
                console.print(line)
            
            # Add spacing between tests
            console.print()
        
        async with MCPValidator(
            mcp_server_url,
            access_token=None,  # Let it use env token
            timeout=30.0,
            verify_ssl=not no_ssl_verify,
            auto_register=False,
            progress_callback=display_detailed_test_result,  # Stream detailed results
        ) as validator:
            # Check if we have a token
            validator.access_token = validator.env_manager.get_valid_access_token(mcp_server_url)
            if validator.access_token:
                console.print("[dim]Using stored access token from .env[/dim]")
            else:
                console.print("[yellow]Some tests may be skipped without authentication[/yellow]")
            
            console.print()
            console.print("[bold]Test Results:[/bold]")
            console.print()
            
            validation_result = await validator.validate()
            server_info = validator.server_info
            
            # Generate compliance report
            checker = ComplianceChecker(validation_result, server_info)
            report = checker.check_compliance()
            
            # Display only the summary since we already showed detailed results
            if verbose:
                # Show additional technical details
                console.print()
                console.print("[bold]Additional Technical Details:[/bold]")
                console.print()
                
                for test_result in validation_result.test_results:
                    # Only show tests with interesting technical details
                    if test_result.details and test_result.status != TestStatus.PASSED:
                        # Skip if no technical details beyond what was already shown
                        tech_keys = set(test_result.details.keys()) - {
                            "test_description", "requirement", "purpose", "fix", 
                            "expected_status", "status_code", "url_tested", "spec_reference",
                            "missing_params", "found_params", "spec_requirement", "example_header",
                            "diagnosis", "likely_cause", "note", "violation", "auth_status_code",
                            "www_authenticate", "protocol_version_sent", "header_name", "body"
                        }
                        
                        # Skip tests without additional technical details
                        if not tech_keys or all(k in {"error", "errors", "warnings"} for k in tech_keys):
                            continue
                            
                        console.print(f"[cyan]{test_result.test_case.name}:[/cyan]")
                        
                        # Show additional details based on test type
                        for key, value in test_result.details.items():
                            if key not in {"test_description", "requirement", "purpose", "fix", 
                                          "expected_status", "status_code", "url_tested", "spec_reference"}:
                                if isinstance(value, (dict, list)):
                                    console.print(f"  {key}: {json.dumps(value, indent=2)}")
                                else:
                                    console.print(f"  {key}: {value}")
                        console.print()
            
            # Show summary
            display_terminal_summary(report)
            
            return report
    
    validation_report = asyncio.run(run_validation_test())
    validation_passed = validation_report.validation_result.failed_tests == 0
    if not validation_passed:
        all_passed = False
    
    # OAuth server testing already done above, no need to repeat
    
    # Tools testing is already included in main validation, no need for separate section
    
    # Exit with error code if tests failed
    if not all_passed:
        sys.exit(1)


@cli.command()
@click.argument("mcp_server_url")
@click.option(
    "--test-destructive",
    is_flag=True,
    help="Also test destructive tools (use with caution)",
)
@click.option(
    "--tool-name",
    help="Test only a specific tool by name",
)
@click.option(
    "--list-only",
    is_flag=True,
    help="Only list available tools without testing",
)
def tools(
    mcp_server_url: str,
    test_destructive: bool,
    tool_name: Optional[str],
    list_only: bool,
):
    """Test MCP server tools.
    
    Discovers and tests all tools exposed by an MCP server.
    
    Example:
        mcp-validate tools https://mcp.example.com
        mcp-validate tools https://mcp.example.com --list-only
        mcp-validate tools https://mcp.example.com --tool-name "search"
    """
    async def run_tools_test():
        env_manager = EnvManager()
        
        async with MCPValidator(mcp_server_url) as validator:
            # Get access token if available
            validator.access_token = validator.env_manager.get_valid_access_token(mcp_server_url)
            
            if not validator.access_token:
                console.print("[yellow]No access token found. Some servers may require authentication.[/yellow]")
                console.print("Run 'mcp-validate flow' to authenticate if needed.")
                console.print()
            
            # Detect transport type first
            from mcp_http_validator.transport_detector import TransportDetector, TransportType
            from mcp_http_validator.sse_client import MCPSSEClient
            
            detector = TransportDetector(validator.client)
            headers = validator._get_headers({})
            
            try:
                caps = await detector.detect(mcp_server_url, headers)
                is_sse = caps.primary_transport == TransportType.HTTP_SSE
            except Exception:
                # If detection fails, try to determine from URL
                is_sse = mcp_server_url.endswith("/sse")
            
            if is_sse:
                # Handle SSE endpoints
                console.print("[bold]Connecting to SSE endpoint...[/bold]")
                sse_client = MCPSSEClient(mcp_server_url, validator.client, headers)
                
                connected = await sse_client.connect(timeout=10.0)
                if not connected:
                    console.print("[red]✗[/red] Failed to connect to SSE endpoint")
                    console.print("  The server should send an 'endpoint' event with the message URL")
                    return False
                
                console.print(f"[green]✓[/green] Connected to SSE endpoint")
                console.print(f"  Message endpoint: {sse_client.endpoint_url}")
                
                # Try to initialize (optional for some servers)
                initialized = await sse_client.test_initialize()
                if initialized:
                    console.print("[green]✓[/green] Session initialized")
                else:
                    console.print("[yellow]⚠[/yellow] Session initialization not required")
                
                # List tools via SSE
                console.print()
                console.print("[bold]Discovering tools...[/bold]")
                tools = await sse_client.list_tools()
                
                if tools is None:
                    console.print("[red]✗[/red] Failed to list tools via SSE")
                    console.print("  Authentication may be required")
                    return False
                
                success = True
                error = None
            else:
                # Handle regular HTTP endpoints
                console.print("[bold]Initializing MCP session...[/bold]")
                success, error, init_details = await validator.initialize_mcp_session()
                
                if success:
                    console.print("[green]✓[/green] Session initialized")
                    server_info = init_details.get("server_info", {})
                    if server_info:
                        console.print(f"  Server: {server_info.get('name', 'Unknown')}")
                        console.print(f"  Version: {server_info.get('version', 'Unknown')}")
                else:
                    # Check if this is a protocol version spec violation
                    if isinstance(init_details, dict) and init_details.get("spec_violation"):
                        console.print(f"[yellow]⚠[/yellow] Session initialization failed: Server spec violation")
                        err_msg = init_details.get('error', {}).get('message', '') if isinstance(init_details.get('error'), dict) else ''
                        if err_msg:
                            console.print(f"  Server error: {err_msg}")
                        console.print(f"  [dim]Issue: {init_details.get('spec_violation')}[/dim]")
                        console.print("  Continuing anyway - some servers may not require initialization")
                    else:
                        # Show shortened error for readability
                        error_msg = str(error)
                        if len(error_msg) > 200:
                            error_msg = error_msg[:197] + "..."
                        console.print(f"[yellow]⚠[/yellow] Session initialization failed: {error_msg}")
                        console.print("  Continuing anyway - some servers may not require initialization")
                
                # List tools
                console.print()
                console.print("[bold]Discovering tools...[/bold]")
                success, error, tools = await validator.list_mcp_tools()
            
            if not success:
                console.print(f"[red]✗[/red] Failed to list tools: {error}")
                return False  # Return failure status
            
            if not tools:
                console.print("[yellow]No tools found on this server[/yellow]")
                return True  # Not an error, just no tools
            
            console.print(f"[green]✓[/green] Found {len(tools)} tool(s)")
            
            # Create tools table
            tools_table = Table(title="Available Tools")
            tools_table.add_column("Name", style="cyan")
            tools_table.add_column("Description")
            tools_table.add_column("Type", style="yellow")
            
            for tool in tools:
                tool_type = []
                if tool.get("annotations", {}).get("destructiveHint"):
                    tool_type.append("destructive")
                if tool.get("annotations", {}).get("readOnlyHint"):
                    tool_type.append("read-only")
                
                tools_table.add_row(
                    tool.get("name", "unknown"),
                    tool.get("description", ""),
                    ", ".join(tool_type) if tool_type else "standard"
                )
            
            console.print()
            console.print(tools_table)
            
            if list_only:
                return
            
            # Filter tools if specific tool requested (note: tool_name is a parameter of the function)
            if tool_name:
                tools = [t for t in tools if t.get("name") == tool_name]
                if not tools:
                    console.print(f"[red]Tool '{tool_name}' not found[/red]")
                    return False  # Tool not found is a failure
            
            # Test tools
            console.print()
            console.print("[bold]Testing tools...[/bold]")
            
            passed = 0
            failed = 0
            skipped = 0
            
            for tool in tools:
                # Show message for destructive tools
                if test_destructive and tool.get("annotations", {}).get("destructiveHint"):
                    console.print(f"\n[yellow]Testing destructive tool: {tool['name']}[/yellow]")
                
                # Use appropriate method for testing based on transport
                if is_sse:
                    # Test via SSE - inline implementation
                    current_tool_name = tool.get("name", "unknown")
                    result = {"tool_name": current_tool_name}
                    
                    # Skip destructive tools unless explicitly requested
                    is_destructive = tool.get("annotations", {}).get("destructiveHint", False)
                    if is_destructive and not test_destructive:
                        result["status"] = "skipped"
                        result["reason"] = "Destructive tool - use --test-destructive to test"
                    else:
                        try:
                            # Build minimal test arguments
                            test_args = {}
                            schema = tool.get("inputSchema", {})
                            required = schema.get("required", [])
                            
                            # Only provide required arguments with minimal values
                            for req in required:
                                prop_def = schema.get("properties", {}).get(req, {})
                                if prop_def.get("type") == "string":
                                    test_args[req] = "test"
                                elif prop_def.get("type") == "integer":
                                    test_args[req] = 0
                                elif prop_def.get("type") == "number":
                                    test_args[req] = 0.0
                                elif prop_def.get("type") == "boolean":
                                    test_args[req] = False
                                elif prop_def.get("type") == "array":
                                    test_args[req] = []
                                elif prop_def.get("type") == "object":
                                    test_args[req] = {}
                            
                            # Call the tool via SSE
                            response = await sse_client.call_tool(current_tool_name, test_args)
                            
                            if "result" in response:
                                result["status"] = "success"
                                result["test_params"] = test_args
                            elif "error" in response:
                                result["status"] = "error"
                                result["error"] = response["error"].get("message", "Unknown error")
                                result["test_params"] = test_args
                            else:
                                result["status"] = "error"
                                result["error"] = "Invalid response format"
                                
                        except Exception as e:
                            result["status"] = "exception"
                            result["error"] = str(e)
                else:
                    # Test via JSON-RPC
                    result = await validator.test_mcp_tool(tool, test_destructive=test_destructive)
                
                status_icons = {
                    "success": "[green]✓[/green]",
                    "failed": "[red]✗[/red]",
                    "error": "[red]✗[/red]",
                    "tool_error": "[yellow]⚠[/yellow]",
                    "skipped": "[yellow]⊘[/yellow]",
                    "exception": "[red]⚠[/red]",
                    "invalid": "[red]✗[/red]"
                }
                
                icon = status_icons.get(result["status"], "?")
                console.print(f"\n{icon} {result['tool_name']}")
                
                if result.get("error"):
                    console.print(f"  Error: {result['error']}")
                
                if result["status"] == "success":
                    passed += 1
                    console.print("  Response received successfully")
                elif result["status"] == "skipped":
                    skipped += 1
                else:
                    failed += 1
                
                # Show test parameters used
                if result.get("test_params") and result["status"] != "skipped":
                    console.print(f"  Test params: {json.dumps(result['test_params'])}")
            
            # Summary
            console.print()
            console.print("[bold]Summary:[/bold]")
            console.print(f"  Total: {len(tools)}")
            console.print(f"  Passed: [green]{passed}[/green]")
            console.print(f"  Failed: [red]{failed}[/red]")
            console.print(f"  Skipped: [yellow]{skipped}[/yellow]")
            
            # Return success only if we had no failures (or only skipped tests)
            return failed == 0
    
    try:
        success = asyncio.run(run_tools_test())
        if success is False:  # Explicit False check (None means list_only)
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()