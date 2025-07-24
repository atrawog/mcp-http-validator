"""CLI command for OAuth grant types validation."""

import asyncio
import click
from rich.console import Console
from rich.table import Table

from .oauth import OAuthTestClient
from .grant_validator import OAuthGrantValidator, GrantType
from .validator import MCPValidator

console = Console()


@click.command(name="oauth-grants")
@click.argument("mcp_server_url", required=True)
@click.option(
    "--test-grants/--no-test-grants",
    default=True,
    help="Actually test the grant types (vs just check metadata)",
)
@click.option(
    "--no-ssl-verify",
    is_flag=True,
    help="Disable SSL certificate verification",
)
def validate_oauth_grants(
    mcp_server_url: str,
    test_grants: bool,
    no_ssl_verify: bool,
):
    """Validate OAuth grant types supported by an MCP server.
    
    Discovers the OAuth server, checks supported grant types,
    and optionally tests them for functionality.
    
    Example:
        mcp-validate oauth-grants https://mcp.example.com
    """
    async def run_validation():
        # Discover OAuth server
        async with MCPValidator(mcp_server_url, verify_ssl=not no_ssl_verify) as validator:
            console.print("[bold]Discovering OAuth server...[/bold]")
            auth_server_url = await validator.discover_oauth_server()
            
            if not auth_server_url:
                console.print("[red]✗[/red] No OAuth server discovered")
                return False
                
            console.print(f"[green]✓[/green] OAuth server: {auth_server_url}")
            
            # Get credentials
            credentials = validator.env_manager.get_oauth_credentials(mcp_server_url)
            if not credentials["client_id"] and test_grants:
                console.print("[yellow]No OAuth client registered. Some tests will be skipped.[/yellow]")
        
        # Create OAuth client
        async with OAuthTestClient(
            auth_server_url,
            client_id=credentials.get("client_id"),
            client_secret=credentials.get("client_secret"),
            verify_ssl=not no_ssl_verify,
        ) as client:
            # Discover metadata
            console.print("\n[bold]Fetching OAuth server metadata...[/bold]")
            try:
                metadata = await client.discover_metadata()
                console.print("[green]✓[/green] Metadata retrieved")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to fetch metadata: {e}")
                return False
            
            # Validate grant types
            console.print("\n[bold]Validating Grant Types...[/bold]")
            validator = OAuthGrantValidator(client.client)
            
            results = await validator.validate_all_grants(
                metadata.model_dump(),
                client.client_id,
                client.client_secret,
                test_grants=test_grants and bool(client.client_id)
            )
            
            # Display results
            table = Table(title="OAuth Grant Types")
            table.add_column("Grant Type", style="cyan")
            table.add_column("Supported", style="white")
            table.add_column("Tested", style="white") 
            table.add_column("Result", style="white")
            table.add_column("Notes", style="dim")
            
            has_failures = False
            for grant_type, result in results.items():
                if not result.supported:
                    continue
                    
                supported = "✓" if result.supported else "✗"
                tested = "✓" if result.tested else "-"
                
                if result.tested:
                    if result.success:
                        status = "[green]PASS[/green]"
                    else:
                        status = "[red]FAIL[/red]"
                        has_failures = True
                else:
                    status = "[dim]N/A[/dim]"
                
                notes = result.recommendation or ""
                if result.error:
                    notes = f"[red]{result.error}[/red]"
                
                table.add_row(
                    grant_type,
                    supported,
                    tested,
                    status,
                    notes
                )
            
            console.print(table)
            
            # Show best grant recommendation
            console.print("\n[bold]Recommendation:[/bold]")
            best_grant = OAuthGrantValidator.recommend_best_grant(
                results,
                is_cli=True,
                has_browser=False,
                is_automated=test_grants
            )
            
            if best_grant:
                console.print(f"Best grant type for CLI use: [green]{best_grant}[/green]")
                if best_grant == GrantType.CLIENT_CREDENTIALS:
                    console.print("[dim]No user interaction required - ideal for automation[/dim]")
                elif best_grant == GrantType.DEVICE_CODE:
                    console.print("[dim]User-friendly for CLI tools without browser access[/dim]")
                elif best_grant == GrantType.AUTHORIZATION_CODE:
                    console.print("[dim]Standard flow - requires browser for authorization[/dim]")
            else:
                console.print("[yellow]No suitable grant type found for CLI use[/yellow]")
            
            return not has_failures
    
    try:
        success = asyncio.run(run_validation())
        if not success:
            exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Validation cancelled[/yellow]")
        exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        exit(1)