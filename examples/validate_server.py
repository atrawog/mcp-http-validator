"""Example: Validate an MCP server for specification compliance."""

import asyncio
import os
from pathlib import Path

from mcp_http_validator import MCPValidator, ComplianceChecker


async def validate_mcp_server():
    """Example of validating an MCP server with automatic OAuth discovery."""
    # Configuration - typically from environment variables or command line
    server_url = os.getenv("MCP_SERVER_URL", "https://mcp.example.com")
    access_token = os.getenv("MCP_ACCESS_TOKEN")
    
    print(f"Validating MCP server: {server_url}")
    print("-" * 50)
    
    # Create validator with automatic OAuth client registration
    async with MCPValidator(
        server_url=server_url,
        access_token=access_token,
        timeout=30.0,
        verify_ssl=True,
        auto_register=True,  # Automatically register OAuth client if needed
    ) as validator:
        # Setup OAuth client if no token provided
        if not access_token:
            print("\nSetting up OAuth client...")
            oauth_client = await validator.setup_oauth_client()
            if oauth_client:
                print(f"✓ OAuth client configured: {oauth_client.client_id}")
                print("  Credentials saved to .env file")
            else:
                print("⚠ No OAuth client available, some tests may be skipped")
        
        # Run validation tests
        validation_result = await validator.validate()
        server_info = validator.server_info
    
    # Generate compliance report
    checker = ComplianceChecker(validation_result, server_info)
    report = checker.check_compliance()
    
    # Display results
    print(f"\nCompliance Level: {report.compliance_level}")
    print(f"Success Rate: {validation_result.success_rate:.1f}%")
    print(f"Tests: {validation_result.passed_tests}/{validation_result.total_tests} passed")
    
    # Show test results
    print("\nTest Results:")
    for result in validation_result.test_results:
        status = "✓" if result.status == "passed" else "✗"
        print(f"  {status} {result.test_case.name}")
        if result.error_message:
            print(f"    → {result.error_message}")
    
    # Show critical failures
    if report.critical_failures:
        print("\nCritical Failures:")
        for failure in report.critical_failures:
            print(f"  - {failure.test_case.name}: {failure.error_message}")
    
    # Show recommendations
    if report.recommendations:
        print("\nRecommendations:")
        for rec in report.recommendations:
            print(f"  - {rec}")
    
    # Save report
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)
    
    # Save as JSON
    json_file = output_dir / "mcp_compliance_report.json"
    with open(json_file, "w") as f:
        import json
        json.dump(report.model_dump(), f, indent=2, default=str)
    print(f"\nReport saved to: {json_file}")
    
    # Save as Markdown
    md_file = output_dir / "mcp_compliance_report.md"
    with open(md_file, "w") as f:
        f.write(report.to_markdown())
    print(f"Markdown report saved to: {md_file}")


if __name__ == "__main__":
    asyncio.run(validate_mcp_server())