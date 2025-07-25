#!/usr/bin/env python3
"""Test the new resource-token consistency validation."""

import asyncio
from mcp_http_validator import MCPValidator, ComplianceChecker

async def test_resource_token_consistency():
    """Demonstrate the resource-token consistency test."""
    
    # Example MCP server URL
    server_url = "https://mcp.example.com"
    
    print(f"Testing resource-token consistency for: {server_url}")
    print("-" * 60)
    
    async with MCPValidator(server_url) as validator:
        # Run validation
        result = await validator.validate()
        
        # Find the resource-token consistency test result
        consistency_test = None
        for test_result in result.test_results:
            if test_result.test_case.id == "resource-token-consistency":
                consistency_test = test_result
                break
        
        if consistency_test:
            print(f"\nTest: {consistency_test.test_case.name}")
            print(f"Status: {consistency_test.status.value.upper()}")
            print(f"Message: {consistency_test.message}")
            
            if consistency_test.details:
                print("\nDetails:")
                if "declared_resource" in consistency_test.details:
                    print(f"  Declared Resource: {consistency_test.details['declared_resource']}")
                if "token_audience" in consistency_test.details:
                    print(f"  Token Audience: {consistency_test.details['token_audience']}")
                if "mismatch_type" in consistency_test.details:
                    print(f"  Mismatch Type: {consistency_test.details['mismatch_type']}")
        else:
            print("Resource-token consistency test not found in results")
        
        # Show overall compliance
        checker = ComplianceChecker(result, validator.server_info)
        report = checker.check_compliance()
        print(f"\nOverall Compliance: {report.compliance_level}")

async def demonstrate_test_scenarios():
    """Show different test scenarios and expected outcomes."""
    
    print("\n" + "="*80)
    print("RESOURCE-TOKEN CONSISTENCY TEST SCENARIOS")
    print("="*80)
    
    print("\n1. PASSING SCENARIO:")
    print("   - Protected resource metadata declares: 'https://mcp.example.com'")
    print("   - Token audience contains: ['https://mcp.example.com']")
    print("   - Result: ✅ PASS - Resource and token are consistent")
    
    print("\n2. FAILING SCENARIO - Resource Mismatch:")
    print("   - Protected resource metadata declares: 'https://api.example.com/mcp'")
    print("   - Token audience contains: ['https://mcp.example.com']")
    print("   - Result: ❌ FAIL - Token doesn't match declared resource")
    
    print("\n3. SKIPPED SCENARIO - No Token:")
    print("   - Protected resource metadata exists")
    print("   - No access token available")
    print("   - Result: ⏭️ SKIP - Test requires a valid token")
    
    print("\n4. SKIPPED SCENARIO - Opaque Token:")
    print("   - Protected resource metadata exists")
    print("   - Token is opaque (not JWT)")
    print("   - Result: ⏭️ SKIP - Can't inspect opaque token audience")
    
    print("\n" + "="*80)
    print("KEY BENEFITS OF THIS TEST:")
    print("="*80)
    print("1. Ensures OAuth configuration consistency")
    print("2. Detects mismatched resource identifiers early")
    print("3. Prevents authorization failures due to audience mismatch")
    print("4. Validates proper RFC 8707 resource indicator implementation")
    print("5. Helps debug OAuth integration issues")

if __name__ == "__main__":
    # Run the test
    # asyncio.run(test_resource_token_consistency())
    
    # Just show the scenarios since we don't have a real server
    asyncio.run(demonstrate_test_scenarios())