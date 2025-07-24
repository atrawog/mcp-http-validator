"""MCP HTTP Validator - HTTP-based validator for Model Context Protocol servers.

This package provides tools for validating MCP server implementations against
the MCP specification, with a focus on OAuth 2.0 authorization compliance.
"""

from .validator import MCPValidator
from .oauth import OAuthTestClient
from .oauth_tests import OAuthTestValidator, BaseMCPValidator
from .compliance import ComplianceChecker
from .models import ValidationResult, TestCase, ComplianceReport
from .env_manager import EnvManager
from .rfc7591 import RFC7591Validator, RFC7592Validator

__version__ = "0.1.0"
__all__ = [
    "MCPValidator",
    "OAuthTestClient",
    "OAuthTestValidator",
    "BaseMCPValidator",
    "ComplianceChecker",
    "ValidationResult",
    "TestCase",
    "ComplianceReport",
    "EnvManager",
    "RFC7591Validator",
    "RFC7592Validator",
]