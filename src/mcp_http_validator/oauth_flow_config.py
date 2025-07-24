"""Configuration for generic OAuth flow handling."""

import os
from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse


class RedirectStrategy(str, Enum):
    """OAuth redirect URI strategies."""
    AUTO = "auto"  # Automatically detect best option
    PUBLIC_IP = "public_ip"  # Use detected public IP
    PUBLIC_HOSTNAME = "public_hostname"  # Use public hostname (from env/config)
    LOCALHOST = "localhost"  # Use localhost (dev environment)
    DOCKER_HOST = "docker_host"  # Use host.docker.internal
    CUSTOM = "custom"  # User-provided URI
    OOB = "oob"  # Out-of-band (last resort)
    DEVICE = "device"  # Device flow (no redirect)
    ENV = "env"  # From environment variable


class GrantPreference(str, Enum):
    """Grant type preferences for different scenarios."""
    INTERACTIVE = "interactive"  # User can interact (browser available)
    AUTOMATED = "automated"  # No user interaction (CI/CD, cron)
    CLI = "cli"  # CLI with potential user (may or may not have browser)
    SERVICE = "service"  # Service-to-service only


@dataclass
class OAuthFlowConfig:
    """Configuration for OAuth flow behavior."""
    
    # Redirect URI configuration
    redirect_strategy: RedirectStrategy = RedirectStrategy.AUTO
    custom_redirect_uri: Optional[str] = None
    redirect_port_range: tuple[int, int] = (8080, 8180)  # Port range to try
    public_hostname: Optional[str] = None  # Override detected hostname
    
    # Grant type preferences
    grant_preference: GrantPreference = GrantPreference.CLI
    allowed_grants: List[str] = field(default_factory=lambda: [
        "client_credentials",
        "device_code", 
        "authorization_code",
        "refresh_token"
    ])
    force_grant_type: Optional[str] = None  # Force specific grant
    
    # Network configuration
    bind_address: str = "0.0.0.0"  # Address to bind callback server
    prefer_ipv4: bool = True  # Prefer IPv4 over IPv6
    behind_proxy: bool = False  # Running behind proxy/LB
    proxy_public_url: Optional[str] = None  # Public URL if behind proxy
    
    # Behavior configuration
    auto_open_browser: bool = True  # Open browser automatically
    browser_command: Optional[str] = None  # Custom browser command
    callback_timeout: int = 300  # Seconds to wait for callback
    suppress_console: bool = False  # Suppress console output
    
    # Environment detection
    detect_docker: bool = True  # Auto-detect Docker environment
    detect_kubernetes: bool = True  # Auto-detect K8s environment
    detect_cloud: bool = True  # Auto-detect cloud environments
    
    @classmethod
    def from_environment(cls) -> "OAuthFlowConfig":
        """Create config from environment variables."""
        config = cls()
        
        # Redirect strategy
        if strategy := os.getenv("OAUTH_REDIRECT_STRATEGY"):
            config.redirect_strategy = RedirectStrategy(strategy.lower())
        
        if uri := os.getenv("OAUTH_REDIRECT_URI"):
            config.custom_redirect_uri = uri
            if config.redirect_strategy == RedirectStrategy.AUTO:
                config.redirect_strategy = RedirectStrategy.CUSTOM
        
        if hostname := os.getenv("OAUTH_PUBLIC_HOSTNAME"):
            config.public_hostname = hostname
        
        # Grant preferences
        if pref := os.getenv("OAUTH_GRANT_PREFERENCE"):
            config.grant_preference = GrantPreference(pref.lower())
        
        if grants := os.getenv("OAUTH_ALLOWED_GRANTS"):
            config.allowed_grants = [g.strip() for g in grants.split(",")]
        
        if force := os.getenv("OAUTH_FORCE_GRANT"):
            config.force_grant_type = force
        
        # Network
        if bind := os.getenv("OAUTH_BIND_ADDRESS"):
            config.bind_address = bind
        
        config.prefer_ipv4 = os.getenv("OAUTH_PREFER_IPV4", "true").lower() == "true"
        config.behind_proxy = os.getenv("OAUTH_BEHIND_PROXY", "false").lower() == "true"
        
        if proxy_url := os.getenv("OAUTH_PROXY_PUBLIC_URL"):
            config.proxy_public_url = proxy_url
        
        # Auto-detection overrides
        config.detect_docker = os.getenv("OAUTH_DETECT_DOCKER", "true").lower() == "true"
        config.detect_kubernetes = os.getenv("OAUTH_DETECT_K8S", "true").lower() == "true"
        config.detect_cloud = os.getenv("OAUTH_DETECT_CLOUD", "true").lower() == "true"
        
        # Behavior
        config.auto_open_browser = os.getenv("OAUTH_AUTO_BROWSER", "true").lower() == "true"
        config.browser_command = os.getenv("BROWSER")
        
        if timeout := os.getenv("OAUTH_CALLBACK_TIMEOUT"):
            config.callback_timeout = int(timeout)
        
        return config
    
    def get_grant_order(self) -> List[str]:
        """Get grant types in order of preference based on scenario."""
        if self.force_grant_type:
            return [self.force_grant_type]
        
        # Define preferences for each scenario
        preferences = {
            GrantPreference.SERVICE: [
                "client_credentials",
                "refresh_token"
            ],
            GrantPreference.AUTOMATED: [
                "client_credentials",
                "refresh_token"
            ],
            GrantPreference.CLI: [
                "client_credentials",  # Best if available
                "device_code",  # Good for CLI without browser
                "authorization_code",  # Needs browser/callback
                "refresh_token"
            ],
            GrantPreference.INTERACTIVE: [
                "authorization_code",  # Best for interactive
                "device_code",  # Alternative
                "client_credentials",
                "refresh_token"
            ]
        }
        
        preferred_order = preferences.get(self.grant_preference, self.allowed_grants)
        
        # Filter to only allowed grants
        return [g for g in preferred_order if g in self.allowed_grants]
    
    def is_interactive_allowed(self) -> bool:
        """Check if interactive flows are allowed."""
        return self.grant_preference in [GrantPreference.CLI, GrantPreference.INTERACTIVE]
    
    def should_use_callback_server(self) -> bool:
        """Determine if callback server should be used."""
        if self.redirect_strategy == RedirectStrategy.DEVICE:
            return False
        if self.redirect_strategy == RedirectStrategy.OOB:
            return False
        if self.force_grant_type == "device_code":
            return False
        return True


class EnvironmentDetector:
    """Detect runtime environment for OAuth configuration."""
    
    @staticmethod
    def is_docker() -> bool:
        """Check if running in Docker container."""
        return (
            os.path.exists("/.dockerenv") or
            os.getenv("DOCKER_CONTAINER") == "true" or
            os.path.exists("/proc/1/cgroup") and "docker" in open("/proc/1/cgroup").read()
        )
    
    @staticmethod
    def is_kubernetes() -> bool:
        """Check if running in Kubernetes pod."""
        return (
            os.getenv("KUBERNETES_SERVICE_HOST") is not None or
            os.path.exists("/var/run/secrets/kubernetes.io")
        )
    
    @staticmethod
    def is_github_actions() -> bool:
        """Check if running in GitHub Actions."""
        return os.getenv("GITHUB_ACTIONS") == "true"
    
    @staticmethod
    def is_gitlab_ci() -> bool:
        """Check if running in GitLab CI."""
        return os.getenv("GITLAB_CI") == "true"
    
    @staticmethod
    def is_ci() -> bool:
        """Check if running in any CI environment."""
        return (
            os.getenv("CI") == "true" or
            os.getenv("CONTINUOUS_INTEGRATION") == "true" or
            EnvironmentDetector.is_github_actions() or
            EnvironmentDetector.is_gitlab_ci() or
            os.getenv("JENKINS_URL") is not None or
            os.getenv("TRAVIS") == "true" or
            os.getenv("CIRCLECI") == "true"
        )
    
    @staticmethod
    def detect_cloud_provider() -> Optional[str]:
        """Detect cloud provider."""
        # AWS
        if os.getenv("AWS_EXECUTION_ENV") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
            return "aws"
        # Google Cloud
        if os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT"):
            return "gcp"
        # Azure
        if os.getenv("WEBSITE_INSTANCE_ID") or os.getenv("AZURE_FUNCTIONS_ENVIRONMENT"):
            return "azure"
        # DigitalOcean
        if os.getenv("DO_TOKEN"):
            return "digitalocean"
        
        # Check metadata endpoints
        import socket
        try:
            # AWS metadata
            socket.create_connection(("169.254.169.254", 80), timeout=1).close()
            return "aws"
        except:
            pass
        
        return None
    
    @staticmethod
    def get_environment_context() -> Dict[str, Any]:
        """Get complete environment context."""
        return {
            "is_docker": EnvironmentDetector.is_docker(),
            "is_kubernetes": EnvironmentDetector.is_kubernetes(),
            "is_ci": EnvironmentDetector.is_ci(),
            "cloud_provider": EnvironmentDetector.detect_cloud_provider(),
            "has_display": os.getenv("DISPLAY") is not None,
            "ssh_connection": os.getenv("SSH_CONNECTION") is not None,
            "term_program": os.getenv("TERM_PROGRAM"),
        }


def determine_redirect_strategy(config: OAuthFlowConfig) -> RedirectStrategy:
    """Determine the best redirect strategy based on environment."""
    if config.redirect_strategy != RedirectStrategy.AUTO:
        return config.redirect_strategy
    
    context = EnvironmentDetector.get_environment_context()
    
    # In CI/CD, use OOB or device flow
    if context["is_ci"]:
        return RedirectStrategy.OOB
    
    # In Docker, check if we can use host networking
    if context["is_docker"] and config.detect_docker:
        # Check if running with host network
        try:
            import socket
            # If we can bind to host IPs, we might have host networking
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.bind(("0.0.0.0", 0))
            test_sock.close()
            return RedirectStrategy.PUBLIC_IP
        except:
            return RedirectStrategy.DOCKER_HOST
    
    # In Kubernetes, use service URL if available
    if context["is_kubernetes"] and config.detect_kubernetes:
        if config.proxy_public_url:
            return RedirectStrategy.CUSTOM
        return RedirectStrategy.OOB
    
    # SSH session without display - no browser
    if context["ssh_connection"] and not context["has_display"]:
        return RedirectStrategy.OOB
    
    # Default: try public IP, fall back to localhost
    return RedirectStrategy.PUBLIC_IP