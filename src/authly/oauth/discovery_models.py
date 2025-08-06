"""OAuth 2.1 Authorization Server Discovery Models.

Based on RFC 8414: OAuth 2.0 Authorization Server Metadata
and OAuth 2.1 specifications.
"""

from pydantic import BaseModel, Field


class OAuthServerMetadata(BaseModel):
    """OAuth 2.1 Authorization Server Metadata Response.

    This model represents the standard metadata returned by the
    /.well-known/oauth-authorization-server discovery endpoint.

    Based on RFC 8414 with OAuth 2.1 specific requirements.
    """

    # Required metadata
    issuer: str = Field(..., description="URL using the https scheme that identifies the authorization server")
    authorization_endpoint: str = Field(..., description="URL of the authorization server's authorization endpoint")
    token_endpoint: str = Field(..., description="URL of the authorization server's token endpoint")

    # OAuth 2.1 specific requirements
    response_types_supported: list[str] = Field(
        default=["code"], description="List of OAuth 2.0 response types that this server supports"
    )
    grant_types_supported: list[str] = Field(
        default=["authorization_code", "refresh_token"],
        description="List of OAuth 2.0 grant types that this server supports",
    )

    # PKCE requirements (mandatory in OAuth 2.1)
    code_challenge_methods_supported: list[str] = Field(
        default=["S256"], description="List of PKCE code challenge methods supported"
    )

    # Token endpoint authentication
    token_endpoint_auth_methods_supported: list[str] = Field(
        default=["client_secret_basic", "client_secret_post", "none"],
        description="List of client authentication methods supported at the token endpoint",
    )

    # Scopes
    scopes_supported: list[str] | None = Field(default=None, description="List of OAuth 2.0 scope values supported")

    # Optional but recommended metadata
    revocation_endpoint: str | None = Field(
        default=None, description="URL of the authorization server's token revocation endpoint"
    )

    # Additional security features
    require_pkce: bool = Field(default=True, description="Whether PKCE is required for all authorization code flows")

    # Server capabilities
    response_modes_supported: list[str] = Field(
        default=["query"], description="List of OAuth 2.0 response modes supported"
    )

    # Service documentation
    service_documentation: str | None = Field(default=None, description="URL of service documentation for developers")

    # UI locales
    ui_locales_supported: list[str] | None = Field(
        default=["en"], description="Languages and scripts supported for the user interface"
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/api/v1/oauth/authorize",
                "token_endpoint": "https://auth.example.com/api/v1/oauth/token",
                "revocation_endpoint": "https://auth.example.com/api/v1/oauth/revoke",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
                "require_pkce": True,
                "response_modes_supported": ["query"],
                "scopes_supported": ["read", "write", "admin"],
                "ui_locales_supported": ["en"],
            }
        }
